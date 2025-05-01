#!/usr/bin/env python3

import hashlib
import socket
import threading
import time
import uuid

from tinydb import Query, TinyDB

from constants import *

# Sessions map: token -> user info
sessions = {}

# Active peers map: (ip, port) -> { last_heartbeat, username, files, etc. }
active_peers = {}

# Lock for synchronizing active peers operations
active_peers_lock = threading.Lock()

# Underlying TinyDB store (file on disk)
peer_registry_store = TinyDB('peer_registry.json')

# In-memory cache: mapping (ip, port) -> peer info dict
peer_registry_data = {}

# Lock for synchronizing DB and cache operations
registry_lock = threading.Lock()


def registry_interface(operation, filters=None, data=None):
    """
    Shared interface to database and in-memory cache.

    operation: 'load', 'read', 'insert', 'update', 'delete'
    filters: dict of field->value to filter entries for read/update/delete
    data: dict of data for insert or update
    """
    filters = filters or {}
    with registry_lock:
        if operation == 'load':
            entries = peer_registry_store.all()
            peer_registry_data.clear()
            for e in entries:
                peer_registry_data[(e['ip'], e['port'])] = e
            return list(peer_registry_data.values())

        elif operation == 'read':
            results = []
            for entry in peer_registry_data.values():
                if all(entry.get(k) == v for k, v in filters.items()):
                    results.append(entry)
            return results

        elif operation == 'insert':
            # Insert into DB and cache
            peer_registry_store.insert(data)
            peer_registry_data[(data['ip'], data['port'])] = data
            return data

        elif operation == 'update':
            # Update DB
            q = Query()
            query_expr = None
            for k, v in filters.items():
                cond = (q[k] == v)
                query_expr = cond if query_expr is None else query_expr & cond
            peer_registry_store.update(data, query_expr)

            # Update cache
            for entry in peer_registry_data.values():
                if all(entry.get(k) == v for k, v in filters.items()):
                    entry.update(data)
                    peer_registry_data[(entry['ip'], entry['port'])] = entry
            return None

        elif operation == 'delete':
            # Delete from DB and cache
            q = Query()
            query_expr = None
            for k, v in filters.items():
                cond = (q[k] == v)
                query_expr = cond if query_expr is None else query_expr & cond
            peer_registry_store.remove(query_expr)

            # Remove from cache
            for key, entry in list(peer_registry_data.items()):
                if all(entry.get(k) == v for k, v in filters.items()):
                    del peer_registry_data[key]
            return None

        else:
            raise ValueError(f"Unknown operation: {operation}")


# Active peers management functions
def update_active_peer(username, ip, port, files=None):
    """
    Update or add an active peer to the in-memory active peers list
    """
    key = (ip, port)
    with active_peers_lock:
        if key in active_peers:
            active_peers[key].update({
                'last_heartbeat': time.time(),
                'username': username
            })
            if files is not None:
                active_peers[key]['files'] = files
        else:
            active_peers[key] = {
                'username': username,
                'ip': ip,
                'port': port,
                'files': files or [],
                'last_heartbeat': time.time()
            }
    return active_peers[key]


def remove_active_peer(ip, port):
    """
    Remove a peer from the active peers list
    """
    key = (ip, port)
    with active_peers_lock:
        if key in active_peers:
            del active_peers[key]
            return True
    return False


def get_active_peers(filter_func=None):
    """
    Get a list of currently active peers, optionally filtered
    """
    with active_peers_lock:
        if filter_func:
            return [peer for peer in active_peers.values() if filter_func(peer)]
        return list(active_peers.values())


# Load DB into memory at startup
registry_interface('load')


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def notify_peers(username: str, ip: str, port: int, token: str):
    """
    Send a short notification to every other peer:
    e.g. "UPDATE alice 10.0.0.5 5500"
    """
    message = f"UPDATE {username} {ip} {port} {token}"
    # Use active peers instead of registry for notifications
    current_active_peers = get_active_peers()
    for entry in current_active_peers:
        target_ip = entry['ip']
        target_port = entry['port']
        other_username = entry['username']
        # skip notifying the peer who just registered/logged in
        if target_ip == ip and target_port == port:
            continue
        try:
            # Notify existing peer
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((target_ip, target_port))
                s.sendall(message.encode('utf-8'))
            # Notify back
            other_message = f"UPDATE {other_username} {target_ip} {target_port} {token}"
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                s2.settimeout(2)
                s2.connect((ip, port))
                s2.sendall(other_message.encode('utf-8'))
        except Exception as e:
            print(f"[WARN] Could not notify {target_ip}:{target_port} — {e}")
            # If we can't reach this peer, it might be offline - mark for cleanup
            # We don't remove immediately here to avoid modifying while iterating
            entry['unreachable'] = True

    # Clean up any peers marked as unreachable
    for entry in current_active_peers:
        if entry.get('unreachable'):
            remove_active_peer(entry['ip'], entry['port'])
            print(f"[INFO] Removed unreachable peer: {entry['username']} @ {entry['ip']}:{entry['port']}")


def handle_client(conn: socket.socket, addr):
    try:
        raw = conn.recv(BUFFER_SIZE).decode('utf-8').strip()
        if not raw:
            return
        tokens = raw.split()
        cmd = tokens[0].upper()

        if cmd == 'REGISTER':
            if len(tokens) < 5:
                response = 'ERROR: REGISTER format: REGISTER <username> <password> <ip> <port> [<files>]'
            else:
                username, raw_pw, peer_ip = tokens[1], tokens[2], tokens[3]
                try:
                    peer_port = int(tokens[4])
                except ValueError:
                    response = 'ERROR: Invalid port number.'
                else:
                    files = tokens[5].split(',') if len(tokens) >= 6 and tokens[5] else []
                    pwd_hash = hash_password(raw_pw)
                    new_entry = {
                        'username': username,
                        'password': pwd_hash,
                        'ip': peer_ip,
                        'port': peer_port,
                        'files': files,
                        'last_seen': time.time()
                    }
                    if registry_interface("read", filters={"username": username}):
                        response = "Error: Username Already Registered."
                    else:
                        registry_interface('insert', data=new_entry)
                        token = str(uuid.uuid4())
                        sessions[token] = new_entry
                        # Add to active peers
                        update_active_peer(username, peer_ip, peer_port, files)
                        print(f"[INFO] Registered {username} @ {peer_ip}:{peer_port}")
                        notify_peers(username, peer_ip, peer_port, token)
                        response = f'REGISTERED {token}'

        elif cmd == 'LOGIN':
            if len(tokens) != 3:
                response = 'ERROR: LOGIN command format: LOGIN <username> <password>'
            else:
                username, raw_pw = tokens[1], tokens[2]
                pwd_hash = hash_password(raw_pw)
                peers = registry_interface('read', filters={'username': username, 'password': pwd_hash})
                peer = peers[0] if peers else None
                if peer:
                    new_last = time.time()
                    registry_interface('update', filters={'username': username}, data={'last_seen': new_last})
                    token = str(uuid.uuid4())
                    sessions[token] = peer
                    # Add to active peers
                    update_active_peer(username, peer['ip'], peer['port'], peer.get('files', []))
                    print(f"[INFO] User {username} logged in from {addr}")
                    notify_peers(username, peer['ip'], peer['port'], token)
                    files_str = ','.join(peer.get('files', []))
                    response = f'LOGGED_IN {token} {peer["ip"]}:{peer["port"]} {files_str}'
                else:
                    response = 'INVALID_CREDENTIALS'

        elif cmd == 'HEARTBEAT':
            if len(tokens) != 2:
                response = 'ERROR: HEARTBEAT command format: HEARTBEAT <session_id>'
            else:
                session_id = tokens[1]
                session = sessions.get(session_id)
                if not session:
                    response = 'ERROR: Invalid session ID. Please login first.'
                else:
                    username = session['username']
                    ip = session['ip']
                    port = session['port']
                    # Update last heartbeat time
                    update_active_peer(username, ip, port)
                    response = 'HEARTBEAT_ACK'

        elif cmd == 'LIST':
            if len(tokens) != 2:
                response = 'ERROR: LIST command format: LIST <session_id>'
            else:
                session = sessions.get(tokens[1])
                if not session:
                    response = 'ERROR: Invalid session ID. Please login first.'
                else:
                    # Use active peers for listing
                    entries = []
                    for peer in get_active_peers():
                        files_str = ','.join(peer.get('files', []))
                        entries.append(f"{peer['username']}@{peer['ip']}:{peer['port']}|{files_str}")
                    response = ';'.join(entries) if entries else 'NO_PEERS_FOUND'

        elif cmd == 'SEARCH':
            if len(tokens) != 3:
                response = 'ERROR: SEARCH command format: SEARCH <session_id> <filename>'
            else:
                session_id, filename = tokens[1], tokens[2]
                if session_id not in sessions:
                    response = 'ERROR: Invalid session ID. Please login first.'
                else:
                    # Search in active peers
                    matching = []
                    for peer in get_active_peers():
                        if filename in peer.get('files', []):
                            matching.append(f"{peer['ip']}:{peer['port']}")
                    response = ','.join(matching) if matching else 'NOT_FOUND'

        elif cmd == 'LOGOUT':
            if len(tokens) != 2:
                response = 'ERROR: LOGOUT command format: LOGOUT <session_id>'
            else:
                session_id = tokens[1]
                session = sessions.get(session_id)
                if not session:
                    response = 'ERROR: Invalid session ID.'
                else:
                    # Remove from active peers
                    username = session['username']
                    ip = session['ip']
                    port = session['port']
                    remove_active_peer(ip, port)
                    # Remove session
                    del sessions[session_id]
                    print(f"[INFO] User {username} logged out")
                    response = 'LOGGED_OUT'

        else:
            response = 'ERROR: Unknown command'

        conn.send(response.encode('utf-8'))

    except Exception as e:
        print(f"[ERROR] Client {addr} -> {e}")
    finally:
        conn.close()


def active_peers_cleanup():
    """
    Periodically remove peers that haven't sent a heartbeat in the last 30 seconds.
    This is separate from the database cleanup as it only affects the in-memory active peers.
    """
    while True:
        time.sleep(HEARTBEAT_INTERVAL)  # Check every 10 seconds
        now = time.time()
        peers_to_remove = []

        with active_peers_lock:
            for key, peer in active_peers.items():
                if now - peer['last_heartbeat'] > 30:  # 30 seconds timeout
                    peers_to_remove.append(key)

        # Remove inactive peers outside the lock
        for key in peers_to_remove:
            ip, port = key
            remove_active_peer(ip, port)
            print(f"[INFO] Removed inactive peer from active list: {key}")


def registry_cleanup():
    """
    Periodically remove peers from the database that haven't sent a heartbeat in the last 90 seconds.
    This is separate from active peers cleanup as it affects the persistent database.
    """
    while True:
        time.sleep(30)
        now = time.time()
        for entry in registry_interface('read'):
            if now - entry['last_seen'] > 90:
                registry_interface('delete', filters={'ip': entry['ip'], 'port': entry['port']})
                print(f"[INFO] Removed inactive peer from database: {(entry['ip'], entry['port'])}")


def start_discovery_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"[INFO] Discovery server listening on {SERVER_HOST}:{SERVER_PORT}")

    # Launch cleanup threads
    threading.Thread(target=active_peers_cleanup, daemon=True).start()
    # threading.Thread(target=registry_cleanup, daemon=True).start()

    try:
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down discovery server.")
    finally:
        server_socket.close()


if __name__ == '__main__':
    threading.Thread(target=start_discovery_server, daemon=True).start()
    input()
