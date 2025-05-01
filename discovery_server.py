#!/usr/bin/env python3

import hashlib
import socket
import threading
import time
import uuid

from tinydb import Query, TinyDB

from constants import *

sessions = {}

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
    for entry in registry_interface('read'):
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
                    print(f"[INFO] User {username} logged in from {addr}")
                    notify_peers(username, peer['ip'], peer['port'], token)
                    files_str = ','.join(peer.get('files', []))
                    response = f'LOGGED_IN {token} {peer["ip"]}:{peer["port"]} {files_str}'
                else:
                    response = 'INVALID_CREDENTIALS'

        elif cmd == 'LIST':
            if len(tokens) != 2:
                response = 'ERROR: LIST command format: LIST <session_id>'
            else:
                session = sessions.get(tokens[1])
                if not session:
                    response = 'ERROR: Invalid session ID. Please login first.'
                else:
                    entries = []
                    for s in sessions.values():
                        ip, port = s['ip'], s['port']
                        info = peer_registry_data.get((ip, port))
                        if info:
                            files_str = ','.join(info.get('files', []))
                            entries.append(f"{info['username']}@{ip}:{port}|{files_str}")
                    response = ';'.join(entries) if entries else 'NO_PEERS_FOUND'

        elif cmd == 'SEARCH':
            if len(tokens) != 3:
                response = 'ERROR: SEARCH command format: SEARCH <session_id> <filename>'
            else:
                session_id, filename = tokens[1], tokens[2]
                if session_id not in sessions:
                    response = 'ERROR: Invalid session ID. Please login first.'
                else:
                    matching = []
                    for entry in registry_interface('read'):
                        if filename in entry.get('files', []):
                            matching.append(f"{entry['ip']}:{entry['port']}")
                    response = ','.join(matching) if matching else 'NOT_FOUND'

        else:
            response = 'ERROR: Unknown command'

        conn.send(response.encode('utf-8'))

    except Exception as e:
        print(f"[ERROR] Client {addr} -> {e}")
    finally:
        conn.close()


def registry_cleanup():
    """
    Periodically remove peers that haven't sent a heartbeat in the last 90 seconds.
    """
    while True:
        time.sleep(30)
        now = time.time()
        for entry in registry_interface('read'):
            if now - entry['last_seen'] > 90:
                registry_interface('delete', filters={'ip': entry['ip'], 'port': entry['port']})
                print(f"[INFO] Removed inactive peer: {(entry['ip'], entry['port'])}")


def start_discovery_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"[INFO] Discovery server listening on {SERVER_HOST}:{SERVER_PORT}")

    # Launch cleanup thread
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
