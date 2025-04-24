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

# Lock for synchronizing writes to both store and cache
registry_lock = threading.Lock()


# Load DB into memory at startup
def load_registry():
    global peer_registry_data
    with registry_lock:
        entries = peer_registry_store.all()
        peer_registry_data = {(e["ip"], e["port"]): e for e in entries}


load_registry()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def notify_peers(username: str, ip: str, port: int):
    """
    Send a short notification to every other peer:
    e.g. "UPDATE alice 10.0.0.5 5500"
    """
    message = f"UPDATE {username} {ip} {port}"
    print(peer_registry_data)
    # Iterate over in-memory registry data (thread-safe for reads)
    for entry in list(peer_registry_data.values()):
        print(entry)
        target_ip = entry["ip"]
        target_port = entry["port"]
        other_username = entry["username"]
        # skip notifying the peer who just registered/logged in
        print(f"Sending {message} to {target_ip} {target_port}")
        other_message = f"UPDATE {other_username} {target_ip} {target_port}"
        if target_ip == ip and target_port == port:
            continue
        try:
            print(f"Connecting to {target_ip}:{target_port}")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target_ip, target_port))
            s.sendall(message.encode('utf-8'))
            s.close()
            print(f"Connecting to {ip}:{port}")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))
            s.sendall(other_message.encode('utf-8'))
            s.close()
        except Exception as e:
            print(f"[WARN] Could not notify {target_ip}:{target_port} — {e}")


def handle_client(conn: socket.socket, addr):
    try:
        raw = conn.recv(BUFFER_SIZE).decode("utf-8").strip()
        if not raw:
            return
        tokens = raw.split()
        cmd = tokens[0].upper()

        if cmd == "REGISTER":
            if len(tokens) < 5:
                response = "ERROR: REGISTER format: REGISTER <username> <password> <ip> <port> [<files>]"
            else:
                username, raw_pw, peer_ip = tokens[1], tokens[2], tokens[3]
                try:
                    peer_port = int(tokens[4])
                except ValueError:
                    response = "ERROR: Invalid port number."
                else:
                    files = tokens[5].split(",") if len(tokens) >= 6 and tokens[5] else []
                    pwd_hash = hash_password(raw_pw)
                    # Write lock for updating store and cache
                    with registry_lock:
                        new_entry = {
                            "username": username,
                            "password": pwd_hash,
                            "ip": peer_ip,
                            "port": peer_port,
                            "files": files,
                            "last_seen": time.time()
                        }
                        peer_registry_store.insert(new_entry)
                        peer_registry_data[(peer_ip, peer_port)] = new_entry
                    token = str(uuid.uuid4())
                    sessions[token] = peer_registry_data[(peer_ip, peer_port)]

                    print(f"[INFO] Registered {username} @ {peer_ip}:{peer_port}")
                    # notify everyone else
                    notify_peers(username, peer_ip, peer_port)
                    response = f"REGISTERED {token}"

        elif cmd == "LOGIN":
            if len(tokens) != 3:
                response = "ERROR: LOGIN command format: LOGIN <username> <password>"
            else:
                username, raw_pw = tokens[1], tokens[2]
                pwd_hash = hash_password(raw_pw)
                # Read from in-memory cache
                with registry_lock:
                    peer = next(
                        (entry for entry in peer_registry_data.values()
                         if entry['username'] == username and entry['password'] == pwd_hash),
                        None
                    )
                    if peer:
                        peer['last_seen'] = time.time()
                        # Persist the last_seen update
                        peer_registry_store.update(
                            {'last_seen': peer['last_seen']},
                            (Query().username == username)
                        )

                if peer:
                    ip, port, files = peer['ip'], peer['port'], peer.get('files', [])
                    peer_registry_data[(ip, port)] = peer
                    token = str(uuid.uuid4())
                    sessions[token] = peer
                    print(f"[INFO] User {username} logged in from {addr}")
                    notify_peers(username, ip, port)
                    files_str = ",".join(files)
                    response = f"LOGGED_IN {token} {ip}:{port} {files_str}"
                else:
                    response = "INVALID_CREDENTIALS"

        elif cmd == "LIST":
            if len(tokens) != 2:
                response = "ERROR: LIST command format: LIST <session_id>"
            else:
                session = sessions.get(tokens[1])
                if not session:
                    response = "ERROR: Invalid session ID. Please login first."
                else:
                    entries = []
                    for s in sessions.values():
                        ip, port = s['ip'], s['port']
                        info = peer_registry_data.get((ip, port))
                        if info:
                            files_str = ",".join(info.get('files', []))
                            entries.append(f"{info['username']}@{ip}:{port}|{files_str}")
                    response = ";".join(entries) if entries else "NO_PEERS_FOUND"

        # ... keep SEARCH, cleanup, etc. unchanged ...
        else:
            response = "ERROR: Unknown command"

        conn.send(response.encode("utf-8"))

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
        current_time = time.time()
        with registry_lock:
            to_delete = [
                key for key, info in peer_registry_data.items()
                if current_time - info['last_seen'] > 90
            ]
            for ip_port in to_delete:
                peer_registry_store.remove(
                    (Query().ip == ip_port[0]) & (Query().port == ip_port[1])
                )
                del peer_registry_data[ip_port]
                print(f"[INFO] Removed inactive peer: {ip_port}")


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


if __name__ == "__main__":
    threading.Thread(target=start_discovery_server, args=(), daemon=True).start()
    input()
