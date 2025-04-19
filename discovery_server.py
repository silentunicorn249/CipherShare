#!/usr/bin/env python3
import hashlib
import socket
import threading
import time
import uuid

from constants import *

from tinydb import TinyDB, Query

sessions = {}
# Server configuration

# In-memory registry: mapping (ip, port) -> {"files": [list of filenames], "last_seen": timestamp}
# use tinydb to persist the data
peer_registry = TinyDB('peer_registry.json')

# Lock for synchronizing access to peer_registry
registry_lock = threading.Lock()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def handle_client(conn: socket.socket, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode("utf-8").strip()
        if not data:
            conn.close()
            return

        tokens = data.split()
        command = tokens[0].upper()
        response = ""

        if command == "REGISTER":
            if len(tokens) < 5:
                response = "ERROR: REGISTER format: REGISTER <username> <password> <ip> <port> [<files>]"
            else:
                username = tokens[1]
                raw_password = tokens[2]
                password = hash_password(raw_password)
                peer_ip = tokens[3]
                try:
                    peer_port = int(tokens[4])
                except ValueError:
                    response = "ERROR: Invalid port number."
                else:
                    file_list = tokens[5].split(",") if len(tokens) >= 6 and tokens[5] else []
                    with registry_lock:
                        peer_registry.insert({
                            "username": username,
                            "password": password,
                            "ip": peer_ip,
                            "port": peer_port,
                            "files": file_list,
                            "last_seen": time.time()
                        })

                        # Generate session token
                        session_token = str(uuid.uuid4())
                        sessions[session_token] = {
                            "username": username,
                            "ip": peer_ip,
                            "port": peer_port,
                            "files": file_list,
                            "last_seen": time.time()
                        }

                    print(f"[INFO] Peer registered: {username} from {peer_ip}:{peer_port} with files: {file_list}")
                    response = f"REGISTERED {session_token}"

        elif command == "LOGIN":
            if len(tokens) != 3:
                response = "ERROR: LOGIN command format: LOGIN <username> <password>"
            else:
                username = tokens[1]
                raw_password = tokens[2]
                hashed_password = hash_password(raw_password)
                user = Query()
                with registry_lock:
                    peer = peer_registry.get((user.username == username) & (user.password == hashed_password))
                    print(f"[INFO] Peer login attempt: {username} from {addr}")
                    if peer:
                        peer_registry.update({"last_seen": time.time()}, user.username == username)
                        ip = peer.get("ip", "unknown")
                        port = peer.get("port", "unknown")
                        files = peer.get("files", [])

                        # Generate session token
                        session_token = str(uuid.uuid4())
                        sessions[session_token] = {
                            "username": username,
                            "ip": ip,
                            "port": port,
                            "files": files,
                            "last_seen": time.time()
                        }

                        response = f"LOGGED_IN {session_token} {ip}:{port} {','.join(files)}"
                    else:
                        response = "INVALID_CREDENTIALS"

        elif command == "LIST":
            # Expected format: LIST <session_id>
            if len(tokens) != 2:
                response = "ERROR: LIST command format: LIST <session_id>"
            else:
                session_id = tokens[1]
                session = sessions.get(session_id)

                if not session:
                    response = "ERROR: Invalid session ID. Please login first."
                else:
                    with registry_lock:
                        entries = []
                        for s_id, s in sessions.items():
                            ip = s["ip"]
                            port = s["port"]
                            user = Query()
                            peer_info = peer_registry.get((user.ip == ip) & (user.port == port))
                            if peer_info:
                                files_str = ",".join(peer_info.get("files", []))
                                entries.append(f"{ip}:{port}|{files_str}")
                        response = ";".join(entries) if entries else "NO_PEERS_FOUND"

        elif command == "SEARCH":
            # Expected format: SEARCH <session_id> <filename>
            if len(tokens) != 3:
                response = "ERROR: SEARCH command format: SEARCH <session_id> <filename>"
            else:
                session_id = tokens[1]
                filename = tokens[2]
                session = sessions.get(session_id)

                if not session:
                    response = "ERROR: Invalid session ID. Please login first."
                else:
                    with registry_lock:
                        matching_peers = []
                        for s_id, s in sessions.items():
                            ip = s["ip"]
                            port = s["port"]
                            user = Query()
                            peer_info = peer_registry.get((user.ip == ip) & (user.port == port))
                            if peer_info and filename in peer_info.get("files", []):
                                matching_peers.append(f"{ip}:{port}")
                        response = ",".join(matching_peers) if matching_peers else "NOT_FOUND"

        else:
            response = "ERROR: Unknown command"

        conn.send(response.encode("utf-8"))
    except Exception as e:
        print(f"[ERROR] Exception handling client {addr}: {e}")
    finally:
        conn.close()


def registry_cleanup():
    """
    Periodically remove peers that haven't sent a heartbeat in the last 90 seconds.
    This ensures that peers are removed only if they are actually disconnected.
    """
    while True:
        time.sleep(30)
        current_time = time.time()
        with registry_lock:
            to_delete = []
            for (ip, port), info in peer_registry.items():
                if current_time - info["last_seen"] > 90:
                    to_delete.append((ip, port))
            for key in to_delete:
                del peer_registry[key]
                print(f"[INFO] Removed inactive peer: {key}")


def start_discovery_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"[INFO] Discovery server listening on {SERVER_HOST}:{SERVER_PORT}")

    # Launch cleanup thread
    # cleanup_thread = threading.Thread(target=registry_cleanup, daemon=True)
    # cleanup_thread.start()

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
