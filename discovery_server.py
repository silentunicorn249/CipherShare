#!/usr/bin/env python3
import socket
import threading
import time

# Server configuration
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 6000
BUFFER_SIZE = 4096

# In-memory registry: mapping (ip, port) -> {"files": [list of filenames], "last_seen": timestamp}
peer_registry = {}

# Lock for synchronizing access to peer_registry
registry_lock = threading.Lock()

def handle_client(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode("utf-8").strip()
        if not data:
            conn.close()
            return

        tokens = data.split()
        command = tokens[0].upper()
        response = ""

        if command == "REGISTER":
            # Expected format: REGISTER <peer_ip> <peer_port> <file1,file2,...>
            # This command is used both for initial registration and for heartbeat updates.
            if len(tokens) < 4:
                response = "ERROR: REGISTER command format: REGISTER <ip> <port> <file1,file2,...>"
            else:
                peer_ip = tokens[1]
                try:
                    peer_port = int(tokens[2])
                except ValueError:
                    response = "ERROR: Invalid port number."
                else:
                    file_list = tokens[3].split(",") if tokens[3] else []
                    with registry_lock:
                        peer_registry[(peer_ip, peer_port)] = {"files": file_list, "last_seen": time.time()}
                    response = "REGISTERED"
        elif command == "LIST":
            # List all active peers in format: ip:port|file1,file2;...
            with registry_lock:
                entries = []
                for (ip, port), info in peer_registry.items():
                    files_str = ",".join(info["files"])
                    entries.append(f"{ip}:{port}|{files_str}")
                response = ";".join(entries)
        elif command == "SEARCH":
            # Expected format: SEARCH <filename>
            if len(tokens) != 2:
                response = "ERROR: SEARCH command format: SEARCH <filename>"
            else:
                search_file = tokens[1]
                matching_peers = []
                with registry_lock:
                    for (ip, port), info in peer_registry.items():
                        if search_file in info["files"]:
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
    cleanup_thread = threading.Thread(target=registry_cleanup, daemon=True)
    cleanup_thread.start()

    try:
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down discovery server.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_discovery_server()
