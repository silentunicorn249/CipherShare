#!/usr/bin/env python3
import socket
import threading
import os
import sys
import argparse
import time
import uuid

# ---------------------------
# Global Configuration
# ---------------------------
BUFFER_SIZE = 4096
SHARED_FILES_DIR = "./shared_files"
BROADCAST_TTL = 4         # initial TTL for broadcast messages
BCAST_CACHE_EXPIRY = 120    # seconds to keep seen message IDs

# Discovery server configuration (default)
DISCOVERY_SERVER_IP = "127.0.0.1"  # Change as appropriate
DISCOVERY_SERVER_PORT = 6000

# ---------------------------
# Helper Functions
# ---------------------------
def list_local_shared_files():
    """Return a list of files available in the shared directory."""
    if not os.path.exists(SHARED_FILES_DIR):
        os.makedirs(SHARED_FILES_DIR)
    return os.listdir(SHARED_FILES_DIR)

def send_all(sock, data):
    totalsent = 0
    while totalsent < len(data):
        sent = sock.send(data[totalsent:])
        if sent == 0:
            raise RuntimeError("Socket connection broken")
        totalsent += sent

# ---------------------------
# Broadcast Cache (to avoid processing duplicate broadcast messages)
# ---------------------------
class BroadcastCache:
    def __init__(self):
        self.cache = {}  # msg_id: timestamp
        self.lock = threading.Lock()

    def add(self, msg_id):
        with self.lock:
            self.cache[msg_id] = time.time()

    def exists(self, msg_id):
        with self.lock:
            return msg_id in self.cache

    def cleanup(self):
        while True:
            time.sleep(30)
            with self.lock:
                now = time.time()
                to_del = [mid for mid, ts in self.cache.items() if now - ts > BCAST_CACHE_EXPIRY]
                for mid in to_del:
                    del self.cache[mid]

bcast_cache = BroadcastCache()
threading.Thread(target=bcast_cache.cleanup, daemon=True).start()

# ---------------------------
# Decentralized P2P Node Class with Peer Discovery
# ---------------------------
class P2PNode:
    def __init__(self, host="0.0.0.0", port=5000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        # List of neighbor tuples: (ip, port)
        self.neighbors = []
        self.lock = threading.Lock()

    def start_server(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.listen(10)
            print(f"[INFO] Listening on {self.host}:{self.port}")
        except Exception as e:
            print(f"[ERROR] Could not start server: {e}")
            sys.exit(1)
        threading.Thread(target=self.accept_peers, daemon=True).start()

    def accept_peers(self):
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                threading.Thread(target=self.handle_connection, args=(client_sock, client_addr), daemon=True).start()
            except Exception as e:
                print(f"[ERROR] Error accepting connection: {e}")

    def handle_connection(self, client_sock, client_addr):
        try:
            data = client_sock.recv(BUFFER_SIZE).decode("utf-8").strip()
            if not data:
                client_sock.close()
                return

            tokens = data.split()
            command = tokens[0].upper()
            if command == "LIST":
                # Direct request for local file list.
                files = list_local_shared_files()
                client_sock.send(",".join(files).encode("utf-8"))
            elif command == "DOWNLOAD" and len(tokens) > 1:
                filename = tokens[1]
                filepath = os.path.join(SHARED_FILES_DIR, filename)
                if os.path.exists(filepath):
                    filesize = os.path.getsize(filepath)
                    client_sock.send(f"{filesize}".encode("utf-8"))
                    ack = client_sock.recv(BUFFER_SIZE)  # wait for ACK
                    with open(filepath, "rb") as f:
                        while (chunk := f.read(BUFFER_SIZE)):
                            send_all(client_sock, chunk)
                    print(f"[INFO] Sent file '{filename}'")
                else:
                    client_sock.send(b"ERROR: File not found")
            elif command == "DISCOVER":
                # New: Return my neighbor list to the requester.
                with self.lock:
                    neighbor_str = ";".join([f"{ip}:{port}" for (ip, port) in self.neighbors])
                client_sock.send(neighbor_str.encode("utf-8"))
            elif command == "BCAST":
                # Broadcast message handling: Format: BCAST <msg_id> <TTL> <CMD> <params...>
                if len(tokens) < 4:
                    client_sock.send(b"ERROR: Invalid broadcast format")
                    client_sock.close()
                    return
                msg_id, ttl_str, bcmd = tokens[1], tokens[2], tokens[3].upper()
                try:
                    ttl = int(ttl_str)
                except ValueError:
                    ttl = 0
                if bcast_cache.exists(msg_id):
                    client_sock.close()
                    return
                bcast_cache.add(msg_id)
                if bcmd == "SEARCH" and len(tokens) == 5:
                    filename = tokens[4]
                    if filename in list_local_shared_files():
                        print(f"[BCAST] Found '{filename}' locally. (msg_id: {msg_id})")
                        # Optionally, send a direct response to the original sender
                if ttl > 1:
                    self.forward_broadcast(msg_id, ttl - 1, bcmd, tokens[4:])
                client_sock.close()
            else:
                client_sock.send(b"ERROR: Unknown command")
        except Exception as e:
            print(f"[ERROR] Handling connection error: {e}")
        finally:
            client_sock.close()

    def forward_broadcast(self, msg_id, ttl, bcmd, params):
        """Forward broadcast message to all neighbors."""
        with self.lock:
            for neighbor in self.neighbors:
                try:
                    ip, port = neighbor
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((ip, port))
                    param_str = " ".join(params)
                    msg = f"BCAST {msg_id} {ttl} {bcmd} {param_str}"
                    sock.send(msg.encode("utf-8"))
                    sock.close()
                except Exception as e:
                    print(f"[ERROR] Forwarding broadcast to {neighbor} failed: {e}")

    def add_neighbor(self, peer_ip, peer_port):
        with self.lock:
            if (peer_ip, peer_port) not in self.neighbors and (peer_ip, peer_port) != (self.host, self.port):
                self.neighbors.append((peer_ip, peer_port))
                print(f"[INFO] Added neighbor: {peer_ip}:{peer_port}")

    def get_peer_file_list(self, peer_ip, peer_port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))
            sock.send(b"LIST")
            data = sock.recv(BUFFER_SIZE).decode("utf-8")
            sock.close()
            return data.split(",") if data else []
        except Exception as e:
            print(f"[ERROR] Could not get file list from {peer_ip}:{peer_port}: {e}")
            return None

    def broadcast_search(self, filename):
        """Initiate a broadcast search for the given file."""
        msg_id = str(uuid.uuid4())
        ttl = BROADCAST_TTL
        message = f"BCAST {msg_id} {ttl} SEARCH {filename}"
        bcast_cache.add(msg_id)  # so we don't process our own message
        with self.lock:
            for neighbor in self.neighbors:
                try:
                    ip, port = neighbor
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((ip, port))
                    sock.send(message.encode("utf-8"))
                    sock.close()
                except Exception as e:
                    print(f"[ERROR] Broadcast to {neighbor} failed: {e}")
        print(f"[INFO] Broadcast for '{filename}' initiated with msg_id: {msg_id}")

    def download_file_from_peer(self, peer_ip, peer_port, filename):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))
            command = f"DOWNLOAD {filename}"
            sock.send(command.encode("utf-8"))
            response = sock.recv(BUFFER_SIZE).decode("utf-8")
            if response.startswith("ERROR"):
                print(response)
                sock.close()
                return
            filesize = int(response)
            sock.send(b"ACK")
            remaining = filesize
            filedata = b""
            while remaining:
                chunk = sock.recv(min(BUFFER_SIZE, remaining))
                if not chunk:
                    break
                filedata += chunk
                remaining -= len(chunk)
            save_path = os.path.join(SHARED_FILES_DIR, filename)
            with open(save_path, "wb") as f:
                f.write(filedata)
            print(f"[INFO] Downloaded file '{filename}' from {peer_ip}:{peer_port}")
        except Exception as e:
            print(f"[ERROR] Error downloading file: {e}")
        finally:
            sock.close()

    # ---------------------------
    # New: Peer Discovery Functions
    # ---------------------------
    def discover_from_neighbor(self, peer_ip, peer_port):
        """
        Send a DISCOVER command to a specific neighbor to get its neighbor list.
        Returns a list of (ip, port) tuples.
        """
        discovered = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))
            sock.send(b"DISCOVER")
            data = sock.recv(BUFFER_SIZE).decode("utf-8")
            sock.close()
            if data:
                entries = data.split(";")
                for entry in entries:
                    if entry:
                        ip, port = entry.split(":")
                        discovered.append((ip, int(port)))
        except Exception as e:
            print(f"[ERROR] DISCOVER request to {peer_ip}:{peer_port} failed: {e}")
        return discovered

    def discover_neighbors(self):
        """
        Iterate over known neighbors, send DISCOVER requests, and merge results into the neighbor list.
        """
        new_neighbors = []
        with self.lock:
            current = self.neighbors.copy()
        for neighbor in current:
            ip, port = neighbor
            discovered = self.discover_from_neighbor(ip, port)
            for peer in discovered:
                if peer not in current and peer not in new_neighbors and peer != (self.host, self.port):
                    new_neighbors.append(peer)
        with self.lock:
            for peer in new_neighbors:
                self.neighbors.append(peer)
        if new_neighbors:
            print(f"[INFO] Discovered new neighbors: {new_neighbors}")
        else:
            print("[INFO] No additional neighbors discovered.")

# ---------------------------
# Discovery Server Connection Helpers
# ---------------------------
def try_connect_to_discovery(own_ip, own_port):
    """Attempt to connect and register with the discovery server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
        sock.close()
        print(f"[INFO] Connected to discovery server at {DISCOVERY_SERVER_IP}:{DISCOVERY_SERVER_PORT}")
        register_with_discovery(own_ip, own_port)
        return True
    except Exception as e:
        print(f"[WARNING] Could not connect to discovery server: {e}")
        return False

def register_with_discovery(own_ip, own_port):
    """Register this node with the discovery server (sending file list along)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
        files = list_local_shared_files()
        file_list_str = ",".join(files)
        register_msg = f"REGISTER {own_ip} {own_port} {file_list_str}"
        sock.send(register_msg.encode("utf-8"))
        response = sock.recv(BUFFER_SIZE).decode("utf-8")
        print(f"[DISCOVERY] Register response: {response}")
    except Exception as e:
        print(f"[ERROR] Registration with discovery server failed: {e}")
    finally:
        sock.close()

# ---------------------------
# CLI Interface
# ---------------------------
def cli_loop(node: P2PNode):
    help_message = (
        "\nCommands:\n"
        "  list_local                         - List local shared files\n"
        "  list_peer <ip> <port>              - Get file list from a peer\n"
        "  add_neighbor <ip> <port>           - Manually add a neighbor\n"
        "  discover                           - Query known neighbors for their neighbor lists\n"
        "  bcast_search <filename>            - Broadcast search for a file\n"
        "  download <ip> <port> <filename>      - Download file from a peer\n"
        "  exit                               - Exit\n"
    )
    print(help_message)
    while True:
        try:
            user_input = input(">> ").strip()
            if not user_input:
                continue
            parts = user_input.split()
            cmd = parts[0].lower()
            if cmd == "list_local":
                print("Local files:", list_local_shared_files())
            elif cmd == "list_peer" and len(parts) == 3:
                files = node.get_peer_file_list(parts[1], int(parts[2]))
                print(f"Files at {parts[1]}:{parts[2]}:", files)
            elif cmd == "add_neighbor" and len(parts) == 3:
                node.add_neighbor(parts[1], int(parts[2]))
            elif cmd == "discover":
                node.discover_neighbors()
            elif cmd == "bcast_search" and len(parts) == 2:
                node.broadcast_search(parts[1])
            elif cmd == "download" and len(parts) == 4:
                node.download_file_from_peer(parts[1], int(parts[2]), parts[3])
            elif cmd == "exit":
                print("Exiting...")
                node.running = False
                node.server_socket.close()
                break
            else:
                print(help_message)
        except KeyboardInterrupt:
            print("\nExiting...")
            node.running = False
            node.server_socket.close()
            break
        except Exception as e:
            print(f"[ERROR] {e}")

# ---------------------------
# Main Entry Point
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="Decentralized P2P Node with Discovery")
    parser.add_argument("--port", type=int, default=5000, help="Listening port for this node")
    args = parser.parse_args()

    node = P2PNode(port=args.port)
    node.start_server()

    # Obtain own IP address.
    try:
        own_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        own_ip = "127.0.0.1"

    # Try to connect to the discovery server first.
    if try_connect_to_discovery(own_ip, args.port):
        # Optionally, update neighbor list from the discovery server here.
        pass
    else:
        # Discovery server unreachable; ask user for an alternate node.
        print("[INFO] Discovery server is unreachable.")
        neighbor_ip = input("Enter alternate node IP: ").strip()
        neighbor_port = int(input("Enter alternate node port: ").strip())
        node.add_neighbor(neighbor_ip, neighbor_port)

    print("[INFO] Node started. Ready for commands.")
    cli_loop(node)

if __name__ == "__main__":
    main()
