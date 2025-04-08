#!/usr/bin/env python3
import socket
import threading
import os
import sys
import argparse
import time

# ---------------------------
# Configuration & Global Variables
# ---------------------------
BUFFER_SIZE = 4096  # bytes per chunk
SHARED_FILES_DIR = "./shared_files"  # directory where files to share are stored

# Discovery server configuration
DISCOVERY_SERVER_IP = "127.0.0.1"  # Adjust as needed
DISCOVERY_SERVER_PORT = 6000

# Heartbeat interval (in seconds)
HEARTBEAT_INTERVAL = 30


# ---------------------------
# Utility Functions
# ---------------------------
def list_local_shared_files():
    """Return a list of files available in the shared directory."""
    if not os.path.exists(SHARED_FILES_DIR):
        os.makedirs(SHARED_FILES_DIR)
    return os.listdir(SHARED_FILES_DIR)


def send_all(sock, data):
    """Helper function to send all data over a socket."""
    totalsent = 0
    while totalsent < len(data):
        sent = sock.send(data[totalsent:])
        if sent == 0:
            raise RuntimeError("Socket connection broken")
        totalsent += sent


def recv_all(sock, length):
    """Helper function to receive a given amount of data."""
    data = b""
    while len(data) < length:
        chunk = sock.recv(min(length - len(data), BUFFER_SIZE))
        if chunk == b"":
            break
        data += chunk
    return data


# ---------------------------
# Discovery Client Functions
# ---------------------------
def register_with_discovery(own_ip, own_port):
    """Register this peer with the discovery server along with its file list."""
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
        print(f"[ERROR] Failed to register with discovery server: {e}")
    finally:
        sock.close()


def start_heartbeat(own_ip, own_port):
    """Periodically send registration (heartbeat) to the discovery server."""
    while True:
        register_with_discovery(own_ip, own_port)
        time.sleep(HEARTBEAT_INTERVAL)


def get_active_peers():
    """Query the discovery server for a list of active peers and their files."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
        sock.send(b"LIST")
        data = sock.recv(BUFFER_SIZE).decode("utf-8")
        sock.close()

        # Parse response format: ip:port|file1,file2;ip:port|fileA,fileB;...
        peers = {}
        if data:
            entries = data.split(";")
            for entry in entries:
                if entry:
                    peer_info, files = entry.split("|")
                    ip, port = peer_info.split(":")
                    peers[(ip, int(port))] = files.split(",") if files else []
        return peers
    except Exception as e:
        print(f"[ERROR] Failed to get active peers: {e}")
        return {}


def search_file_discovery(filename):
    """Search for peers that have the given file."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
        search_msg = f"SEARCH {filename}"
        sock.send(search_msg.encode("utf-8"))
        response = sock.recv(BUFFER_SIZE).decode("utf-8")
        sock.close()
        # Response format: ip:port,ip:port,... or "NOT_FOUND"
        if response == "NOT_FOUND":
            return []
        else:
            peer_strings = response.split(",")
            result = []
            for peer_str in peer_strings:
                ip, port = peer_str.split(":")
                result.append((ip, int(port)))
            return result
    except Exception as e:
        print(f"[ERROR] File search failed: {e}")
        return []


# ---------------------------
# Core P2P Networking Module
# ---------------------------
class P2PNode:
    def __init__(self, host="0.0.0.0", port=5000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True

    def start_server(self):
        """Start a thread to listen for incoming peer connections."""
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"[INFO] Listening on {self.host}:{self.port}")
        except Exception as e:
            print(f"[ERROR] Could not start server: {e}")
            sys.exit(1)
        thread = threading.Thread(target=self.accept_peers, daemon=True)
        thread.start()

    def accept_peers(self):
        """Accept incoming connections and create a new thread to handle them."""
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                print(f"[INFO] Accepted connection from {client_addr}")
                threading.Thread(target=self.handle_client, args=(client_sock,), daemon=True).start()
            except Exception as e:
                print(f"[ERROR] Error accepting connection: {e}")

    def handle_client(self, client_sock):
        """
        Handle incoming requests from a connected peer.
        Protocol:
          - The client sends a command string ("LIST", "DOWNLOAD <filename>").
          - Depending on the command, reply with the list or send the file data.
        """
        try:
            data = client_sock.recv(BUFFER_SIZE).decode("utf-8").strip()
            if not data:
                client_sock.close()
                return

            tokens = data.split()
            command = tokens[0].upper()
            if command == "LIST":
                # Send list of available files (as comma-separated string)
                files = list_local_shared_files()
                response = ",".join(files)
                client_sock.send(response.encode("utf-8"))
            elif command == "DOWNLOAD" and len(tokens) > 1:
                filename = tokens[1]
                filepath = os.path.join(SHARED_FILES_DIR, filename)
                if os.path.exists(filepath):
                    # Send file size first
                    filesize = os.path.getsize(filepath)
                    client_sock.send(f"{filesize}".encode("utf-8"))
                    ack = client_sock.recv(BUFFER_SIZE)  # wait for acknowledgment
                    with open(filepath, "rb") as f:
                        while True:
                            chunk = f.read(BUFFER_SIZE)
                            if not chunk:
                                break
                            send_all(client_sock, chunk)
                    print(f"[INFO] Sent file '{filename}'")
                else:
                    client_sock.send(b"ERROR: File not found")
            else:
                client_sock.send(b"ERROR: Unknown command")
        except Exception as e:
            print(f"[ERROR] Handling client error: {e}")
        finally:
            client_sock.close()

    def connect_to_peer(self, peer_ip, peer_port):
        """Create a connection to another peer."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))
            return sock
        except Exception as e:
            print(f"[ERROR] Could not connect to peer {peer_ip}:{peer_port}: {e}")
            return None

    def get_peer_file_list(self, peer_ip, peer_port):
        """Connect to a peer and request its file list."""
        sock = self.connect_to_peer(peer_ip, peer_port)
        if sock:
            try:
                sock.send(b"LIST")
                data = sock.recv(BUFFER_SIZE).decode("utf-8")
                files = data.split(",") if data else []
                return files
            except Exception as e:
                print(f"[ERROR] Failed to get file list: {e}")
            finally:
                sock.close()
        return None

    def download_file_from_peer(self, peer_ip, peer_port, filename):
        """Download a file from a peer."""
        sock = self.connect_to_peer(peer_ip, peer_port)
        if sock:
            try:
                command = f"DOWNLOAD {filename}"
                sock.send(command.encode("utf-8"))
                # First receive file size
                response = sock.recv(BUFFER_SIZE).decode("utf-8")
                if response.startswith("ERROR"):
                    print(response)
                    sock.close()
                    return
                filesize = int(response)
                # Send acknowledgment
                sock.send(b"ACK")
                remaining = filesize
                filedata = b""
                while remaining:
                    chunk = sock.recv(min(BUFFER_SIZE, remaining))
                    if not chunk:
                        break
                    filedata += chunk
                    remaining -= len(chunk)
                # Save the file
                save_path = os.path.join(SHARED_FILES_DIR, filename)
                with open(save_path, "wb") as f:
                    f.write(filedata)
                print(f"[INFO] Downloaded file '{filename}' from {peer_ip}:{peer_port}")
            except Exception as e:
                print(f"[ERROR] Error downloading file: {e}")
            finally:
                sock.close()


# ---------------------------
# CLI Interface Module
# ---------------------------
def cli_loop(node: P2PNode):
    help_message = (
        "\nAvailable commands:\n"
        "  list_local                      - List files in your shared folder\n"
        "  list_peer <ip> <port>           - List files available at a peer\n"
        "  list_active                     - List active peers from discovery server\n"
        "  search <filename>               - Search for a file across peers\n"
        "  download <ip> <port> <filename> - Download a file from a peer\n"
        "  exit                          - Exit the application\n"
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
                files = list_local_shared_files()
                print("Local shared files:", files)
            elif cmd == "list_peer" and len(parts) == 3:
                peer_ip = parts[1]
                peer_port = int(parts[2])
                files = node.get_peer_file_list(peer_ip, peer_port)
                if files is not None:
                    print(f"Files at {peer_ip}:{peer_port}:", files)
                else:
                    print("Could not retrieve file list from the peer.")
            elif cmd == "list_active":
                peers = get_active_peers()
                if peers:
                    print("Active peers (from discovery):")
                    for (ip, port), files in peers.items():
                        print(f"  {ip}:{port} -> {files}")
                else:
                    print("No active peers found.")
            elif cmd == "search" and len(parts) == 2:
                filename = parts[1]
                peers = search_file_discovery(filename)
                if peers:
                    print(f"Peers with '{filename}':", peers)
                else:
                    print(f"No peers found with '{filename}'.")
            elif cmd == "download" and len(parts) == 4:
                peer_ip = parts[1]
                peer_port = int(parts[2])
                filename = parts[3]
                node.download_file_from_peer(peer_ip, peer_port, filename)
            elif cmd == "exit":
                print("Exiting CLI...")
                node.running = False
                node.server_socket.close()
                break
            else:
                print("Unknown command. Available commands:")
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
    parser = argparse.ArgumentParser(description="P2P File Sharing Node with Discovery & Heartbeat")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on for P2P connections")
    args = parser.parse_args()

    p2p_node = P2PNode(port=args.port)
    p2p_node.start_server()

    # Determine the own IP address
    try:
        own_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        own_ip = "127.0.0.1"

    # Initial registration with the discovery server
    register_with_discovery(own_ip, args.port)

    # Start heartbeat thread to re-register every HEARTBEAT_INTERVAL seconds.
    heartbeat_thread = threading.Thread(target=start_heartbeat, args=(own_ip, args.port), daemon=True)
    heartbeat_thread.start()

    print("[INFO] Peer node started and registered with discovery server.")
    cli_loop(p2p_node)


if __name__ == "__main__":
    main()
