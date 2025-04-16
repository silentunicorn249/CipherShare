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
DOWNLOAD_DIR = "./downloads"  # directory where downloaded files are saved

# Global set of disabled files (by filename)
DISABLED_FILES = set()
# Global dictionary mapping filename to set of allowed IP addresses
SHARED_FILE_RESTRICTIONS = {}

# Discovery server configuration
DISCOVERY_SERVER_IP = "127.0.0.1"  # Adjust as needed
DISCOVERY_SERVER_PORT = 6000

# Heartbeat interval (in seconds)
HEARTBEAT_INTERVAL = 90

# This will store the session token globally once the user logs in
SESSION_TOKEN = None

# ---------------------------
# Utility Functions
# ---------------------------
def list_local_shared_files():
    """Return a list of files available in the shared directory, excluding disabled files."""
    if not os.path.exists(SHARED_FILES_DIR):
        os.makedirs(SHARED_FILES_DIR)
    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR)
    all_files = os.listdir(SHARED_FILES_DIR)
    return [f for f in all_files if f not in DISABLED_FILES]


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


def get_active_peers(session_id):
    """Query the discovery server for a list of active peers and their files."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
        request_msg = f"LIST {session_id}"
        print(f"[DISCOVERY] Sending request: {request_msg}")
        sock.send(request_msg.encode("utf-8"))
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



def search_file_discovery(filename, session_id):
    """Search for peers that have the given file."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
        search_msg = f"SEARCH {session_id} {filename}"
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
                threading.Thread(target=self.handle_client, args=(client_sock, client_addr), daemon=True).start()
            except Exception as e:
                print(f"[ERROR] Error accepting connection: {e}")

    def handle_client(self, client_sock: socket.socket, client_addr):
        """
        Handle incoming requests from a connected peer.
        Protocol:
          - The client sends a command string ("LIST", "DOWNLOAD <filename>").
          - Depending on the command, reply with the list or send the file data.
          - For DOWNLOAD, verifies if the file is restricted to specific nodes.
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
                # Check if file is restricted and if client's IP is allowed:
                if filename in DISABLED_FILES:
                    client_sock.send(b"ERROR: File is disabled for sharing")
                    return
                if filename in SHARED_FILE_RESTRICTIONS:
                    allowed_ips = SHARED_FILE_RESTRICTIONS[filename]
                    client_ip = client_addr[0]
                    if client_ip not in allowed_ips:
                        client_sock.send(b"ERROR: Not allowed to download this file")
                        return
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
                save_path = os.path.join(DOWNLOAD_DIR, filename)
                with open(save_path, "wb") as f:
                    f.write(filedata)
                print(f"[INFO] Downloaded file '{filename}' from {peer_ip}:{peer_port}")
            except Exception as e:
                print(f"[ERROR] Error downloading file: {e}")
            finally:
                sock.close()



def register_user(username, password, own_ip, own_port): 
    """Register a new user with the given username and password."""
    global SESSION_TOKEN
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
        files = list_local_shared_files()
        file_list_str = ",".join(files)
        register_msg = f"REGISTER {username} {password} {own_ip} {own_port} {file_list_str}"
        sock.send(register_msg.encode("utf-8"))
        response = sock.recv(BUFFER_SIZE).decode("utf-8").strip()
        if response.startswith("REGISTERED"):
            SESSION_TOKEN = response.split(" ")[1] if " " in response else None
            print(f"[INFO] User '{username}' registered successfully.")
            return True
        else:
            print(f"[ERROR] Registration failed: {response}")
            return False
    except Exception as e:
        print(f"[ERROR] Failed to register with discovery server: {e}")
    finally:
        sock.close()


def login_user(username, password):
    """Login with the given username and password."""
    global SESSION_TOKEN
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
        login_msg = f"LOGIN {username} {password}"
        sock.send(login_msg.encode("utf-8"))
        response = sock.recv(BUFFER_SIZE).decode("utf-8").strip()
        if response.startswith("LOGGED_IN"):
            parts = response.split()
            if len(parts) >= 4:
                SESSION_TOKEN = parts[1]  # Session token is the 4th part
                print(f"[INFO] User '{username}' logged in successfully with session token {SESSION_TOKEN}.")
                return True
            else:
                print("[ERROR] Malformed login response.")
                return False
        else:
            print(f"[ERROR] Login failed: {response}")
            return False
    except Exception as e:
        print(f"[ERROR] Failed to login with discovery server: {e}")
    finally:
        sock.close()


def initial_authentication(node: P2PNode, own_ip, own_port):
    # this function is called when the node starts and will register with the server using 
    # the username and password provided by the user
    help_message = (
        "\nAvailable commands:\n"
        " Register                  - register <username> <password>\n"
        " Login                     - login <username> <password>\n"
        " exit - Exit the application\n"
    )
    print(help_message)
    while True:
        try:
            user_input = input(">> ").strip()
            if not user_input:
                continue
            parts = user_input.split()
            cmd = parts[0].lower()
            if cmd == "register" and len(parts) == 3:
                username = parts[1]
                password = parts[2]
                if register_user(username, password, own_ip, own_port):
                    print(f"User '{username}' registered successfully.")
                    return True
                    # break
                
            elif cmd == "login" and len(parts) == 3:

                username = parts[1]
                password = parts[2]
                if login_user(username, password): 
                    print(f"User '{username}' logged in successfully.")
                    return True
                    # break
                
            elif cmd == "exit":
                print("Exiting CLI...")
                node.running = False
                node.server_socket.close()
                return False
                # break
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
        "  disable_file <filename>         - Disable sharing a file locally\n"
        "  enable_file <filename>          - Enable sharing a file locally\n"
        "  restrict_file <filename> <ip1,ip2,...>  - Restrict a file to specific nodes\n"
        "  unrestrict_file <filename>      - Remove restrictions on a file\n"
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
                peers = get_active_peers(SESSION_TOKEN)
                if peers:
                    print("Active peers (from discovery):")
                    for (ip, port), files in peers.items():
                        print(f"  {ip}:{port} -> {files}")
                else:
                    print("No active peers found.")

            elif cmd == "search" and len(parts) == 2:
                filename = parts[1]
                peers = search_file_discovery(filename, SESSION_TOKEN)
                if peers:
                    print(f"Peers with '{filename}':", peers)
                else:
                    print(f"No peers found with '{filename}'.")

            elif cmd == "download" and len(parts) == 4:
                peer_ip = parts[1]
                peer_port = int(parts[2])
                filename = parts[3]
                node.download_file_from_peer(peer_ip, peer_port, filename)


            elif cmd == "disable_file" and len(parts) == 2:
                filename = parts[1]
                DISABLED_FILES.add(filename)
                print(f"File '{filename}' disabled from sharing.")

            elif cmd == "enable_file" and len(parts) == 2:
                filename = parts[1]
                if filename in DISABLED_FILES:
                    DISABLED_FILES.remove(filename)
                    print(f"File '{filename}' enabled for sharing.")
                else:
                    print(f"File '{filename}' is not disabled.")

            elif cmd == "restrict_file" and len(parts) == 3:
                filename = parts[1]
                allowed_ips = parts[2].split(",")
                SHARED_FILE_RESTRICTIONS[filename] = set(allowed_ips)
                print(f"File '{filename}' restricted to nodes: {', '.join(allowed_ips)}")


            elif cmd == "unrestrict_file" and len(parts) == 2:
                filename = parts[1]
                if filename in SHARED_FILE_RESTRICTIONS:
                    del SHARED_FILE_RESTRICTIONS[filename]
                    print(f"Restrictions removed for file '{filename}'.")
                else:
                    print(f"No restrictions exist for file '{filename}'.")


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
    parser.add_argument("--disable-file", action="append", default=[], help="Filename to disable from being shared")
    # New: Option to restrict file sharing to specific nodes, format: filename:ip1,ip2,...
    parser.add_argument("--restrict-file", action="append", default=[], help="Restrict a file to specific nodes (format: filename:ip1,ip2,...)")
    args = parser.parse_args()
    
    global DISABLED_FILES, SHARED_FILE_RESTRICTIONS
    DISABLED_FILES = set(args.disable_file)
    for entry in args.restrict_file:
        try:
            file_part, ips = entry.split(":")
            SHARED_FILE_RESTRICTIONS[file_part] = set(ips.split(","))
        except Exception as e:
            print(f"[ERROR] Invalid restrict file format '{entry}': {e}")
    
    p2p_node = P2PNode(port=args.port)
    p2p_node.start_server()

    # Determine the own IP address
    try:
        own_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        own_ip = "127.0.0.1"

    # Initial registration with the discovery server

    # register_with_discovery(own_ip, args.port)

    # Start heartbeat thread to re-register every HEARTBEAT_INTERVAL seconds.
    # heartbeat_thread = threading.Thread(target=start_heartbeat, args=(own_ip, args.port), daemon=True)
    # heartbeat_thread.start()

    if initial_authentication(p2p_node, own_ip, args.port):

        print("[INFO] Peer node started and registered with discovery server.")
        cli_loop(p2p_node)


if __name__ == "__main__":
    main()
