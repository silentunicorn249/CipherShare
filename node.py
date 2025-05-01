#!/usr/bin/env python3
import hashlib
import os
import sys
import threading
from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from typing import List

from SecureSocket import SecureSocket
from constants import *
from file_utils import receive_file_with_hash, send_file_with_hash


def compute_file_hash(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


# ---------------------------
# Core P2P Networking Module
# ---------------------------
class P2PNode:
    def __init__(self, host="0.0.0.0", port=5000):
        self.host = host
        self.port = port
        self.peer_socket = SecureSocket(AF_INET, SOCK_STREAM)
        self.running = True
        self.disabled_files = set()
        # Global dictionary mapping filename to set of allowed IP addresses
        self.shared_files_restrictions = {}
        self.session_token = ""
        self.peers = {}
        self.username = ""

    # ---------------------------
    # Utility Functions
    # ---------------------------

    def list_local_shared_files(self):
        """Return a list of files available in the shared directory, excluding disabled files."""
        if not os.path.exists(SHARED_FILES_DIR):
            os.makedirs(SHARED_FILES_DIR)
        if not os.path.exists(DOWNLOAD_DIR):
            os.makedirs(DOWNLOAD_DIR)
        all_files = os.listdir(SHARED_FILES_DIR)
        return [f for f in all_files if f not in self.disabled_files]

    def upload_file_to_peer(self, filename: str, client_sock: SecureSocket, client_ip):
        if filename in self.disabled_files:
            client_sock.send(b"ERROR: File is disabled for sharing")
            return

        if filename in self.shared_files_restrictions:
            allowed_ips = self.shared_files_restrictions[filename]
            if client_ip not in allowed_ips:
                client_sock.send(b"ERROR: Not allowed to download this file")
                return

        filepath = os.path.join(SHARED_FILES_DIR, filename)
        print(filepath)
        if not os.path.exists(filepath):
            client_sock.send(b"ERROR: File not found")
            return

        send_file_with_hash(client_sock, filepath)

    def download_file_from_peer(self, username, filename):
        """Download a file from a peer."""
        _ = self.peers[username]
        if _:
            peer_ip, peer_port, peer_token = self.peers[username]
        else:
            print("No user found")
            return

        print(f"Downloading file from peer {username}")
        sock = self.connect_to_peer(peer_ip, peer_port)
        if sock:
            try:
                command = f"DOWNLOAD {filename} {self.username} {self.session_token}"
                sock.send(command.encode("utf-8"))
                sock._perform_key_exchange(is_server=False)
                response = sock.recv(BUFFER_SIZE).decode("utf-8")
                if response.startswith("ERROR"):
                    print(response)
                    sock.close()
                    return
                filesize = int(response)
                received = receive_file_with_hash(sock, filename, filesize)
                if received:
                    print(f"[INFO] Downloaded file '{filename}' from {peer_ip}:{peer_port} with integrity verified")
                else:
                    print(f"[ERROR] File integrity check failed for '{filename}'")
            except Exception as e:
                print(f"[ERROR] Error downloading file: {e}")
            finally:
                print("Closing connection")
                sock.close()

    # ---------------------------
    # Discovery Client Functions
    # ---------------------------

    def send_discovery_message(self, request_msg):
        sock = SecureSocket(AF_INET, SOCK_STREAM)
        sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
        print(f"[DISCOVERY] Sending request: {request_msg}")
        sock.send(request_msg.encode("utf-8"))
        data = sock.recv(BUFFER_SIZE).decode("utf-8")
        sock.close()

        if data.startswith("ERROR"):
            print(f"[Server ERROR] {data}")
            return ""

        return data

    def get_active_peers(self):
        """Query the discovery server for a list of active peers and their files."""
        try:
            return self.peers
            request_msg = f"LIST {self.session_token}"

            data = self.send_discovery_message(request_msg)

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

    def search_file_discovery(self, filename):
        """Search for peers that have the given file."""
        try:
            search_msg = f"SEARCH {self.session_token} {filename}"
            response = self.send_discovery_message(search_msg)
            if not response: return

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

    def start_server(self):
        """Start a thread to listen for incoming peer connections."""
        try:
            self.peer_socket.bind((self.host, self.port))
            self.peer_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            self.peer_socket.listen(5)
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
                client_sock, client_addr = self.peer_socket.accept()
                print(f"[INFO] Accepted connection from {client_addr}")
                threading.Thread(target=self.handle_client, args=(client_sock, client_addr), daemon=True).start()
            except Exception as e:
                print(f"[ERROR] Error accepting connection: {e}")

    def handle_client(self, client_sock: SecureSocket, client_addr):
        """
        Handle incoming requests from a connected peer.
        Protocol:
          - The client sends a command string ("LIST", "DOWNLOAD <filename>").
          - Depending on the command, reply with the list or send the file data.
          - For DOWNLOAD, verifies if the file is restricted to specific nodes.
        """
        print(f"Started handling client {client_addr}")
        if True:
            data = client_sock.recv(BUFFER_SIZE).decode("utf-8").strip()
            if not data:
                client_sock.close()
                return

            tokens = data.split()
            command = tokens[0].upper()
            if command == "LIST":
                # Send list of available files (as comma-separated string)
                files = self.list_local_shared_files()
                response = ",".join(files)
                client_sock.send(response.encode("utf-8"))
            elif command == "DOWNLOAD" and len(tokens) > 1:
                print(f"starting uploading file {tokens}")
                filename = tokens[1]
                requester_username = tokens[2]
                requester_token = tokens[3]
                client_sock._perform_key_exchange(is_server=True)
                if requester_username not in self.peers:
                    client_sock.send(b"ERROR: Unknown user")
                    client_sock.close()
                    return
                saved_token = self.peers[requester_username][2]

                if saved_token != requester_token:
                    print(tokens)
                    print(self.peers)
                    print(saved_token, requester_token)
                    client_sock.send(b"ERROR: Invalid token")
                    client_sock.close()
                    return
                self.upload_file_to_peer(filename, client_sock, client_addr[0])
                client_sock.close()

            elif command == "UPDATE":
                print(f"[INFO] GOT Update {tokens}")
                username = tokens[1]
                peer_ip = tokens[2]
                peer_port = int(tokens[3])
                peer_token = tokens[4]
                self.peers[username] = [peer_ip, peer_port, peer_token]

            else:
                client_sock.send(b"ERROR: Unknown command")
        # except Exception as e:
        #     print(f"[ERROR] Handling client error: {e}")
        # finally:
        #     client_sock.close()

    def connect_to_peer(self, peer_ip, peer_port):
        """Create a connection to another peer."""
        try:
            print(f"[INFO] Connecting to {peer_ip}:{peer_port}")
            sock = SecureSocket(AF_INET, SOCK_STREAM)
            sock.connect((peer_ip, peer_port))
            return sock
        except Exception as e:
            print(f"[ERROR] Could not connect to peer {peer_ip}:{peer_port}: {e}")
            return None

    # ---------------------------
    # File Sharing Settings
    # ---------------------------
    def disable_file(self, filename):
        self.disabled_files.add(filename)

    def enable_file(self, filename) -> bool:
        if filename in self.disabled_files:
            self.disabled_files.remove(filename)
            return True
        return False

    def restrict_file(self, filename: os.PathLike | str, allowed_ips: List[str]):
        self.shared_files_restrictions[filename] = set(allowed_ips)

    def unrestrict_file(self, filename: os.PathLike | str) -> bool:
        if filename in self.shared_files_restrictions:
            del self.shared_files_restrictions[filename]
            return True
        return False

    def get_peer_file_list(self, username):
        """Connect to a peer and request its file list."""
        _ = self.peers[username]
        if _:
            peer_ip, peer_port = self.peers[username]
        else:
            # TODO extract print
            print("No user found")
            return
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

    def register_user(self, username, password, own_ip, own_port):
        """Register a new user with the given username and password."""
        try:
            sock = SecureSocket(AF_INET, SOCK_STREAM)
            sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
            files = self.list_local_shared_files()
            file_list_str = ",".join(files)
            register_msg = f"REGISTER {username} {password} {own_ip} {own_port} {file_list_str}"
            sock.send(register_msg.encode("utf-8"))
            response = sock.recv(BUFFER_SIZE).decode("utf-8").strip()
            if response.startswith("REGISTERED"):
                self.session_token = response.split(" ")[1] if " " in response else None
                self.username = username
                print(f"[INFO] User '{username}' registered successfully.")
                return True
            else:
                print(f"[ERROR] Registration failed: {response}")
                return False
        except Exception as e:
            print(f"[ERROR] Failed to register with discovery server: {e}")
        finally:
            sock.close()

    def login_user(self, username, password):
        """Login with the given username and password."""
        try:
            sock = SecureSocket(AF_INET, SOCK_STREAM)
            sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
            login_msg = f"LOGIN {username} {password}"
            sock.send(login_msg.encode("utf-8"))
            response = sock.recv(BUFFER_SIZE).decode("utf-8").strip()
            if response.startswith("LOGGED_IN"):
                parts = response.split()
                if len(parts) >= 4:
                    self.session_token = parts[1]  # Session token is the 4th part
                    self.username = username
                    print(f"[INFO] User '{username}' logged in successfully with session token {self.session_token}.")
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
