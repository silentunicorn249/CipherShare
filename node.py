#!/usr/bin/env python3
import os
import socket
import sys
import threading
import time
from typing import List

from constants import *


# ---------------------------
# Core P2P Networking Module
# ---------------------------
class P2PNode:
    def __init__(self, host="0.0.0.0", port=5000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.disabled_files = set()
        # Global dictionary mapping filename to set of allowed IP addresses
        self.shared_files_restrictions = {}
        self.session_token = None

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

    def register_with_discovery(self, own_ip, own_port):
        """Register this peer with the discovery server along with its file list."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
            files = self.list_local_shared_files()
            file_list_str = ",".join(files)
            register_msg = f"REGISTER {own_ip} {own_port} {file_list_str}"
            sock.send(register_msg.encode("utf-8"))
            response = sock.recv(BUFFER_SIZE).decode("utf-8")
            print(f"[DISCOVERY] Register response: {response}")
        except Exception as e:
            print(f"[ERROR] Failed to register with discovery server: {e}")
        finally:
            sock.close()

    def send_all(self, sock, data):
        """Helper function to send all data over a socket."""
        totalsent = 0
        while totalsent < len(data):
            sent = sock.send(data[totalsent:])
            if sent == 0:
                raise RuntimeError("Socket connection broken")
            totalsent += sent

    def recv_all(self, sock, length):
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

    def start_heartbeat(self, own_ip, own_port):
        """Periodically send registration (heartbeat) to the discovery server."""
        while True:
            self.register_with_discovery(own_ip, own_port)
            time.sleep(HEARTBEAT_INTERVAL)

    def get_active_peers(self):
        """Query the discovery server for a list of active peers and their files."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
            request_msg = f"LIST {self.session_token}"
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

    def search_file_discovery(self, filename):
        """Search for peers that have the given file."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
            search_msg = f"SEARCH {self.session_token} {filename}"
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
                files = self.list_local_shared_files()
                response = ",".join(files)
                client_sock.send(response.encode("utf-8"))
            elif command == "DOWNLOAD" and len(tokens) > 1:
                filename = tokens[1]
                # Check if file is restricted and if client's IP is allowed:
                if filename in self.disabled_files:
                    client_sock.send(b"ERROR: File is disabled for sharing")
                    return
                if filename in self.shared_files_restrictions:
                    allowed_ips = self.shared_files_restrictions[filename]
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
                            self.send_all(client_sock, chunk)
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

    def register_user(self, username, password, own_ip, own_port):
        """Register a new user with the given username and password."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
            files = self.list_local_shared_files()
            file_list_str = ",".join(files)
            register_msg = f"REGISTER {username} {password} {own_ip} {own_port} {file_list_str}"
            sock.send(register_msg.encode("utf-8"))
            response = sock.recv(BUFFER_SIZE).decode("utf-8").strip()
            if response.startswith("REGISTERED"):
                self.session_token = response.split(" ")[1] if " " in response else None
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
            login_msg = f"LOGIN {username} {password}"
            sock.send(login_msg.encode("utf-8"))
            response = sock.recv(BUFFER_SIZE).decode("utf-8").strip()
            if response.startswith("LOGGED_IN"):
                parts = response.split()
                if len(parts) >= 4:
                    self.session_token = parts[1]  # Session token is the 4th part
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

    def initial_authentication(self, own_ip, own_port):
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
                    if self.register_user(username, password, own_ip, own_port):
                        print(f"User '{username}' registered successfully.")
                        return True
                        # break

                elif cmd == "login" and len(parts) == 3:

                    username = parts[1]
                    password = parts[2]
                    if self.login_user(username, password):
                        print(f"User '{username}' logged in successfully.")
                        return True
                        # break

                elif cmd == "exit":
                    print("Exiting CLI...")
                    self.running = False
                    self.server_socket.close()
                    return False
                    # break
                else:
                    print("Unknown command. Available commands:")
                    print(help_message)
            except KeyboardInterrupt:
                print("\nExiting...")
                self.running = False
                self.server_socket.close()
                break
            except Exception as e:
                print(f"[ERROR] {e}")
