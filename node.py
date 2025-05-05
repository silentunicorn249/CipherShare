#!/usr/bin/env python3
import base64
import hashlib
import os
import socket
import threading
import time
from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from typing import List, Dict, Tuple, Optional

# Cryptography imports
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Local imports
from SecureSocket import SecureSocket  # Use SecureSocket
# Assume constants.py defines:
# SHARED_FILES_DIR, DOWNLOAD_DIR, NODE_PRIVATE_KEY_FILE, NODE_PUBLIC_KEY_FILE,
# SERVER_PUBLIC_KEY_FILE, DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT,
# BUFFER_SIZE, HEARTBEAT_INTERVAL, PUBLIC_EXPONENT, KEY_SIZE
from constants import *
# Assume file_utils.py defines:
# receive_file_with_hash(socket, filename, filesize) -> bool
# send_file_with_hash(socket, filepath) -> bool
from file_utils import receive_file_with_hash, send_file_with_hash


# --- Utility Functions ---
def compute_file_hash(filepath):
    """Computes the SHA256 hash of a file."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        print(f"[ERROR] File not found for hashing: {filepath}")
        return None
    except Exception as e:
        print(f"[ERROR] Error hashing file {filepath}: {e}")
        return None


# ---------------------------
# Core P2P Networking Module
# ---------------------------
class P2PNode:
    def __init__(self, host="0.0.0.0", port=5000):
        self.host = host  # Host to bind the listening socket
        self.port = port  # Port to bind the listening socket
        self.running = True
        self.disabled_files = set()
        self.shared_files_restrictions: Dict[str, set] = {}  # filename -> {allowed_ip1, allowed_ip2}
        self.session_token: Optional[str] = None
        # Peers format: { username: (ip, port, public_key_pem_str) }
        self.peers: Dict[str, Tuple[str, int, Optional[str]]] = {}
        self.peers_lock = threading.Lock()  # Lock for accessing self.peers
        self.username: Optional[str] = None
        self.listen_ip: Optional[str] = None  # The IP others should use to connect to this node

        # --- Key Management ---
        self.node_private_key: Optional[rsa.RSAPrivateKey] = None
        self.node_public_key_pem: Optional[bytes] = None  # PEM format as bytes
        self.server_public_key: Optional[rsa.RSAPublicKey] = None
        self._load_or_generate_node_keys()
        self._load_server_public_key()
        # --- End Key Management ---

        # --- Listening Socket ---
        # Initialize the listening socket as SecureSocket
        self.peer_listening_socket = SecureSocket(AF_INET, SOCK_STREAM)
        # Load own private key for accepting connections
        if self.node_private_key:
            self.peer_listening_socket.own_rsa_private_key = self.node_private_key
            print("[INFO] Node RSA private key loaded into listening socket.")
        else:
            print("[ERROR] Node private key not loaded. Cannot accept secure connections.")
            # Stop node if keys failed
            self.running = False
        # --- End Listening Socket ---

        # --- Threads ---
        self.server_thread = None  # Thread for accepting peer connections
        self.heartbeat_thread = None  # Thread for sending heartbeats
        # --- End Threads ---

        # Determine a suitable listen IP (best effort)
        self._determine_listen_ip()

        # Ensure shared/download directories exist
        self._ensure_directories()

        # Start server thread (bind and listen is done here)
        if self.running:
            self.start_server()

    def _ensure_directories(self):
        """Creates shared and download directories if they don't exist."""
        for dir_path in [SHARED_FILES_DIR, DOWNLOAD_DIR]:
            if not os.path.exists(dir_path):
                try:
                    os.makedirs(dir_path)
                    print(f"[INFO] Created directory: {dir_path}")
                except OSError as e:
                    print(f"[ERROR] Could not create directory {dir_path}: {e}")
                    # Decide if this is fatal. For now, log and continue.
                    # self.running = False

    def _determine_listen_ip(self):
        """Tries to determine the IP address peers should use."""
        # Option 1: Get IP from hostname (might be loopback or internal)
        try:
            hostname_ip = socket.gethostbyname(socket.gethostname())
            # Avoid loopback unless it's the only option
            if not hostname_ip.startswith("127."):
                self.listen_ip = hostname_ip
                print(f"[INFO] Determined listen IP from hostname: {self.listen_ip}")
                return
        except socket.gaierror:
            print("[WARN] Could not determine IP from hostname.")

        # Option 2: Try connecting to an external service (like the discovery server)
        # This often gives the outbound IP, which might be the public IP behind NAT
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # Doesn't actually send data, just finds the interface used to reach the target
                s.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))
                outbound_ip = s.getsockname()[0]
                if not outbound_ip.startswith("0.") and not outbound_ip.startswith("127."):  # Avoid 0.0.0.0 or loopback
                    self.listen_ip = outbound_ip
                    print(f"[INFO] Determined listen IP from outbound connection: {self.listen_ip}")
                    return
        except Exception as e:
            print(f"[WARN] Could not determine IP from outbound connection: {e}")

        # Fallback: Use 127.0.0.1 (only works locally)
        if not self.listen_ip:
            self.listen_ip = "127.0.0.1"
            print(f"[WARN] Falling back to listen IP: {self.listen_ip}. May only work locally.")

    # --- Key Loading Methods ---
    def _load_or_generate_node_keys(self):
        """Loads node RSA keys or generates them if they don't exist."""
        try:
            # Try loading private key
            with open(NODE_PRIVATE_KEY_FILE, "rb") as key_file:
                print(f"[INFO] Loading node private key from {NODE_PRIVATE_KEY_FILE}")
                self.node_private_key = serialization.load_pem_private_key(
                    key_file.read(), password=None
                )
            # Try loading public key PEM
            with open(NODE_PUBLIC_KEY_FILE, "rb") as key_file:
                print(f"[INFO] Loading node public key from {NODE_PUBLIC_KEY_FILE}")
                self.node_public_key_pem = key_file.read()  # Read as bytes

        except FileNotFoundError:
            print("[WARN] Node key files not found. Generating new keys...")
            self.node_private_key = rsa.generate_private_key(
                public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE
            )
            public_key = self.node_private_key.public_key()

            # Save private key
            pem_private = self.node_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(NODE_PRIVATE_KEY_FILE, "wb") as key_file:
                key_file.write(pem_private)
            print(f"[INFO] Saved new node private key to {NODE_PRIVATE_KEY_FILE}")

            # Save public key
            self.node_public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(NODE_PUBLIC_KEY_FILE, "wb") as key_file:
                key_file.write(self.node_public_key_pem)
            print(f"[INFO] Saved new node public key to {NODE_PUBLIC_KEY_FILE}")

        except Exception as e:
            print(f"[ERROR] Failed to load or generate node keys: {e}")
            self.node_private_key = None  # Ensure keys are None on failure
            self.node_public_key_pem = None
            self.running = False  # Stop node if keys fail

    def _load_server_public_key(self):
        """Loads the discovery server's public key from a file."""
        try:
            with open(SERVER_PUBLIC_KEY_FILE, "rb") as key_file:
                self.server_public_key = serialization.load_pem_public_key(
                    key_file.read()
                )
                print(f"[INFO] Loaded server public key from {SERVER_PUBLIC_KEY_FILE}")
        except FileNotFoundError:
            print(f"[ERROR] Server public key file not found: {SERVER_PUBLIC_KEY_FILE}")
            print("[ERROR] Cannot connect securely to the server without its public key.")
            self.server_public_key = None
            self.running = False  # Stop node if server key is missing
        except Exception as e:
            print(f"[ERROR] Failed to load server public key: {e}")
            self.server_public_key = None
            self.running = False

    # --- Heartbeat ---
    def start_heartbeat_thread(self):
        """Starts the heartbeat thread if not already running and logged in."""
        if not self.session_token:
            print("[INFO] Cannot start heartbeat: Not logged in.")
            return
        if self.heartbeat_thread is None or not self.heartbeat_thread.is_alive():
            self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            self.heartbeat_thread.start()
            print("[INFO] Heartbeat thread started.")
        else:
            print("[INFO] Heartbeat thread already running.")

    def _heartbeat_loop(self):
        """Periodically sends heartbeat messages to the discovery server."""
        while self.running and self.session_token:
            current_token = self.session_token  # Capture token at start of loop iteration
            if not current_token:  # Check if logged out during sleep
                break

            sock = None  # Initialize sock
            try:
                # Create a new SecureSocket for each heartbeat
                sock = SecureSocket(AF_INET, SOCK_STREAM)
                if not self.server_public_key:
                    print("[ERROR] Heartbeat: Server public key not loaded. Stopping heartbeat.")
                    break
                sock.peer_rsa_public_key = self.server_public_key

                sock.settimeout(10)  # Timeout for connection and send/recv
                sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))  # Key exchange
                heartbeat_msg = f"HEARTBEAT {current_token}"
                sock.send(heartbeat_msg.encode('utf-8'))  # Send securely
                response = sock.recv(BUFFER_SIZE).decode('utf-8')  # Receive securely

                if response != 'HEARTBEAT_ACK':
                    print(f"[WARN] Heartbeat rejected or failed: {response}.")
                    # If session is invalid, clear token and stop heartbeat
                    if "Invalid session" in response:
                        print("[INFO] Session invalid according to server. Logging out locally.")
                        self.session_token = None  # Clear invalid token
                        self.username = None
                        with self.peers_lock:
                            self.peers.clear()
                        break  # Exit heartbeat loop
                    # Handle other errors? Maybe retry? For now, just log.
                # else: print("[DEBUG] Heartbeat acknowledged.")

            except (ConnectionError, socket.timeout, OSError) as e:
                print(f"[WARN] Heartbeat failed: {type(e).__name__} - {e}. Server might be down or session expired.")
                # Wait longer before retrying if connection fails
                time.sleep(HEARTBEAT_INTERVAL * 1.5)  # Wait a bit longer before next attempt
                continue  # Skip the normal sleep and retry
            except Exception as e:
                print(f"[ERROR] Unexpected error during heartbeat: {type(e).__name__} - {e}")
                time.sleep(HEARTBEAT_INTERVAL * 1.5)  # Wait longer
                continue
            finally:
                if sock:
                    sock.close()

            # Wait for the normal interval before the next heartbeat
            # Check token again before sleeping in case logged out while sending/receiving
            if self.session_token == current_token:
                time.sleep(HEARTBEAT_INTERVAL)
            else:
                print("[INFO] Logged out during heartbeat cycle. Stopping heartbeat.")
                break  # Exit if token changed (logged out)

        print("[INFO] Heartbeat loop stopped.")
        self.heartbeat_thread = None  # Mark thread as stopped

    # --- Utility Functions ---
    def list_local_shared_files(self) -> List[str]:
        """Returns a list of files in the shared directory available for sharing."""
        shared_dir = SHARED_FILES_DIR
        if not os.path.exists(shared_dir) or not os.path.isdir(shared_dir):
            print(f"[WARN] Shared directory '{shared_dir}' not found or not a directory.")
            return []

        try:
            all_files = os.listdir(shared_dir)
            # Filter out disabled files and directories
            available_files = [
                f for f in all_files
                if os.path.isfile(os.path.join(shared_dir, f)) and f not in self.disabled_files
            ]
            return available_files
        except OSError as e:
            print(f"[ERROR] Could not list shared directory {shared_dir}: {e}")
            return []

    # --- Peer Interaction ---
    def upload_file_to_peer(self, filename: str, client_sock: SecureSocket, client_ip: str):
        """Handles sending a requested file to a connected peer (securely)."""
        filepath = os.path.join(SHARED_FILES_DIR, filename)

        # 1. Check if file exists and is actually a file
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            print(f"[UPLOAD] Denied request: File not found or is directory: {filename} from {client_ip}")
            try:
                client_sock.send(b"ERROR: File not found on peer.")
            except Exception as send_e:
                print(f"[ERROR] Failed to send 'File not found' error to {client_ip}: {send_e}")
            return

        # 2. Check if file is disabled
        if filename in self.disabled_files:
            print(f"[UPLOAD] Denied request for disabled file: {filename} from {client_ip}")
            try:
                client_sock.send(b"ERROR: File is disabled for sharing by owner.")
            except Exception as send_e:
                print(f"[ERROR] Failed to send 'File disabled' error to {client_ip}: {send_e}")
            return

        # 3. Check restrictions based on the *requesting* peer's IP
        if filename in self.shared_files_restrictions:
            allowed_ips = self.shared_files_restrictions[filename]
            if client_ip not in allowed_ips:
                print(
                    f"[UPLOAD] Denied request for restricted file: {filename} from {client_ip} (Not in {allowed_ips})")
                try:
                    client_sock.send(b"ERROR: Access denied. You are not allowed to download this file.")
                except Exception as send_e:
                    print(f"[ERROR] Failed to send 'Access denied' error to {client_ip}: {send_e}")
                return

        # 4. If all checks pass, send the file
        print(f"[UPLOAD] Starting upload of '{filename}' to {client_ip}")
        try:
            # send_file_with_hash uses the provided SecureSocket's send method
            # It should handle sending the initial "SENDING <filesize>" message
            success = send_file_with_hash(client_sock, filepath)
            if success:
                print(f"[UPLOAD] Successfully uploaded '{filename}' to {client_ip}")
            else:
                # Error message likely sent within send_file_with_hash
                print(f"[UPLOAD] Failed to complete upload of '{filename}' to {client_ip} (Check file_utils logs)")
        except (ConnectionError, OSError) as e:
            print(f"[ERROR] Connection error during upload of {filename} to {client_ip}: {e}")


    def download_file_from_peer(self, target_username: str, filename: str):
        """Initiates a download of a file from a specific peer."""
        if not self.session_token:
            print("[ERROR] Cannot download: Not logged in.")
            return
        if not self.username:
            print("[ERROR] Cannot download: Username not set (Internal error).")
            return

        with self.peers_lock:
            peer_info = self.peers.get(target_username)

        if not peer_info:
            print(f"[DOWNLOAD] Error: Peer '{target_username}' not found in known peers list.")
            print("[DOWNLOAD] Try running 'updatepeers' command to refresh.")
            return

        peer_ip, peer_port, peer_public_key_pem_str = peer_info
        if not peer_public_key_pem_str:
            print(f"[DOWNLOAD] Error: Cannot connect securely to peer '{target_username}': Missing public key.")
            return

        print(f"[DOWNLOAD] Attempting to download '{filename}' from {target_username} ({peer_ip}:{peer_port})")

        sock = None  # Initialize sock to None
        try:
            # 1. Connect securely to the peer
            sock = SecureSocket(AF_INET, SOCK_STREAM)
            # Load the target peer's public key (must be bytes)
            try:
                peer_public_key_bytes = peer_public_key_pem_str.encode('utf-8')
                sock.load_rsa_public_key_from_pem_bytes(peer_public_key_bytes)
            except Exception as key_load_e:
                print(f"[ERROR] Failed to load peer '{target_username}' public key: {key_load_e}")
                return  # Cannot connect without valid key

            sock.settimeout(15)  # Timeout for connection and download
            sock.connect((peer_ip, peer_port))  # Key exchange happens here
            print(f"[DOWNLOAD] Secure connection established with {target_username}.")

            # 2. Send the download request
            # Format: DOWNLOAD <filename> <requester_username> <requester_session_token_for_auth_proof>
            # Note: Sending the session token here is a weak proof. A challenge-response might be better.
            command = f"DOWNLOAD {filename} {self.username} {self.session_token}"
            sock.send(command.encode("utf-8"))  # Send securely
            print(f"[DOWNLOAD] Sent download request for '{filename}' to {target_username}.")

            # 3. Receive response (file size or error) - handled by receive_file_with_hash
            # receive_file_with_hash expects the peer to send "SENDING <filesize>" or "ERROR..."
            print(f"[DOWNLOAD] Waiting for file transfer initiation from {target_username}...")
            received_ok = receive_file_with_hash(sock, filename)  # Pass -1 filesize, expect peer to send it

            if received_ok:
                print(
                    f"[SUCCESS] Downloaded '{filename}' from {target_username} successfully. File saved in '{DOWNLOAD_DIR}'.")
            else:
                # Error message should have been printed by receive_file_with_hash
                print(f"[ERROR] Failed to download '{filename}' from {target_username}. Check previous logs.")
                # Optional: Clean up potentially incomplete file
                filepath = os.path.join(DOWNLOAD_DIR, filename)
                if os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                        print(f"[INFO] Removed potentially incomplete/corrupt file: {filepath}")
                    except OSError as rm_e:
                        print(f"[WARN] Could not remove incomplete file {filepath}: {rm_e}")

        except (ConnectionError, socket.timeout, OSError) as e:
            print(f"[ERROR] Connection error during download from {target_username}: {type(e).__name__} - {e}")
        except ValueError as ve:
            # Catch errors from loading keys or parsing responses
            print(f"[ERROR] Value error during download from {target_username}: {ve}")
        except Exception as e:
            print(f"[ERROR] Unexpected error downloading file from {target_username}: {type(e).__name__} - {e}")
        finally:
            if sock:
                print(f"[DOWNLOAD] Closing connection with {target_username}.")
                sock.close()

    # --- Discovery Server Communication ---
    def _send_discovery_request(self, request_msg: str, expect_response=True) -> Optional[str]:
        """Sends a request to the discovery server using SecureSocket. Returns response string or None."""
        if not self.server_public_key:
            print("[ERROR] Cannot communicate with discovery server: Server public key not loaded.")
            return None

        response_data = None
        sock = None  # Initialize sock to None
        try:
            print(f"Sending msg {request_msg}")
            sock = SecureSocket(AF_INET, SOCK_STREAM)
            sock.peer_rsa_public_key = self.server_public_key  # Load server key for connection
            sock.settimeout(10)  # Timeout for connection and request
            # print(f"[DISCOVERY] Connecting securely to {DISCOVERY_SERVER_IP}:{DISCOVERY_SERVER_PORT}")
            sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))  # Key exchange
            # print(f"[DISCOVERY] Sending request: {request_msg}")
            sock.send(request_msg.encode("utf-8"))  # Send securely

            if expect_response:
                # Use a loop to potentially receive larger responses (like LIST)
                full_response_bytes = b""
                while True:
                    try:
                        # Set a shorter timeout for subsequent recv calls within the loop
                        # sock.settimeout(2.0) # Optional: shorter timeout after first chunk
                        chunk = sock.recv(BUFFER_SIZE)  # Use secure recv
                        if not chunk:
                            break  # Connection closed by server
                        full_response_bytes += chunk
                        # Heuristic: If the chunk is smaller than buffer size, assume it's the last one.
                        # This isn't foolproof but works for many cases. A better approach would
                        # be a length prefix from the server, but we adapt to the current server impl.
                        if len(chunk) < BUFFER_SIZE:
                            break
                    except socket.timeout:
                        # Timeout waiting for more data, assume complete response received
                        print("[DEBUG] Timeout waiting for more data from server, assuming response complete.")
                        break
                    except Exception as recv_e:
                        print(f"[ERROR] Error receiving data from server: {recv_e}")
                        raise  # Re-raise to be caught by outer handler

                response_data = full_response_bytes.decode("utf-8").strip()
                # print(f"[DISCOVERY] Received response: {response_data[:200]}...") # Log truncated response

                if response_data.startswith("ERROR"):
                    print(f"[DISCOVERY SERVER ERROR] {response_data}")
                    # Check for session errors specifically
                    if "Invalid session ID" in response_data:
                        print("[INFO] Session expired or invalid according to server. Logging out locally.")
                        self.session_token = None  # Clear invalid token
                        self.username = None
                        with self.peers_lock:
                            self.peers.clear()
                        # Stop heartbeat if running
                        # (Heartbeat loop should stop itself when token becomes None)
                    return None  # Return None on server error
            return response_data

        except (ConnectionError, socket.timeout, OSError, ValueError) as e:
            # Catch connection errors, timeouts, OS errors, or key loading errors (ValueError from SecureSocket)
            print(f"[ERROR] Failed to communicate with discovery server: {type(e).__name__} - {e}")
            return None
        except Exception as e:
            print(f"[ERROR] Unexpected error communicating with discovery server: {type(e).__name__} - {e}")
            return None
        finally:
            if sock:
                sock.close()

    def update_peer_list_from_server(self):
        """Queries server for active peers and updates local list."""
        if not self.session_token:
            print("[INFO] Cannot update peer list: Not logged in.")
            return False

        print("[INFO] Requesting peer list from discovery server...")
        request_msg = f"LIST {self.session_token}"
        data = self._send_discovery_request(request_msg)

        if data is None:
            print("[ERROR] Failed to get peer list from server.")
            return False  # Indicate failure
        if data == "NO_PEERS_FOUND":
            print("[INFO] No other active peers found.")
            with self.peers_lock:
                self.peers.clear()  # Clear local list if server says none are active
            return True  # Operation succeeded, just no peers

        # Parse response format: username@ip:port|file1,file2|base64_key_pem;...
        new_peers: Dict[str, Tuple[str, int, Optional[str]]] = {}
        parse_errors = 0
        entries = data.split(";")
        print(f"[INFO] Received {len(entries)} peer entries from server.")

        for entry in entries:
            if not entry.strip(): continue  # Skip empty entries
            try:
                parts = entry.split("|")
                if len(parts) != 3:
                    print(f"[WARN] Skipping malformed peer entry (Wrong parts): '{entry}'")
                    parse_errors += 1
                    continue

                peer_info, files_str, b64_key_pem = parts
                # Use rsplit for safety in case username contains '@'
                user_part, addr_part = peer_info.rsplit("@", 1)
                # Use rsplit for safety in case IP is IPv6 containing ':'
                ip, port_str = addr_part.rsplit(":", 1)
                port = int(port_str)

                # Decode public key (Base64 -> bytes -> UTF-8 string)
                public_key_pem_str = None
                if b64_key_pem and b64_key_pem not in ["NO_KEY", "KEY_ENCODE_ERROR"]:
                    try:
                        public_key_pem_bytes = base64.b64decode(b64_key_pem)
                        public_key_pem_str = public_key_pem_bytes.decode('utf-8')  # Store as string
                    except Exception as decode_e:
                        print(f"[WARN] Failed to decode public key for peer {user_part}: {decode_e}")
                        # Store None if key is invalid/missing
                elif b64_key_pem == "NO_KEY":
                    # print(f"[DEBUG] Peer {user_part} has no public key registered.")
                    pass
                elif b64_key_pem == "KEY_ENCODE_ERROR":
                    print(f"[WARN] Server reported key encoding error for peer {user_part}.")

                # Don't add self to the peer list
                # Compare username, and also IP/Port if available
                if user_part == self.username:
                    # print(f"[DEBUG] Skipping self in peer list: {user_part}")
                    continue

                new_peers[user_part] = (ip, port, public_key_pem_str)  # Store PEM as string
                # Files are not stored locally in this version, but could be added if needed
                # files = files_str.split(",") if files_str else []

            except (ValueError, IndexError, TypeError) as e:
                print(f"[WARN] Skipping invalid peer entry format: '{entry}' ({type(e).__name__}: {e})")
                parse_errors += 1
            except Exception as e:
                print(f"[ERROR] Unexpected error parsing peer entry '{entry}': {type(e).__name__} - {e}")
                parse_errors += 1

        # Update local peer list atomically
        with self.peers_lock:
            self.peers = new_peers
        print(f"[INFO] Updated local peer list. Found {len(new_peers)} other peers.")
        if parse_errors > 0:
            print(f"[WARN] Encountered {parse_errors} errors parsing peer list entries.")
        return True

    def search_file_discovery(self, filename: str) -> List[Tuple[str, int]]:
        """Search for peers holding a specific file via the discovery server. Returns list of (ip, port)."""
        if not self.session_token:
            print("[ERROR] Cannot search: Not logged in.")
            return []

        print(f"[SEARCH] Searching for file '{filename}' via discovery server...")
        search_msg = f"SEARCH {self.session_token} {filename}"
        response = self._send_discovery_request(search_msg)

        if response is None:
            print(f"[SEARCH] Error occurred during search for '{filename}'.")
            return []
        if response == "NOT_FOUND":
            print(f"[SEARCH] File '{filename}' not found on any active peer.")
            return []

        # Response format: ip:port,ip:port,...
        peer_locations = []
        try:
            peer_strings = response.split(",")
            for peer_str in peer_strings:
                if ':' in peer_str:
                    # Use rsplit for safety with IPv6
                    ip, port_str = peer_str.rsplit(":", 1)
                    try:
                        port = int(port_str)
                        peer_locations.append((ip, port))
                    except ValueError:
                        print(f"[WARN] Invalid port in SEARCH response item: {peer_str}")
            print(f"[SEARCH] Found file '{filename}' at: {peer_locations}")
            return peer_locations
        except Exception as e:
            print(f"[ERROR] Failed to parse SEARCH response: '{response}' ({type(e).__name__} - {e})")
            return []

    # --- Server Functions (Accepting Peer Connections) ---
    def start_server(self):
        """Binds the listening socket and starts the peer acceptance thread."""
        if not self.running:
            print("[INFO] Node is not running, skipping server start.")
            return

        try:
            # Bind to the specified host and port
            self.peer_listening_socket.bind((self.host, self.port))
            self.peer_listening_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            self.peer_listening_socket.listen(5)
            actual_port = self.peer_listening_socket.getsockname()[1]  # Get actual bound port if 0 was used
            print(
                f"[INFO] Node listening for secure peer connections on {self.host}:{actual_port} (Reported as {self.listen_ip}:{self.port})")
            self.server_thread = threading.Thread(target=self._accept_peers_loop, daemon=True)
            self.server_thread.start()
        except OSError as e:
            print(f"[ERROR] Could not start node listening server on {self.host}:{self.port}: {e}")
            print("[ERROR] Port might be in use or permission denied.")
            self.running = False  # Stop node if binding fails
            try:
                self.peer_listening_socket.close()
            except Exception:
                pass  # Ignore errors closing socket that failed to bind
        except Exception as e:
            print(f"[ERROR] Unexpected error starting node listening server: {e}")
            self.running = False

    def _accept_peers_loop(self):
        """Loop to accept incoming peer connections using SecureSocket."""
        print("[INFO] Peer acceptance thread started.")
        while self.running:
            client_sock = None  # Initialize
            client_addr = None
            try:
                # SecureSocket.accept handles the key exchange automatically
                # It uses the self.node_private_key loaded into self.peer_listening_socket
                client_sock, client_addr = self.peer_listening_socket.accept()
                print(f"[ACCEPT] Accepted secure connection from peer {client_addr}")
                # Handle the connected client in a new thread
                handler_thread = threading.Thread(target=self.handle_peer_client,
                                                  args=(client_sock, client_addr),
                                                  daemon=True)
                handler_thread.start()
            except ConnectionError as ce:
                # Catch key exchange failures or other connection issues during accept/handshake
                print(
                    f"[WARN] Connection error accepting peer connection from {client_addr if client_addr else 'unknown'}: {ce}")
                if client_sock:
                    client_sock.close()  # Ensure socket is closed on error
            except OSError as e:
                if self.running:  # Only log error if we are supposed to be running
                    print(f"[ERROR] Error accepting peer connection (OSError): {e}")
                # If socket is closed intentionally (self.running is False), OSError is expected
                break  # Exit loop if socket is closed or error occurs
            except Exception as e:
                if self.running:
                    print(f"[ERROR] Unexpected error in accept loop: {type(e).__name__} - {e}")
                if client_sock:
                    client_sock.close()
                time.sleep(0.1)  # Small delay before retrying

        print("[INFO] Peer acceptance thread stopped.")
        # Socket is closed in shutdown() method

    def handle_peer_client(self, client_sock: SecureSocket, client_addr: Tuple[str, int]):
        """
        Handles commands from a connected peer over an already secure channel.
        """
        client_ip, client_port = client_addr
        print(f"[HANDLE PEER] Handling connection from {client_ip}:{client_port}")
        try:
            # Key exchange is already done by accept()
            # Receive the first command securely
            request_bytes = client_sock.recv(BUFFER_SIZE)
            if not request_bytes:
                print(f"[HANDLE PEER] No data received from {client_addr}. Closing.")
                return

            request = request_bytes.decode("utf-8").strip()
            print(f"[HANDLE PEER] Received command from {client_addr}: {request[:100]}...")
            tokens = request.split()
            if not tokens:
                print(f"[HANDLE PEER] Empty command from {client_addr}. Closing.")
                return

            command = tokens[0].upper()

            # --- Peer Command Processing ---
            if command == "DOWNLOAD" and len(tokens) >= 3:  # Min: DOWNLOAD <filename> <requester_user> [<token>]
                # Format: DOWNLOAD <filename> <requester_username> [<requester_session_token>]
                filename = tokens[1]
                requester_username = tokens[2]
                # Token might not be sent by all clients, handle optional presence
                # requester_token = tokens[3] if len(tokens) >= 4 else None

                print(
                    f"[HANDLE PEER] Received DOWNLOAD request for '{filename}' from user '{requester_username}' ({client_addr})")

                # Security Check (Optional but Recommended):
                # Verify the requester IP matches the known IP for that username, if available.
                # This is a basic check against spoofing.
                with self.peers_lock:
                    known_peer_info = self.peers.get(requester_username)

                if known_peer_info:
                    known_ip, _, _ = known_peer_info
                    if known_ip != client_ip:
                        print(
                            f"[AUTH] Download Warning: Requester IP {client_ip} does not match known IP {known_ip} for user '{requester_username}'. Allowing for now.")
                        # Decide whether to deny or just warn. Allowing might be necessary for NAT scenarios.
                        # client_sock.send(b"ERROR: Peer authentication failed (IP mismatch).")
                        # return
                else:
                    # If peer isn't known (e.g., lists are out of sync), maybe allow anyway? Or deny?
                    print(
                        f"[AUTH] Download Warning: Requester '{requester_username}' is not in the current local peer list.")
                    # client_sock.send(b"ERROR: Peer authentication failed (Unknown peer).")
                    # return

                # Proceed to upload (which includes its own checks for disabled/restricted files)
                self.upload_file_to_peer(filename, client_sock, client_ip)

            elif command == "LIST":  # Handle LIST request from peer (optional)
                print(f"[HANDLE PEER] Received LIST request from {client_addr}")
                files = self.list_local_shared_files()
                response = ",".join(files) if files else "NO_FILES"
                client_sock.send(response.encode("utf-8"))  # Send securely

            elif command == "UPDATE":
                # Format: UPDATE <username> <ip> <port> <base64_encoded_public_key_pem>
                # This command is typically sent BY the discovery server TO this node.
                print(f"[HANDLE PEER] Received UPDATE command likely from server ({client_addr}): {request}")
                if len(tokens) == 5:
                    username, peer_ip, port_str, b64_key_pem = tokens[1], tokens[2], tokens[3], tokens[4]
                    try:
                        peer_port = int(port_str)
                        # Decode public key (Base64 -> bytes -> UTF-8 string)
                        public_key_pem_str = None
                        if b64_key_pem and b64_key_pem not in ["NO_KEY", "ERROR_ENCODING_KEY"]:
                            try:
                                public_key_pem_bytes = base64.b64decode(b64_key_pem)
                                public_key_pem_str = public_key_pem_bytes.decode('utf-8')  # Store as string
                            except Exception as decode_e:
                                print(f"[WARN] Failed to decode public key for UPDATE {username}: {decode_e}")
                        elif b64_key_pem == "NO_KEY":
                            # print(f"[DEBUG] UPDATE for {username} indicates no public key.")
                            pass
                        elif b64_key_pem == "ERROR_ENCODING_KEY":
                            print(f"[WARN] UPDATE for {username} reported key encoding error by sender.")

                        # Don't add self
                        if username != self.username:
                            print(
                                f"[PEERS] Updating local entry via UPDATE command: {username} -> {peer_ip}:{peer_port} (Key: {'Yes' if public_key_pem_str else 'No'})")
                            with self.peers_lock:
                                self.peers[username] = (peer_ip, peer_port, public_key_pem_str)  # Store PEM as string
                        # else: print("[DEBUG] Received self-update via UPDATE command, ignoring.")

                    except ValueError:
                        print(f"[WARN] Invalid port in UPDATE command: {request}")
                    except Exception as e:
                        print(f"[ERROR] Error processing UPDATE command: {type(e).__name__} - {e}")
                else:
                    print(f"[WARN] Malformed UPDATE command received: {request}")
                # No response needed for UPDATE command
                return  # Close connection after processing update

            else:
                print(f"[HANDLE PEER] Received unknown command from {client_addr}: {command}")
                client_sock.send(b"ERROR: Unknown command")

        except (ConnectionError, ConnectionResetError, socket.timeout) as conn_e:
            print(f"[ERROR] Connection error handling peer {client_addr}: {type(conn_e).__name__} - {conn_e}")
        except Exception as e:
            print(f"[ERROR] Unexpected error handling peer {client_addr}: {type(e).__name__} - {e}")
            # Attempt to send error back if possible
            try:
                client_sock.send(b"ERROR: Internal node error.")
            except Exception:
                pass
        finally:
            print(f"[HANDLE PEER] Closing connection with {client_addr}")
            client_sock.close()

    # --- File Sharing Settings ---
    def disable_file(self, filename: str):
        """Mark a file as disabled for sharing."""
        # Check if file actually exists in shared dir for user feedback
        filepath = os.path.join(SHARED_FILES_DIR, filename)
        if os.path.exists(filepath) and os.path.isfile(filepath):
            self.disabled_files.add(filename)
            print(f"[CONFIG] Disabled file for sharing: {filename}")
            return True
        else:
            print(f"[CONFIG] Cannot disable file (Not found or is directory): {filename}")
            # Also add to disabled list even if not found? Prevents sharing if added later.
            # self.disabled_files.add(filename)
            return False

    def enable_file(self, filename: str) -> bool:
        """Re-enable a previously disabled file for sharing."""
        if filename in self.disabled_files:
            self.disabled_files.remove(filename)
            print(f"[CONFIG] Enabled file for sharing: {filename}")
            return True
        else:
            # Check if file exists to give better feedback
            filepath = os.path.join(SHARED_FILES_DIR, filename)
            if os.path.exists(filepath) and os.path.isfile(filepath):
                print(f"[CONFIG] File is already enabled (or was never disabled): {filename}")
            else:
                print(f"[CONFIG] File not found in shared directory: {filename}")
            return False

    def restrict_file(self, filename: str, allowed_ips: List[str]):
        """Restrict file download access to specific IP addresses."""
        filepath = os.path.join(SHARED_FILES_DIR, filename)
        if os.path.exists(filepath) and os.path.isfile(filepath):
            # Validate IPs? Basic check for now.
            valid_ips = set(ip for ip in allowed_ips if ip)  # Remove empty strings
            if not valid_ips:
                print("[CONFIG] Restriction failed: No valid IP addresses provided.")
                return False
            self.shared_files_restrictions[filename] = valid_ips
            print(f"[CONFIG] Restricted file '{filename}' to IPs: {valid_ips}")
            return True
        else:
            print(f"[CONFIG] Cannot restrict file (Not found or is directory): {filename}")
            return False

    def unrestrict_file(self, filename: str) -> bool:
        """Remove download restrictions for a file."""
        if filename in self.shared_files_restrictions:
            del self.shared_files_restrictions[filename]
            print(f"[CONFIG] Unrestricted file: {filename}")
            return True
        else:
            print(f"[CONFIG] File is not currently restricted: {filename}")
            return False

    # --- User Actions (Registration, Login, Logout) ---
    def register_user(self, username, password) -> bool:
        """Registers the user with the discovery server."""
        if not self.node_public_key_pem or not self.server_public_key:
            print("[ERROR] Cannot register: Node or Server keys missing.")
            return False
        if self.session_token:
            print("[WARN] Already logged in. Please logout first to register.")
            return False
        if not self.listen_ip:
            print("[ERROR] Cannot register: Listen IP address not determined.")
            return False

        print(f"[REGISTER] Attempting to register username '{username}'...")
        sock = None
        try:
            sock = SecureSocket(AF_INET, SOCK_STREAM)
            sock.peer_rsa_public_key = self.server_public_key
            sock.settimeout(15)
            sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))  # Secure connect

            files = self.list_local_shared_files()
            file_list_str = ",".join(files)
            # Send the IP and Port that other peers should use to connect to this node
            register_msg = f"REGISTER {username} {password} {self.listen_ip} {self.port} {file_list_str}"
            sock.send(register_msg.encode("utf-8"))  # Send register command

            # Wait for REGISTER_ACK response before sending pubkey
            response = sock.recv(BUFFER_SIZE).decode("utf-8").strip()

            if response == "REGISTER_ACK":
                print("[REGISTER] Step 1/2 successful (ACK received). Sending public key...")
                # Step 2: Send public key
                if not self.node_public_key_pem:
                    print("[ERROR] Cannot send public key: Node public key missing.")
                    # Should we try to tell the server? Difficult state. Close connection.
                    return False

                b64_pem = base64.b64encode(self.node_public_key_pem).decode('utf-8')
                pubkey_msg = f"PUBKEY {b64_pem}"
                sock.send(pubkey_msg.encode('utf-8'))
                print("[REGISTER] Sent public key.")

                # Step 3: Wait for final REGISTERED <token> response
                final_response = sock.recv(BUFFER_SIZE).decode("utf-8").strip()
                if final_response.startswith("REGISTERED "):
                    self.session_token = final_response.split(" ", 1)[1]
                    self.username = username
                    print(f"[SUCCESS] User '{username}' registered successfully.")
                    print(f"[INFO] Session token: {self.session_token}")
                    # self.start_heartbeat_thread()  # Start heartbeat after successful registration
                    self.update_peer_list_from_server()  # Get initial peer list
                    return True
                else:
                    print(f"[ERROR] Registration failed after sending key: Server response: {final_response}")
                    self.session_token = None
                    return False
            else:
                # Initial REGISTER command failed
                print(f"[ERROR] Registration failed: Server response: {response}")
                self.session_token = None
                return False

        except (ConnectionError, socket.timeout, OSError, ValueError) as e:
            print(f"[ERROR] Failed to register with discovery server: {type(e).__name__} - {e}")
            return False
        except Exception as e:
            print(f"[ERROR] Unexpected error during registration: {type(e).__name__} - {e}")
            return False
        finally:
            if sock:
                sock.close()

    def login_user(self, username, password) -> bool:
        """Logs the user into the discovery server."""
        if not self.server_public_key:
            print("[ERROR] Cannot login: Server public key missing.")
            return False
        if self.session_token:
            print("[WARN] Already logged in. Please logout first.")
            return False

        print(f"[LOGIN] Attempting to login as '{username}'...")
        sock = None
        try:
            sock = SecureSocket(AF_INET, SOCK_STREAM)
            sock.peer_rsa_public_key = self.server_public_key
            sock.settimeout(15)
            sock.connect((DISCOVERY_SERVER_IP, DISCOVERY_SERVER_PORT))  # Secure connect

            login_msg = f"LOGIN {username} {password}"
            sock.send(login_msg.encode("utf-8"))  # Send login command

            response = sock.recv(BUFFER_SIZE).decode("utf-8").strip()

            if response.startswith("LOGGED_IN"):
                parts = response.split()
                # Format: LOGGED_IN <token> <ip:port> <files>
                if len(parts) >= 3:  # Need at least LOGGED_IN, token, ip:port
                    self.session_token = parts[1]
                    self.username = username
                    # Optional: Update self.listen_ip/self.port based on server response?
                    # server_ip_port = parts[2]
                    # server_files = parts[3] if len(parts) >= 4 else ""
                    print(f"[SUCCESS] User '{username}' logged in successfully.")
                    print(f"[INFO] Session token: {self.session_token}")
                    # self.start_heartbeat_thread()  # Start heartbeat after successful login
                    self.update_peer_list_from_server()  # Get initial peer list
                    return True
                else:
                    print("[ERROR] Login failed: Malformed LOGGED_IN response from server.")
                    self.session_token = None
                    return False
            else:
                print(f"[ERROR] Login failed: Server response: {response}")
                self.session_token = None
                return False

        except (ConnectionError, socket.timeout, OSError, ValueError) as e:
            print(f"[ERROR] Failed to login with discovery server: {type(e).__name__} - {e}")
            return False
        except Exception as e:
            print(f"[ERROR] Unexpected error during login: {type(e).__name__} - {e}")
            return False
        finally:
            if sock:
                sock.close()

    def logout_user(self) -> bool:
        """Logs the user out from the discovery server."""
        if not self.session_token:
            print("[INFO] Not currently logged in.")
            return False

        print("[LOGOUT] Logging out...")
        # Stop heartbeat thread *before* sending logout to server
        # Set token to None first to signal heartbeat loop to stop
        current_token = self.session_token
        self.session_token = None
        self.username = None  # Clear username as well
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            print("[LOGOUT] Stopping heartbeat thread...")
            # No need to join, it's a daemon thread and will exit when loop condition fails
            # self.heartbeat_thread.join(timeout=1.0) # Optional wait
            pass  # Daemon thread will exit

        # Clear local peer list
        with self.peers_lock:
            self.peers.clear()

        # Send logout message to server
        logout_msg = f"LOGOUT {current_token}"
        response = self._send_discovery_request(logout_msg, expect_response=True)  # Expect LOGGED_OUT

        if response == "LOGGED_OUT":
            print("[SUCCESS] Successfully logged out from server.")
            return True
        elif response is None:
            print("[WARN] Logout failed: No response or connection error sending logout message.")
            # Already logged out locally, treat as success from user perspective
            return True
        else:
            # Server might return an error like "Invalid session ID" if already expired
            print(f"[WARN] Logout may have failed server-side: Server response: {response}")
            # Already logged out locally, treat as success from user perspective
            return True

    def shutdown(self):
        """Gracefully shuts down the node."""
        if not self.running:
            print("[INFO] Shutdown already in progress or completed.")
            return

        print("[SHUTDOWN] Initiating node shutdown...")
        self.running = False  # Signal loops to stop

        # Logout if logged in (this also stops heartbeat and clears peers)
        if self.session_token:
            self.logout_user()
        # Ensure heartbeat thread is stopped even if not logged in recently
        elif self.heartbeat_thread and self.heartbeat_thread.is_alive():
            # Heartbeat should stop due to self.running = False
            print("[SHUTDOWN] Waiting for heartbeat thread to stop...")
            self.heartbeat_thread.join(timeout=1.0)  # Brief wait

        # Close the listening socket to stop the accept loop
        try:
            print("[SHUTDOWN] Closing listening socket...")
            # Create a dummy connection to unblock accept() if it's waiting
            # This is a common technique but can be platform-dependent
            try:
                # Use the determined listen_ip or fallback
                connect_ip = self.listen_ip if self.listen_ip and not self.listen_ip.startswith("0.") else "127.0.0.1"
                dummy_socket = socket.socket(AF_INET, SOCK_STREAM)
                dummy_socket.settimeout(0.1)
                dummy_socket.connect((connect_ip, self.port))
                dummy_socket.close()
                print("[DEBUG] Sent dummy connection to unblock accept().")
            except Exception as dummy_e:
                # Ignore errors trying to connect to self, accept might not be blocked
                print(f"[DEBUG] Dummy connection failed (Accept might not be blocked): {dummy_e}")
                pass
            # Now close the actual listening socket
            self.peer_listening_socket.close()
        except Exception as e:
            print(f"[WARN] Error closing listening socket during shutdown: {e}")

        # Wait for server thread (accept loop) to finish
        if self.server_thread and self.server_thread.is_alive():
            print("[SHUTDOWN] Waiting for server thread to stop...")
            self.server_thread.join(timeout=2.0)
            if self.server_thread.is_alive():
                print("[WARN] Server thread did not stop gracefully.")

        print("[SHUTDOWN] Node shutdown complete.")
