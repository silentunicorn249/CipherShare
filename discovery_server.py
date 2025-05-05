#!/usr/bin/env python3
import base64
import socket
import threading
import time
import uuid
from typing import Dict, Tuple

# Cryptography imports for RSA key handling
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from tinydb import Query, TinyDB

# Import SecureSocket and constants
from SecureSocket import SecureSocket  # Use SecureSocket
# Assume constants.py defines:
# SERVER_HOST, SERVER_PORT, BUFFER_SIZE, HEARTBEAT_INTERVAL,
# SERVER_PRIVATE_KEY_FILE, SERVER_PUBLIC_KEY_FILE,
# PUBLIC_EXPONENT, KEY_SIZE
from constants import *
from enc_utils import verify_password, hash_password

# --- Global Variables ---
sessions: Dict[str, Dict] = {}  # token -> user info {username, ip, port, public_key_pem}
active_peers: Dict[
    Tuple[str, int], Dict] = {}  # (ip, port) -> { last_heartbeat, username, files, public_key_pem, ip, port }
active_peers_lock = threading.Lock()
peer_registry_store = TinyDB('peer_registry.json')
# In-memory cache of the registry for faster lookups
peer_registry_data: Dict[
    Tuple[str, int], Dict] = {}  # (ip, port) -> {username, password_hash, ip, port, files, last_seen, public_key_pem}
registry_lock = threading.Lock()

# Load/Generate Server RSA Keys
server_private_key: rsa.RSAPrivateKey | None = None
server_public_key_pem: bytes | None = None


def load_or_generate_server_keys():
    """Loads server RSA keys or generates them if they don't exist."""
    global server_private_key, server_public_key_pem
    try:
        # Try loading private key
        with open(SERVER_PRIVATE_KEY_FILE, "rb") as key_file:
            print(f"[INFO] Loading server private key from {SERVER_PRIVATE_KEY_FILE}")
            server_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None  # No password for simplicity
            )
        # Try loading public key
        with open(SERVER_PUBLIC_KEY_FILE, "rb") as key_file:
            print(f"[INFO] Loading server public key from {SERVER_PUBLIC_KEY_FILE}")
            # We store PEM for easy distribution
            server_public_key_pem = key_file.read()

    except FileNotFoundError:
        print("[WARN] Server key files not found. Generating new keys...")
        server_private_key = rsa.generate_private_key(
            public_exponent=PUBLIC_EXPONENT,
            key_size=KEY_SIZE
        )
        public_key = server_private_key.public_key()

        # Save private key
        pem_private = server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # No password for simplicity
        )
        with open(SERVER_PRIVATE_KEY_FILE, "wb") as key_file:
            key_file.write(pem_private)
        print(f"[INFO] Saved new server private key to {SERVER_PRIVATE_KEY_FILE}")

        # Save public key
        server_public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(SERVER_PUBLIC_KEY_FILE, "wb") as key_file:
            key_file.write(server_public_key_pem)
        print(f"[INFO] Saved new server public key to {SERVER_PUBLIC_KEY_FILE}")

    except Exception as e:
        print(f"[ERROR] Failed to load or generate server keys: {e}")
        exit(1)  # Cannot run without keys

    if not server_private_key or not server_public_key_pem:
        print("[ERROR] Server keys could not be initialized.")
        exit(1)


# --- Database/Cache Interface ---
def registry_interface(operation, filters=None, data=None):
    """
    Shared interface to database (TinyDB) and in-memory cache (peer_registry_data).
    Handles loading, reading, inserting, updating, and deleting peer registration info.
    Includes 'public_key_pem'.
    """
    filters = filters or {}
    with registry_lock:
        if operation == 'load':
            entries = peer_registry_store.all()
            peer_registry_data.clear()
            for e in entries:
                # Ensure public_key_pem exists, default to None if missing from old entries
                e.setdefault('public_key_pem', None)
                # Use (ip, port) as the key for the in-memory cache
                key = (e.get('ip'), e.get('port'))
                if key[0] is not None and key[1] is not None:
                    peer_registry_data[key] = e
                else:
                    print(f"[WARN] Skipping registry entry with missing IP/Port: {e.get('username')}")
            print(f"[INFO] Loaded {len(peer_registry_data)} entries from registry into cache.")
            return list(peer_registry_data.values())

        elif operation == 'read':
            results = []
            # Read from the in-memory cache
            for entry in peer_registry_data.values():
                match = True
                for k, v in filters.items():
                    if entry.get(k) != v:
                        match = False
                        break
                if match:
                    results.append(entry.copy())  # Return copies
            return results

        elif operation == 'insert':
            if not data or 'ip' not in data or 'port' not in data:
                print("[ERROR] Registry insert failed: Missing data or IP/Port.")
                return None
            key = (data['ip'], data['port'])
            if key in peer_registry_data:
                print(
                    f"[WARN] Attempted to insert duplicate registry entry for {data['ip']}:{data['port']}. Handling as update.")
                # Treat as update if exists
                return registry_interface('update', filters={'ip': data['ip'], 'port': data['port']}, data=data)

            # Ensure public_key_pem field exists
            data.setdefault('public_key_pem', None)
            # Insert into TinyDB
            try:
                peer_registry_store.insert(data)
            except Exception as e:
                print(f"[ERROR] Failed to insert into TinyDB: {e}")
                return None  # Indicate failure

            # Insert into cache
            peer_registry_data[key] = data.copy()
            print(f"[INFO] Inserted new registry entry for {data.get('username', 'N/A')}")
            return data

        elif operation == 'update':
            if not filters:
                print("[WARN] Registry update called without filters. Aborting.")
                return None
            if not data:
                print("[WARN] Registry update called without data. Aborting.")
                return None

            updated_keys = []
            # Update TinyDB
            q = Query()
            query_expr = None
            conditions = [(q[k] == v) for k, v in filters.items()]
            if conditions:
                query_expr = conditions[0]
                for cond in conditions[1:]:
                    query_expr &= cond

            if query_expr:
                try:
                    num_updated_db = peer_registry_store.update(data, query_expr)
                    # print(f"[DEBUG] TinyDB updated {num_updated_db} entries.")
                except Exception as e:
                    print(f"[ERROR] Failed to update TinyDB: {e}")
                    # Continue to update cache if possible, but log DB error

            # Update cache
            cache_update_count = 0
            # Iterate over keys found by filter in the cache
            keys_to_update_in_cache = [
                k for k, entry in peer_registry_data.items()
                if all(entry.get(fk) == fv for fk, fv in filters.items())
            ]

            for key in keys_to_update_in_cache:
                if key in peer_registry_data:
                    peer_registry_data[key].update(data)
                    updated_keys.append(key)
                    cache_update_count += 1

            if cache_update_count > 0:
                print(f"[INFO] Updated {cache_update_count} registry cache entries matching filters.")
            else:
                # If filter didn't match cache, maybe entry needs inserting?
                # This can happen if cache/DB are out of sync or filter is too specific.
                # Let's check if the filter matches a potential new key based on data
                potential_key = (data.get('ip'), data.get('port'))
                if potential_key[0] and potential_key[1] and potential_key not in peer_registry_data:
                    print(
                        f"[WARN] Update filter didn't match cache, but data has IP/Port. Attempting insert/update for {potential_key}.")
                    # Try inserting/updating based on the data's IP/Port
                    return registry_interface('insert', data=data)  # Let insert handle duplicates

            return updated_keys  # Return keys of updated entries

        elif operation == 'delete':
            if not filters:
                print("[WARN] Registry delete called without filters. Aborting.")
                return None

            deleted_keys = []
            # Delete from TinyDB
            q = Query()
            query_expr = None
            conditions = [(q[k] == v) for k, v in filters.items()]
            if conditions:
                query_expr = conditions[0]
                for cond in conditions[1:]:
                    query_expr &= cond

            if query_expr:
                try:
                    num_deleted_db = peer_registry_store.remove(query_expr)
                    # print(f"[DEBUG] TinyDB removed {num_deleted_db} entries.")
                except Exception as e:
                    print(f"[ERROR] Failed to delete from TinyDB: {e}")
                    # Continue to delete from cache if possible

            # Delete from cache
            cache_delete_count = 0
            keys_to_delete_in_cache = [
                k for k, entry in peer_registry_data.items()
                if all(entry.get(fk) == fv for fk, fv in filters.items())
            ]
            for key in keys_to_delete_in_cache:
                if key in peer_registry_data:
                    del peer_registry_data[key]
                    deleted_keys.append(key)
                    cache_delete_count += 1

            if cache_delete_count > 0:
                print(f"[INFO] Deleted {cache_delete_count} registry cache entries matching filters.")
            return deleted_keys

        else:
            raise ValueError(f"Unknown registry operation: {operation}")


# --- Active Peers Management ---
def update_active_peer(username, ip, port, files=None, public_key_pem=None):
    """
    Update or add an active peer, including their public key PEM.
    Ensures the peer entry includes 'ip' and 'port'.
    """
    key = (ip, port)
    with active_peers_lock:
        now = time.time()
        if key in active_peers:
            active_peers[key]['last_heartbeat'] = now
            active_peers[key]['username'] = username  # Update username just in case
            if files is not None:
                active_peers[key]['files'] = files
            if public_key_pem is not None:
                active_peers[key]['public_key_pem'] = public_key_pem
            # Ensure ip/port are present (should be from key, but belt-and-suspenders)
            active_peers[key]['ip'] = ip
            active_peers[key]['port'] = port
            # print(f"[DEBUG] Updated active peer heartbeat: {username}@{ip}:{port}")
        else:
            active_peers[key] = {
                'username': username,
                'ip': ip,  # Explicitly add ip
                'port': port,  # Explicitly add port
                'files': files if files is not None else [],
                'public_key_pem': public_key_pem,  # Store PEM string
                'last_heartbeat': now
            }
            print(f"[INFO] Added new active peer: {username}@{ip}:{port}")
    # Return a copy to prevent modification outside the lock
    with active_peers_lock:
        return active_peers.get(key, {}).copy()


def remove_active_peer(ip, port):
    """Remove a peer from the active peers list."""
    key = (ip, port)
    with active_peers_lock:
        if key in active_peers:
            username = active_peers[key].get('username', 'unknown')
            del active_peers[key]
            print(f"[INFO] Removed active peer: {username}@{ip}:{port}")
            return True
        else:
            # print(f"[DEBUG] Attempted to remove non-existent active peer: {ip}:{port}")
            return False


def get_active_peers(exclude_self: Tuple[str, int] | None = None) -> list[Dict]:
    """Get a list of currently active peers, optionally excluding one."""
    with active_peers_lock:
        # Return copies to avoid modification issues outside the lock
        all_peers = [peer.copy() for key, peer in active_peers.items() if key != exclude_self]
    return all_peers



# --- Notification Logic (Modified for two-way notification) ---
def notify_peers_of_update(updated_peer_info: Dict):
    """
    Notifies peers about updates (login/register).
    1. Notifies all *other* active peers about the updated peer.
    2. Notifies the *updated* peer about all *other* active peers.

    Args:
        updated_peer_info: Dictionary containing info of the peer who just
                           registered/logged in ({'username', 'ip', 'port', 'public_key_pem'}).
    """
    updated_username = updated_peer_info.get('username')
    updated_ip = updated_peer_info.get('ip')
    updated_port = updated_peer_info.get('port')
    updated_pubkey_pem = updated_peer_info.get('public_key_pem')  # This is bytes or str

    if not all([updated_username, updated_ip, updated_port]):
        print("[ERROR] Cannot notify: Updated peer info is incomplete.")
        return

    print(f"[NOTIFY] Processing updates for {updated_username}@{updated_ip}:{updated_port}")

    # --- Encode the updated peer's key ONCE ---
    encoded_updated_pem = "NO_KEY"
    updated_pubkey_bytes = None
    if updated_pubkey_pem:
        try:
            # Ensure it's bytes before encoding
            if isinstance(updated_pubkey_pem, str):
                updated_pubkey_bytes = updated_pubkey_pem.encode('utf-8')
            else:
                updated_pubkey_bytes = updated_pubkey_pem  # Assume it's already bytes

            if updated_pubkey_bytes:
                encoded_updated_pem = base64.b64encode(updated_pubkey_bytes).decode('utf-8')
            else:
                print(f"[WARN] Public key PEM for {updated_username} is empty bytes.")

        except Exception as e:
            print(f"[ERROR] Failed to base64 encode public key for {updated_username}: {e}")
            encoded_updated_pem = "ERROR_ENCODING_KEY"

    # --- Message for existing peers about the new/updated peer ---
    message_to_existing = f"UPDATE {updated_username} {updated_ip} {updated_port} {encoded_updated_pem}"

    # Get a snapshot of other active peers
    current_other_peers = get_active_peers(exclude_self=(updated_ip, updated_port))
    unreachable_peers = []  # Track peers that couldn't be reached

    print(f"[NOTIFY] Notifying {len(current_other_peers)} existing peer(s) about {updated_username}.")

    # --- 1. Notify existing peers about the new/updated peer ---
    for existing_peer in current_other_peers:
        target_ip = existing_peer['ip']
        target_port = existing_peer['port']
        target_username = existing_peer['username']
        target_pubkey_pem = existing_peer.get('public_key_pem')  # This is str or None

        print(f"[NOTIFY] -> Attempting to notify {target_username}@{target_ip}:{target_port} about {updated_username}")

        if not target_pubkey_pem:
            print(f"[WARN] Cannot notify {target_username}: Missing public key.")
            continue  # Skip if we don't have their key

        target_pubkey_bytes = None
        try:
            if isinstance(target_pubkey_pem, str):
                target_pubkey_bytes = target_pubkey_pem.encode('utf-8')
            elif isinstance(target_pubkey_pem, bytes):
                target_pubkey_bytes = target_pubkey_pem
            # else: None - handled above

            if not target_pubkey_bytes:
                print(f"[WARN] Cannot notify {target_username}: Public key is empty.")
                continue

        except Exception as e:
            print(f"[ERROR] Error encoding target public key for {target_username}: {e}")
            continue

        notify_sock = None
        try:
            # Create a SecureSocket to connect to the target peer
            notify_sock = SecureSocket(socket.AF_INET, socket.SOCK_STREAM)
            notify_sock.load_rsa_public_key_from_pem_bytes(target_pubkey_bytes)  # Load target's key
            notify_sock.settimeout(5)  # Timeout for connection and exchange
            notify_sock.connect((target_ip, target_port))  # Key exchange happens here
            notify_sock.send(message_to_existing.encode('utf-8'))  # Send the update command securely
            print(f"[NOTIFY] -> Sent update TO {target_username} about {updated_username}")

        except (ConnectionRefusedError, socket.timeout, ConnectionError, OSError, ValueError) as e:
            print(
                f"[WARN] Failed to notify {target_username}@{target_ip}:{target_port} (Update TO): {type(e).__name__} - {e}")
            unreachable_peers.append((target_ip, target_port))
        except Exception as e:
            print(
                f"[ERROR] Unexpected error notifying {target_username}@{target_ip}:{target_port} (Update TO): {type(e).__name__} - {e}")
            unreachable_peers.append((target_ip, target_port))  # Mark as potentially unreachable
        finally:
            if notify_sock:
                notify_sock.close()

    # --- 2. Notify the new/updated peer about existing peers ---
    if not updated_pubkey_bytes:
        print(f"[WARN] Cannot notify {updated_username} about existing peers: Missing own public key.")
    else:
        print(
            f"[NOTIFY] Notifying {updated_username} about {len(current_other_peers) - len(unreachable_peers)} reachable existing peer(s).")
        for existing_peer in current_other_peers:
            target_ip = existing_peer['ip']
            target_port = existing_peer['port']
            target_username = existing_peer['username']
            target_pubkey_pem = existing_peer.get('public_key_pem')  # str or None

            # Skip if this peer was found unreachable in step 1
            if (target_ip, target_port) in unreachable_peers:
                print(f"[NOTIFY] <- Skipping notification to {updated_username} about unreachable {target_username}")
                continue

            print(
                f"[NOTIFY] <- Attempting to notify {updated_username} about {target_username}@{target_ip}:{target_port}")

            # Encode existing peer's key for the message
            encoded_target_pem = "NO_KEY"
            if target_pubkey_pem:
                try:
                    target_pubkey_bytes = target_pubkey_pem.encode('utf-8') if isinstance(target_pubkey_pem,
                                                                                          str) else target_pubkey_pem
                    if target_pubkey_bytes:
                        encoded_target_pem = base64.b64encode(target_pubkey_bytes).decode('utf-8')
                    else:
                        print(f"[WARN] Public key PEM for existing peer {target_username} is empty.")
                except Exception as enc_e:
                    print(f"[ERROR] Failed to base64 encode target key {target_username}: {enc_e}")
                    encoded_target_pem = "ERROR_ENCODING_KEY"

            message_to_new = f"UPDATE {target_username} {target_ip} {target_port} {encoded_target_pem}"

            notify_back_sock = None
            try:
                # Create SecureSocket to connect back to the original peer
                notify_back_sock = SecureSocket(socket.AF_INET, socket.SOCK_STREAM)
                notify_back_sock.load_rsa_public_key_from_pem_bytes(
                    updated_pubkey_bytes)  # Load the *new/updated* peer's key
                notify_back_sock.settimeout(5)
                notify_back_sock.connect((updated_ip, updated_port))  # Key exchange happens here
                notify_back_sock.send(message_to_new.encode('utf-8'))  # Send securely
                print(f"[NOTIFY] <- Sent update FROM {target_username} back TO {updated_username}")

            except (ConnectionRefusedError, socket.timeout, ConnectionError, OSError, ValueError) as e:
                print(
                    f"[WARN] Failed to notify {updated_username} about {target_username} (Update FROM): {type(e).__name__} - {e}")
                # Don't mark the *target* as unreachable here, the issue is with the *updated* peer
            except Exception as e:
                print(
                    f"[ERROR] Unexpected error notifying {updated_username} about {target_username} (Update FROM): {type(e).__name__} - {e}")
            finally:
                if notify_back_sock:
                    notify_back_sock.close()

    # --- 3. Clean up unreachable peers ---
    if unreachable_peers:
        print(f"[INFO] Cleaning up {len(unreachable_peers)} unreachable peers found during notification.")
        for ip, port in unreachable_peers:
            # Check if still active before removing, might have reconnected
            with active_peers_lock:
                if (ip, port) in active_peers:
                    # remove_active_peer handles lock internally
                    remove_active_peer(ip, port)


# --- Client Handler (Uses SecureSocket) ---
def handle_client(secure_conn: SecureSocket, addr: Tuple[str, int]):
    """Handles a single client connection using SecureSocket."""
    print(f"[HANDLE] Handling connection from {addr}")
    username = None  # Track username for logging
    session_token = None  # Track session for context
    ip, port = addr
    peer_info_for_cleanup = None  # Store peer info if login/register succeeds

    try:
        # Key exchange is already done by SecureSocket.accept() which returned secure_conn
        print(f"[HANDLE] Secure connection established with {addr}")

        # Now receive the first command over the secure channel
        raw_data = secure_conn.recv(BUFFER_SIZE)  # Use secure recv
        if not raw_data:
            print(f"[HANDLE] No initial data received from {addr}. Closing.")
            return

        request = raw_data.decode('utf-8').strip()
        print(f"[HANDLE] Received command from {addr}: {request[:100]}...")  # Log truncated command
        tokens = request.split()
        if not tokens:
            print(f"[HANDLE] Empty command from {addr}. Closing.")
            return
        cmd = tokens[0].upper()

        response = "ERROR: Unprocessed command"  # Default response

        # --- Command Processing ---
        if cmd == 'REGISTER':
            # Format: REGISTER <username> <password> <client_listen_ip> <client_listen_port> [<files>]
            # Note: client_listen_ip/port might differ from connection addr if behind NAT.
            # The server should store the ip/port provided by the client for peer-to-peer comms.
            if len(tokens) < 5:
                response = 'ERROR: Usage: REGISTER <username> <password> <your_listen_ip> <your_listen_port> [<files>]'
            else:
                username, raw_pw, peer_listen_ip, peer_listen_port_str = tokens[1], tokens[2], tokens[3], tokens[4]
                try:
                    peer_listen_port = int(peer_listen_port_str)
                    # Basic validation for IP/Port if needed
                    if peer_listen_ip != ip:
                        print(
                            f"[WARN] Registered listen IP {peer_listen_ip} differs from connection source IP {ip}. Using provided listen IP.")
                    # Use the IP/Port provided by the client for P2P
                    peer_ip = peer_listen_ip
                    peer_port = peer_listen_port

                    files = tokens[5].split(',') if len(tokens) >= 6 and tokens[5] else []
                    pwd_hash = hash_password(raw_pw)
                    print(f"Saving pass: {pwd_hash}")

                    # Check if username already exists in registry
                    if registry_interface("read", filters={"username": username}):
                        response = "ERROR: Username already registered."
                    else:
                        # Send ACK to prompt client for public key
                        print(f"[HANDLE] Sending REGISTER_ACK to {username}...")
                        secure_conn.send(b"REGISTER_ACK")

                        # Expect client to send public key next
                        print(f"[HANDLE] Waiting for public key from registering user {username}...")
                        pubkey_resp_bytes = secure_conn.recv(4096)  # Increased buffer for key
                        if not pubkey_resp_bytes:
                            print(f"[ERROR] Did not receive public key from {username} after REGISTER_ACK.")
                            response = "ERROR: Did not receive public key."
                            # No need to send again, just return
                            return

                        pubkey_resp = pubkey_resp_bytes.decode('utf-8').strip()

                        if pubkey_resp.startswith("PUBKEY "):
                            b64_pem = pubkey_resp.split(" ", 1)[1]
                            public_key_pem_str = None
                            try:
                                # Decode Base64 to get the PEM bytes, then decode bytes to string for storage
                                public_key_pem_bytes = base64.b64decode(b64_pem)
                                public_key_pem_str = public_key_pem_bytes.decode('utf-8')
                                # Optional: Validate PEM format here if needed
                                print(f"[HANDLE] Received and decoded public key from {username}")
                            except Exception as e:
                                print(f"[ERROR] Failed to decode/parse public key from {username}: {e}")
                                response = "ERROR: Invalid public key format received."
                                secure_conn.send(response.encode('utf-8'))
                                return  # Abort registration

                            # Proceed with registration
                            new_entry = {
                                'username': username,
                                'password': pwd_hash,  # Store hash, not raw password
                                'ip': peer_ip,  # Use the listen IP provided by the client
                                'port': peer_port,  # Use the listen port provided by the client
                                'files': files,
                                'last_seen': time.time(),
                                'public_key_pem': public_key_pem_str  # Store the PEM string
                            }
                            # Insert into registry (DB and cache)
                            if registry_interface('insert', data=new_entry):
                                session_token = str(uuid.uuid4())
                                peer_info_for_cleanup = {  # Store info needed for notification & cleanup
                                    'username': username,
                                    'ip': peer_ip,
                                    'port': peer_port,
                                    'public_key_pem': public_key_pem_str  # Store str here
                                }
                                sessions[session_token] = peer_info_for_cleanup.copy()  # Store session info

                                # Add to active peers
                                update_active_peer(username, peer_ip, peer_port, files, public_key_pem_str)
                                print(f"[INFO] Registered {username} @ {peer_ip}:{peer_port}")

                                # Notify others AFTER successful registration and key storage
                                # Pass the dictionary containing the PEM string
                                threading.Thread(target=notify_peers_of_update,
                                                 args=(peer_info_for_cleanup,), daemon=True).start()
                                response = f'REGISTERED {session_token}'
                            else:
                                response = "ERROR: Failed to save registration details."

                        else:
                            response = "ERROR: Expected PUBKEY after REGISTER_ACK."

                except ValueError:
                    response = 'ERROR: Invalid port number.'
                except Exception as e:
                    print(f"[ERROR] Exception during REGISTER for {username}: {type(e).__name__} - {e}")
                    response = "ERROR: Internal server error during registration."

        elif cmd == 'LOGIN':
            # Format: LOGIN <username> <password>
            if len(tokens) != 3:
                response = 'ERROR: Usage: LOGIN <username> <password>'
            else:
                username, raw_pw = tokens[1], tokens[2]
                # Read from registry cache based on username
                peers = registry_interface('read', filters={'username': username})

                peer_entry = None
                if peers:
                    # Verify password hash
                    for p in peers:
                        local_hash = p.get('password')
                        if verify_password(local_hash, raw_pw):
                            peer_entry = p
                            break

                if peer_entry:
                    peer_ip = peer_entry.get('ip')
                    peer_port = peer_entry.get('port')
                    public_key_pem_str = peer_entry.get('public_key_pem')  # str or None
                    files = peer_entry.get('files', [])

                    if not peer_ip or not peer_port:
                        print(f"[ERROR] Login failed for {username}: Registry entry missing IP/Port.")
                        response = "ERROR: Internal error - invalid user record."
                    else:
                        # Update last seen time in registry (DB and cache)
                        registry_interface('update', filters={'username': username, 'ip': peer_ip, 'port': peer_port},
                                           data={'last_seen': time.time()})

                        # Create session
                        session_token = str(uuid.uuid4())
                        peer_info_for_cleanup = {
                            'username': username,
                            'ip': peer_ip,
                            'port': peer_port,
                            'public_key_pem': public_key_pem_str  # Store str
                        }
                        sessions[session_token] = peer_info_for_cleanup.copy()

                        # Add/Update active peer list
                        update_active_peer(username, peer_ip, peer_port, files, public_key_pem_str)
                        print(
                            f"[INFO] User {username} logged in from connection {addr} (Peer Addr: {peer_ip}:{peer_port})")

                        # Notify other peers
                        # Pass the dictionary containing the PEM string
                        threading.Thread(target=notify_peers_of_update,
                                         args=(peer_info_for_cleanup,), daemon=True).start()

                        # Prepare response
                        files_str = ','.join(files)
                        # Send back IP/Port known to server, might differ from connection addr if NAT
                        response = f'LOGGED_IN {session_token} {peer_ip}:{peer_port} {files_str}'
                else:
                    response = 'ERROR: Invalid username or password.'


        elif cmd == 'HEARTBEAT':
            # Format: HEARTBEAT <session_id>
            if len(tokens) != 2:
                response = 'ERROR: Usage: HEARTBEAT <session_id>'
            else:
                session_token = tokens[1]
                session = sessions.get(session_token)
                if not session:
                    response = 'ERROR: Invalid session ID. Please login again.'
                else:
                    username = session['username']
                    peer_ip = session['ip']
                    peer_port = session['port']
                    public_key_pem_str = session.get('public_key_pem')  # str or None

                    # Update last heartbeat time in active peers list
                    # Use update_active_peer which handles adding if somehow missing
                    updated_peer = update_active_peer(username, peer_ip, peer_port, public_key_pem=public_key_pem_str)
                    if not updated_peer:  # Check if update failed (shouldn't happen)
                        print(f"[WARN] Failed to update active peer during heartbeat for {username}")

                    # Also update last_seen in the persistent registry (DB and cache)
                    registry_interface('update', filters={'username': username, 'ip': peer_ip, 'port': peer_port},
                                       data={'last_seen': time.time()})
                    # print(f"[DEBUG] Heartbeat acknowledged for {username}")
                    response = 'HEARTBEAT_ACK'


        elif cmd == 'LIST':
            # Format: LIST <session_id>
            if len(tokens) != 2:
                response = 'ERROR: Usage: LIST <session_id>'
            else:
                session_token = tokens[1]
                session = sessions.get(session_token)
                if not session:
                    response = 'ERROR: Invalid session ID. Please login again.'
                else:
                    requesting_peer_key = (session['ip'], session['port'])
                    # Get current list of *other* active peers
                    current_active_peers = get_active_peers(exclude_self=requesting_peer_key)
                    entries = []
                    for peer in current_active_peers:
                        # Encode public key PEM (string) to Base64 for safe transport
                        pubkey_pem_str = peer.get('public_key_pem')  # str or None
                        encoded_pem = "NO_KEY"
                        if pubkey_pem_str:
                            try:
                                pubkey_bytes = pubkey_pem_str.encode('utf-8')
                                encoded_pem = base64.b64encode(pubkey_bytes).decode('utf-8')
                            except Exception as enc_e:
                                print(
                                    f"[ERROR] Failed to encode pubkey for LIST response (peer: {peer.get('username')}): {enc_e}")
                                encoded_pem = "KEY_ENCODE_ERROR"

                        files_str = ','.join(peer.get('files', []))
                        # Format: username@ip:port|file1,file2|base64_key_pem
                        entries.append(
                            f"{peer.get('username', 'N/A')}@{peer.get('ip', 'N/A')}:{peer.get('port', 'N/A')}|{files_str}|{encoded_pem}")

                    if entries:
                        response = ';'.join(entries)
                    else:
                        response = 'NO_PEERS_FOUND'


        elif cmd == 'SEARCH':
            # Format: SEARCH <session_id> <filename>
            if len(tokens) != 3:
                response = 'ERROR: Usage: SEARCH <session_id> <filename>'
            else:
                session_token, filename = tokens[1], tokens[2]
                session = sessions.get(session_token)
                if not session:
                    response = 'ERROR: Invalid session ID. Please login again.'
                else:
                    requesting_peer_key = (session['ip'], session['port'])
                    # Search in *other* active peers' files
                    matching_peers = []
                    current_active_peers = get_active_peers(exclude_self=requesting_peer_key)
                    for peer in current_active_peers:
                        if filename in peer.get('files', []):
                            # Return ip:port for matching peers
                            matching_peers.append(f"{peer['ip']}:{peer['port']}")

                    if matching_peers:
                        response = ','.join(matching_peers)
                    else:
                        response = 'NOT_FOUND'


        elif cmd == 'LOGOUT':
            # Format: LOGOUT <session_id>
            if len(tokens) != 2:
                response = 'ERROR: Usage: LOGOUT <session_id>'
            else:
                session_token = tokens[1]
                session: Dict | None = sessions.pop(session_token, None)  # Remove session atomically
                if not session:
                    response = 'ERROR: Invalid session ID.'
                else:
                    username = session.get('username', 'unknown')
                    peer_ip = session.get('ip')
                    peer_port = session.get('port')
                    if peer_ip and peer_port:
                        # Remove from active peers list
                        remove_active_peer(peer_ip, peer_port)
                        # Optional: Notify other peers of logout? Could add a LOGOUT_UPDATE message type.
                        # For now, rely on heartbeat timeout for cleanup.
                        print(f"[INFO] User {username} logged out ({peer_ip}:{peer_port})")
                        response = 'LOGGED_OUT'
                    else:
                        print(f"[WARN] Logout processed for {username}, but IP/Port missing in session data.")
                        response = 'LOGGED_OUT'  # Still confirm logout

        # --- End Command Processing ---

        # Send the response back securely
        secure_conn.send(response.encode('utf-8'))
        print(f"[HANDLE] Sent response to {addr}: {response[:100]}...")

    except (ConnectionError, ConnectionResetError, socket.timeout) as conn_e:
        print(f"[ERROR] Connection error with {addr}: {type(conn_e).__name__} - {conn_e}")
        # Clean up if user was logged in/active based on stored info
        if peer_info_for_cleanup:
            p_ip = peer_info_for_cleanup.get('ip')
            p_port = peer_info_for_cleanup.get('port')
            p_user = peer_info_for_cleanup.get('username', 'unknown')
            if p_ip and p_port:
                remove_active_peer(p_ip, p_port)
                print(f"[CLEANUP] Removed active peer {p_user}@{p_ip}:{p_port} due to connection error.")
        # Also remove session if it exists
        if session_token and session_token in sessions:
            sessions.pop(session_token, None)
            print(f"[CLEANUP] Removed session {session_token} due to connection error.")


    except Exception as e:
        print(f"[ERROR] Unexpected error handling client {addr}: {type(e).__name__} - {e}")
        # Attempt to send a generic error message if possible
        try:
            secure_conn.send(b"ERROR: Internal server error.")
        except Exception:
            pass  # Ignore if sending fails

    finally:
        print(f"[HANDLE] Closing connection with {addr}")
        secure_conn.close()


# --- Active Peers Cleanup Thread ---
def active_peers_cleanup():
    """Periodically remove peers from active list if no heartbeat received."""
    while True:
        check_interval = HEARTBEAT_INTERVAL  # Check interval related to heartbeat
        time.sleep(check_interval)
        now = time.time()
        # Timeout slightly longer than heartbeat interval to allow for network latency
        # Make timeout configurable or based on HEARTBEAT_INTERVAL
        timeout_value = HEARTBEAT_INTERVAL * 2.5
        timeout_threshold = now - timeout_value
        peers_to_remove = []

        # Check active peers
        with active_peers_lock:
            for key, peer in active_peers.items():
                if peer.get('last_heartbeat', 0) < timeout_threshold:
                    peers_to_remove.append(key)
                    print(
                        f"[CLEANUP] Marking peer for removal due to inactivity ({timeout_value}s): {peer.get('username', 'N/A')}@{key[0]}:{key[1]}")

        # Remove outside the lock to avoid modification during iteration issues
        for key in peers_to_remove:
            remove_active_peer(key[0], key[1])  # Handles lock internally

        # Optional: Clean up expired sessions
        # sessions_to_remove = []
        # with some_session_lock: # Need a lock for sessions dict if accessed by multiple threads
        #      for token, session_data in sessions.items():
        #           # Need a timestamp in session data to check expiry
        #           pass
        # for token in sessions_to_remove:
        #      with some_session_lock:
        #           sessions.pop(token, None)


# --- Main Server Function ---
def start_discovery_server():
    """Starts the discovery server, listening for secure connections."""
    load_or_generate_server_keys()  # Ensure keys are ready

    # Create the main listening socket as a SecureSocket
    server_socket = SecureSocket(socket.AF_INET, socket.SOCK_STREAM)

    # Load the server's private key into the listening socket
    # This key will be used by SecureSocket.accept() for the key exchange
    if server_private_key:
        server_socket.own_rsa_private_key = server_private_key
        print("[INFO] Server RSA private key loaded into listening socket.")
    else:
        print("[ERROR] Server private key not loaded. Cannot start server.")
        return  # Exit if key loading failed

    try:
        server_socket.bind((SERVER_HOST, SERVER_PORT))
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.listen(10)  # Increased backlog
        print(f"[INFO] Secure Discovery Server listening on {SERVER_HOST}:{SERVER_PORT}")
    except Exception as e:
        print(f"[ERROR] Failed to bind/listen on {SERVER_HOST}:{SERVER_PORT}: {e}")
        server_socket.close()
        exit(1)

    # Start cleanup thread
    # threading.Thread(target=active_peers_cleanup, daemon=True).start()
    print("[INFO] Active peers cleanup thread started.")

    # Main accept loop
    try:
        while True:
            secure_conn = None  # Initialize to None
            addr = None
            try:
                # Accept connection - SecureSocket.accept handles key exchange
                secure_conn, addr = server_socket.accept()
                # Pass the already secured socket to the handler thread
                threading.Thread(target=handle_client, args=(secure_conn, addr), daemon=True).start()
            except ConnectionError as ce:
                # Catch key exchange failures or other connection issues during accept/handshake
                print(f"[WARN] Connection error during accept/handshake from {addr if addr else 'unknown'}: {ce}")
                if secure_conn:
                    secure_conn.close()  # Ensure socket is closed on error
            except OSError as oe:
                # Handle socket errors (e.g., server socket closed)
                print(f"[ERROR] OS Error on server socket accept: {oe}")
                break  # Exit loop if server socket has issues
            except Exception as accept_e:
                print(f"[ERROR] Unexpected error during server accept loop: {type(accept_e).__name__} - {accept_e}")
                if secure_conn:
                    secure_conn.close()
                time.sleep(1)  # Avoid busy-looping on persistent errors

    except KeyboardInterrupt:
        print("\n[INFO] Shutting down discovery server...")
    finally:
        print("[INFO] Closing server socket.")
        server_socket.close()
        print("[INFO] Saving registry data...")
        # No explicit save needed for TinyDB in default mode (writes on change)
        # However, ensure TinyDB instance is properly closed if needed (depends on version/usage)
        # peer_registry_store.close() # Uncomment if required
        print("[INFO] Server shutdown complete.")


if __name__ == '__main__':
    # Load registry data from file at startup
    registry_interface('load')
    # Start the server
    # start_discovery_server()
    threading.Thread(target=start_discovery_server, daemon=True).start()
    input()
    # Keep main thread alive if server runs in daemon thread (not needed if server runs in main thread)
    # Example: Keep running until Enter is pressed
    # input("Press Enter to exit...\n")
    # Or use a loop:
    # try:
    #     while True:
    #         time.sleep(3600) # Sleep for a long time
    # except KeyboardInterrupt:
    #     print("\n[INFO] Main thread interrupted. Exiting.")
