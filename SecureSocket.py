import inspect
import os
import struct
from socket import socket

# Error handling for cryptography operations
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.backends import default_backend
# Cryptography imports
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecureSocket(socket):
    """
    A drop-in replacement for socket.socket that encrypts all data with AES-GCM
    after performing a secure key exchange.

    Key Exchange Protocol (Hybrid RSA + X25519):
    1. Client generates ephemeral X25519 key pair (client_x25519_priv, client_x25519_pub).
    2. Server generates ephemeral X25519 key pair (server_x25519_priv, server_x25519_pub).
    3. Client loads Server's long-term RSA Public Key (server_rsa_pub).
    4. Client encrypts its client_x25519_pub using server_rsa_pub (RSA-OAEP).
    5. Client sends [encrypted client_x25519_pub] to Server.
    6. Server loads its long-term RSA Private Key (server_rsa_priv).
    7. Server receives and decrypts the message using server_rsa_priv to get client_x25519_pub.
    8. Server sends its raw server_x25519_pub to Client.
    9. Client receives server_x25519_pub.
    10. Both Client and Server compute the shared secret:
        - Client: shared_secret = client_x25519_priv.exchange(server_x25519_pub_key_obj)
        - Server: shared_secret = server_x25519_priv.exchange(client_x25519_pub_key_obj)
    11. Both derive the symmetric AES key using HKDF from the shared_secret.
    12. Communication proceeds using AES-GCM with the derived key.

    Wire format per-message (after key exchange):
        [4-byte BE length][12-byte nonce][ciphertext||16-byte tag]
    """

    def __init__(self, *args, key: bytes = None, **kwargs):
        """
        Initializes the socket. The AES key is set after key exchange.
        All other args/kwargs are passed to socket.socket.
        """
        super().__init__(*args, **kwargs)
        self._aesgcm = None  # AESGCM cipher is initialized after key exchange
        self._key_exchanged = False  # Flag to track if key exchange is done

        # --- RSA Keys (Must be loaded/provided before key exchange) ---
        # These would typically be loaded from files or configuration
        self.own_rsa_private_key: rsa.RSAPrivateKey | None = None
        self.peer_rsa_public_key: rsa.RSAPublicKey | None = None
        # --- End RSA Keys ---

    def accept(self):
        """
        Accepts a connection, wraps the raw socket, and performs key exchange
        in the server role.
        Returns the SecureSocket instance and the client address.
        """
        print("[SecureSocket] Waiting to accept connection...")
        raw_sock, addr = super().accept()
        print(f"[SecureSocket] Accepted connection from {addr}")

        # Detach the file descriptor so raw_sock no longer owns it
        raw_fd = raw_sock.detach()
        print("[SecureSocket] Detached raw socket FD")

        # Wrap into SecureSocket (same family/type/proto)
        ss = SecureSocket(self.family,
                          self.type,
                          self.proto,
                          fileno=raw_fd)

        # --- Server Role: Load own private key ---
        # In a real application, load this securely, e.g., from a file
        # For demonstration, assuming it's pre-loaded or loaded here
        # ss.load_rsa_private_key_from_pem_file('path/to/server_private.pem')
        print("[SecureSocket] Server: Loading own RSA private key...")
        # Placeholder: Replace with actual key loading
        if not self.own_rsa_private_key:
            # Generate a temporary one if not loaded (FOR DEMO ONLY)
            print("[SecureSocket] WARNING: Generating temporary RSA private key for server (DEMO ONLY)")
            self.own_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ss.own_rsa_private_key = self.own_rsa_private_key
        print("[SecureSocket] Server: Own RSA private key loaded.")
        # --- End Server Role Key Loading ---

        print("[SecureSocket] Server: Performing key exchange...")
        try:
            ss._perform_key_exchange(is_server=True)
            print("[SecureSocket] Server: Key exchange successful.")
        except Exception as e:
            print(f"[SecureSocket] Server: Key exchange failed: {e}")
            ss.close()  # Close socket on failed handshake
            raise ConnectionError("Key exchange failed during accept") from e

        return ss, addr

    def connect(self, address):
        """
        Connects to the peer and performs key exchange in the client role.
        Requires peer_rsa_public_key to be set before calling.
        """

        # Get the current frame and the caller's frame
        frame = inspect.currentframe()
        caller_frame = frame.f_back
        caller_name = caller_frame.f_code.co_name
        print(f"Called by function: {caller_name}")
        print(f"[SecureSocket2] Client: Connecting to {address}...")
        super().connect(address)
        print(f"[SecureSocket2] Client: Connected to {address}")

        # --- Client Role: Load peer's public key ---
        # This key should be obtained beforehand (e.g., from discovery server)
        # For demonstration, assuming it's pre-loaded
        print("[SecureSocket] Client: Loading peer's RSA public key...")
        # Placeholder: Replace with actual key loading/retrieval
        if not self.peer_rsa_public_key:
            # This MUST be set before connect() is called in a real app
            raise ValueError("Peer RSA public key not set before connect()")
        print("[SecureSocket] Client: Peer's RSA public key loaded.")
        # --- End Client Role Key Loading ---

        print("[SecureSocket] Client: Performing key exchange...")
        try:
            self._perform_key_exchange(is_server=False)
            print("[SecureSocket] Client: Key exchange successful.")
        except Exception as e:
            print(f"[SecureSocket] Client: Key exchange failed: {e}")
            self.close()  # Close socket on failed handshake
            raise ConnectionError("Key exchange failed during connect") from e

    def send(self, plaintext: bytes) -> int:
        """
        Encrypts `plaintext` with AESGCM if key exchange is complete,
        otherwise sends raw data (should only happen during key exchange).
        Frames encrypted data with a 4-byte length header and sends atomically.
        Returns total bytes sent (header + payload).
        """
        frame = inspect.currentframe()
        caller_frame = frame.f_back
        caller_name = caller_frame.f_code.co_name
        print(f"Called by function: {caller_name}")
        if not self._key_exchanged or not self._aesgcm:
            # Should only happen if called directly during key exchange logic
            # which uses super().sendall()
            print("[SecureSocket] WARNING: Sending raw data (key exchange likely in progress)")
            super().sendall(plaintext)
            return len(plaintext)

        # print(f"[SecureSocket] Encrypting and sending {len(plaintext)} bytes")
        nonce = os.urandom(12)  # Generate a unique nonce for each message
        try:
            ct_and_tag = self._aesgcm.encrypt(nonce, plaintext, None)
        except Exception as e:
            print(f"[SecureSocket] AESGCM Encryption failed: {e}")
            raise ConnectionError("Encryption failed") from e

        payload = nonce + ct_and_tag
        header = struct.pack('!I', len(payload))  # 4-byte network byte order length

        # Use sendall to ensure the full message (header + payload) is sent
        # print(f"[SecureSocket] Sending payload length: {len(payload)}")

        print(f"[SecureSocket] Before printing")
        super().sendall(header + payload)
        print("REACHED HERE\n---------------\n\n\n\n")
        return len(header) + len(payload)

    def recv(self, bufsize: int) -> bytes:
        """
        Reads one full encrypted packet (ignores bufsize if key exchange is done),
        decrypts it with AESGCM, and returns the plaintext.
        If key exchange is not complete, reads raw data up to bufsize.
        """
        print("[SecureSocket] Receiving")
        if not self._key_exchanged or not self._aesgcm:
            # Should only happen if called directly during key exchange logic
            # which uses _recv_exact()
            print("[SecureSocket] WARNING: Receiving raw data (key exchange likely in progress)")
            data = super().recv(bufsize)
            # print(f"[SecureSocket] Received raw data: {data!r}")
            return data

        # print("[SecureSocket] Receiving encrypted message...")
        # 1. Read the 4-byte length header
        raw_len = self._recv_exact(4)
        if not raw_len:
            print("[SecureSocket] Connection closed while reading length header.")
            return b''  # Peer closed connection
        payload_len = struct.unpack('!I', raw_len)[0]
        # print(f"[SecureSocket] Expected payload length: {payload_len}")

        if payload_len == 0:
            print("[SecureSocket] Received empty payload.")
            return b''  # Empty payload received

        if payload_len > 65536 + 12 + 16:  # Sanity check: 64KB + nonce + tag
            print(f"[SecureSocket] ERROR: Received excessively large payload length: {payload_len}")
            raise ConnectionError("Received excessively large payload length")

        # 2. Read the full encrypted blob (nonce + ciphertext + tag)
        blob = self._recv_exact(payload_len)
        if len(blob) != payload_len:
            print("[SecureSocket] ERROR: Did not receive expected payload length.")
            raise ConnectionError("Incomplete payload received")

        nonce = blob[:12]
        ct_and_tag = blob[12:]

        print("Before Decryption")
        # 3. Decrypt and authenticate
        try:
            # print(f"[SecureSocket] Decrypting {len(ct_and_tag)} bytes...")
            plaintext = self._aesgcm.decrypt(nonce, ct_and_tag, None)
            print("After Decryption")
            print(plaintext)
            # print(f"[SecureSocket] Decryption successful, plaintext length: {len(plaintext)}")
        except InvalidTag:
            print("[SecureSocket] ERROR: AESGCM decryption failed - Invalid Tag (Authentication failed)")
            raise ConnectionError("Decryption/authentication failed: Invalid Tag") from None
        # except Exception as e:
        #     print(f"[SecureSocket] ERROR: AESGCM decryption failed: {e}")
        #     raise ConnectionError("Decryption failed") from e

        return plaintext

    def set_key(self, key: bytes):
        """Manually sets the AES key (use with caution, prefer key exchange)."""
        if len(key) not in [16, 24, 32]:
            raise ValueError("Invalid AES key size. Must be 16, 24, or 32 bytes.")
        print("[SecureSocket] Manually setting AES key.")
        self._aesgcm = AESGCM(key)
        self._key_exchanged = True  # Assume key is set securely

    def _recv_exact(self, n: int) -> bytes:
        """
        Internal helper to read exactly n bytes using the underlying socket.
        Raises ConnectionError on EOF before n bytes are read.
        """
        data = b''
        while len(data) < n:
            try:
                # Use super().recv to bypass our recv logic during raw reads
                chunk = super().recv(n - len(data))
                if not chunk:
                    # Connection closed by peer
                    print(
                        f"[SecureSocket] _recv_exact: Connection closed while waiting for {n} bytes (got {len(data)}).")
                    raise ConnectionError("Socket closed unexpectedly during read")
                data += chunk
            except BlockingIOError:
                # This shouldn't happen with default blocking sockets, but handle defensively
                print("[SecureSocket] _recv_exact: BlockingIOError encountered.")
                raise
            except OSError as e:
                print(f"[SecureSocket] _recv_exact: OSError during recv: {e}")
                raise ConnectionError("Socket error during read") from e
        return data

    def _perform_key_exchange(self, is_server: bool):
        """
        Performs the hybrid RSA + X25519 key exchange.
        - Client encrypts its X25519 pubkey with Server's RSA pubkey.
        - Server decrypts with its RSA privkey.
        - Server sends its X25519 pubkey raw.
        - Both derive shared secret via X25519 exchange.
        - AES key derived via HKDF.

        Requires appropriate RSA keys to be set on the instance before calling.
        (peer_rsa_public_key for client, own_rsa_private_key for server)
        """
        role = "Server" if is_server else "Client"
        print(f"[SecureSocket] {role}: Starting key exchange...")

        # 1) Generate ephemeral X25519 key pair for this session
        x25519_priv = x25519.X25519PrivateKey.generate()
        x25519_pub = x25519_priv.public_key()
        own_x25519_pub_bytes = x25519_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        print(f"[SecureSocket] {role}: Generated ephemeral X25519 key pair.")
        # print(f"[SecureSocket] {role}: Own X25519 Public Key Bytes: {own_x25519_pub_bytes.hex()}")

        # Define RSA padding
        rsa_padding_config = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

        peer_x25519_pub_key = None

        try:
            if is_server:
                # --- Server Logic ---
                if not self.own_rsa_private_key:
                    raise ConnectionError("Server RSA private key not loaded for key exchange.")

                # 2a) Server: Wait for Client's encrypted X25519 public key
                # Need to know the expected length of the RSA encrypted message
                # RSA ciphertext length equals the key size in bytes
                expected_len = self.own_rsa_private_key.key_size // 8
                print(f"[SecureSocket] Server: Waiting for encrypted X25519 key (expected {expected_len} bytes)...")
                encrypted_client_x25519_pub = self._recv_exact(expected_len)  # Use raw recv
                print(f"[SecureSocket] Server: Received {len(encrypted_client_x25519_pub)} bytes.")

                # 3a) Server: Decrypt Client's X25519 public key using own RSA private key
                try:
                    client_x25519_pub_bytes = self.own_rsa_private_key.decrypt(
                        encrypted_client_x25519_pub,
                        rsa_padding_config
                    )
                    print("[SecureSocket] Server: Decrypted client's X25519 public key.")
                    # print(f"[SecureSocket] Server: Client X25519 Public Key Bytes: {client_x25519_pub_bytes.hex()}")

                except ValueError as e:
                    print(f"[SecureSocket] Server: RSA Decryption failed: {e}")
                    raise ConnectionError("Failed to decrypt client's public key") from e

                # Validate length (X25519 public keys are 32 bytes)
                if len(client_x25519_pub_bytes) != 32:
                    print(
                        f"[SecureSocket] Server: ERROR - Decrypted key has invalid length: {len(client_x25519_pub_bytes)}")
                    raise ConnectionError("Invalid X25519 public key length received")

                # Load the client's public key object
                peer_x25519_pub_key = x25519.X25519PublicKey.from_public_bytes(client_x25519_pub_bytes)

                # 4a) Server: Send own (raw) X25519 public key to Client
                print("[SecureSocket] Server: Sending own raw X25519 public key...")
                super().sendall(own_x25519_pub_bytes)  # Use raw send
                print("[SecureSocket] Server: Sent public key.")

            else:
                # --- Client Logic ---
                if not self.peer_rsa_public_key:
                    raise ConnectionError("Peer RSA public key not loaded for key exchange.")

                # 2b) Client: Encrypt own X25519 public key using Server's RSA public key
                print("[SecureSocket] Client: Encrypting own X25519 public key with server's RSA key...")
                try:
                    encrypted_own_x25519_pub = self.peer_rsa_public_key.encrypt(
                        own_x25519_pub_bytes,
                        rsa_padding_config
                    )
                    print(f"[SecureSocket] Client: Encrypted key length: {len(encrypted_own_x25519_pub)} bytes.")
                except Exception as e:
                    print(f"[SecureSocket] Client: RSA Encryption failed: {e}")
                    raise ConnectionError("Failed to encrypt own public key") from e

                # 3b) Client: Send encrypted key to Server
                print("[SecureSocket] Client: Sending encrypted X25519 public key...")
                super().sendall(encrypted_own_x25519_pub)  # Use raw send
                print("[SecureSocket] Client: Sent encrypted key.")

                # 4b) Client: Wait for Server's (raw) X25519 public key
                # X25519 public keys are 32 bytes
                print("[SecureSocket] Client: Waiting for server's raw X25519 public key (expected 32 bytes)...")
                server_x25519_pub_bytes = self._recv_exact(32)  # Use raw recv
                print(f"[SecureSocket] Client: Received server's public key ({len(server_x25519_pub_bytes)} bytes).")
                # print(f"[SecureSocket] Client: Server X25519 Public Key Bytes: {server_x25519_pub_bytes.hex()}")

                # Load the server's public key object
                peer_x25519_pub_key = x25519.X25519PublicKey.from_public_bytes(server_x25519_pub_bytes)

            # 5) Both: Derive shared secret using X25519 exchange
            print(f"[SecureSocket] {role}: Performing X25519 key exchange...")
            shared_secret = x25519_priv.exchange(peer_x25519_pub_key)
            print(f"[SecureSocket] {role}: Derived shared secret ({len(shared_secret)} bytes).")

            # 6) Both: Derive symmetric AES key from shared secret using HKDF
            aes_key = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # AES-256
                salt=b"FM Session key",  # Salt is required for PBKDF2, should be unique and not secret
                iterations=100000,  # Higher value increases security but takes longer
                backend=default_backend()
            ).derive(shared_secret)
            print(f"[SecureSocket] {role}: Derived AES key ({len(aes_key)} bytes).")

            # 7) Both: Install AESGCM cipher with the derived key
            self._aesgcm = AESGCM(aes_key)
            self._key_exchanged = True
            print(f"[SecureSocket] {role}: Key exchange complete. AESGCM cipher installed.")

        except (ConnectionError, ValueError, TypeError, InvalidTag, InvalidSignature) as e:
            # Catch specific crypto and connection errors during exchange
            print(f"[SecureSocket] {role}: Key exchange failed critically: {type(e).__name__} - {e}")
            self.close()  # Ensure socket is closed on failure
            raise ConnectionError(f"{role} key exchange failed") from e
        except Exception as e:
            # Catch any other unexpected errors
            print(f"[SecureSocket] {role}: Unexpected error during key exchange: {type(e).__name__} - {e}")
            self.close()
            raise ConnectionError(f"{role} key exchange encountered an unexpected error") from e

    def load_rsa_public_key_from_pem_bytes(self, pem_bytes: bytes):
        """Loads an RSA public key from PEM-encoded bytes."""
        print("[SecureSocket] Loading RSA public key from bytes...")
        try:
            self.peer_rsa_public_key = serialization.load_pem_public_key(pem_bytes)
            print("[SecureSocket] RSA public key loaded successfully from bytes.")
        except (ValueError, TypeError) as e:
            print(f"[SecureSocket] ERROR: Failed to load public key from bytes: {e}")
            raise
        except Exception as e:
            print(f"[SecureSocket] ERROR: An unexpected error occurred loading public key from bytes: {e}")
            raise

