import os
import struct
from socket import socket

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SecureSocket(socket):
    """
    A drop-in replacement for socket.socket that encrypts all data with AES-GCM.
    Wire format per-message:
        [4-byte BE length][12-byte nonce][ciphertext||16-byte tag]
    """

    def __init__(self, *args, key: bytes = None, **kwargs):
        """
        :param key: 16, 24 or 32-byte AES key
        All other args/kwargs are passed to socket.socket.
        """
        super().__init__(*args, **kwargs)
        # Prepare the AEAD cipher
        if key:
            self._aesgcm = AESGCM(key)
        else:
            self._aesgcm = None

    def accept(self):
        print("Started to accept connection")
        raw_sock, addr = super().accept()

        print(f"Accepted connection from {addr}")

        # detach the FD so raw_sock no longer owns it
        raw_fd = raw_sock.detach()

        print("Deatacched completed connection")
        # wrap into SecureSocket (same family/type/proto) + do handshake
        ss = SecureSocket(self.family,
                          self.type,
                          self.proto,
                          key=None,
                          fileno=raw_fd)
        print("Created new secure socket")
        # print("Performing key exchange")
        # ss._perform_key_exchange(is_server=True)
        return ss, addr

    def send(self, plaintext: bytes) -> int:
        """
        Encrypts `plaintext` with AESGCM.encrypt(nonce, plaintext, None),
        frames it with a 4-byte length header, and sends atomically.
        Returns total bytes sent (header + payload).
        """

        print(f"Sending plaintext {plaintext}")
        if not self._aesgcm:
            super().sendall(plaintext)
            return len(plaintext)

        nonce = os.urandom(12)
        ct_and_tag = self._aesgcm.encrypt(nonce, plaintext, None)
        payload = nonce + ct_and_tag
        header = struct.pack('!I', len(payload))
        # sendall to ensure full delivery
        print(f"Sending payload {payload}")
        super().sendall(header + payload)
        return len(header) + len(payload)

    def recv(self, bufsize: int) -> bytes:
        """
        Reads one full encrypted packet (ignores bufsize),
        decrypts it with AESGCM.decrypt(nonce, ct||tag, None),
        and returns the plaintext.
        """
        print(f"Reading {bufsize}")
        if not self._aesgcm:
            data = super().recv(bufsize)
            print(f"Reading raw data {data}")
            return data

        # Read exact 4-byte length
        raw_len = self._recv_exact(4)
        if not raw_len:
            return b''
        payload_len = struct.unpack('!I', raw_len)[0]
        # Read the full encrypted blob
        blob = self._recv_exact(payload_len)
        nonce = blob[:12]
        ct_and_tag = blob[12:]
        try:
            print(f"Decrypting {ct_and_tag}")
            plaintext = self._aesgcm.decrypt(nonce, ct_and_tag, None)
        except Exception as e:
            raise ConnectionError("Decryption/authentication failed") from e
        return plaintext

    def set_key(self, key: bytes):
        self._aesgcm = AESGCM(key)

    def _recv_exact(self, n: int) -> bytes:
        """
        Internal helper to read exactly n bytes or raise on EOF.
        """
        data = b''
        while len(data) < n:
            chunk = super().recv(n - len(data))
            if not chunk:
                raise ConnectionError("Socket closed unexpectedly")
            data += chunk
        return data

    def _perform_key_exchange(self, is_server: bool):
        print("Starting key exchange")
        # 1) Generate ephemeral X25519 key pair
        priv = x25519.X25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)

        print(pub_bytes)

        if is_server:
            # Server: Send own pub key FIRST, then wait for client's pub key
            print("Server: Sending public key")
            super().sendall(pub_bytes)
            print("Server: Waiting for client public key")
            client_pub = self._recv_exact(len(pub_bytes))  # Use raw recv
            print("Server: Received client public key")
            peer_pub = x25519.X25519PublicKey.from_public_bytes(client_pub)
        else:
            # Client: Wait for server's pub key FIRST, then send own pub key
            print("Client: Waiting for server public key")
            server_pub = self._recv_exact(len(pub_bytes))  # Use raw recv
            print("Client: Received server public key, sending own public key")
            super().sendall(pub_bytes)
            print("Client: Sent public key")
            peer_pub = x25519.X25519PublicKey.from_public_bytes(server_pub)

        # 2) Derive shared secret and stretch to 32-byte key via HKDF
        shared_secret = priv.exchange(peer_pub)
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"secure-socket-handshake",
        ).derive(shared_secret)

        # 3) Install AESGCM cipher
        self._aesgcm = AESGCM(key)
        print("Done key exchange")
