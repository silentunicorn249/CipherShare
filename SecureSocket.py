import os
import struct
from socket import socket

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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

    def send(self, plaintext: bytes) -> int:
        """
        Encrypts `plaintext` with AESGCM.encrypt(nonce, plaintext, None),
        frames it with a 4-byte length header, and sends atomically.
        Returns total bytes sent (header + payload).
        """
        if not self._aesgcm:
            super().sendall(plaintext)
            return len(plaintext)

        nonce = os.urandom(12)
        ct_and_tag = self._aesgcm.encrypt(nonce, plaintext, None)
        payload = nonce + ct_and_tag
        header = struct.pack('!I', len(payload))
        # sendall to ensure full delivery
        super().sendall(header + payload)
        return len(header) + len(payload)

    def recv(self, bufsize: int) -> bytes:
        """
        Reads one full encrypted packet (ignores bufsize),
        decrypts it with AESGCM.decrypt(nonce, ct||tag, None),
        and returns the plaintext.
        """
        if not self._aesgcm:
            data = super().recv(bufsize)
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
            plaintext = self._aesgcm.decrypt(nonce, ct_and_tag, None)
        except Exception as e:
            raise ConnectionError("Decryption/authentication failed") from e
        return plaintext

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
