# --- In file_utils.py ---
import hashlib
import os
import struct
from socket import socket

from constants import DOWNLOAD_DIR, BUFFER_SIZE

# Define a fixed format for the filesize header (e.g., 8-byte unsigned long long)
FILE_SIZE_HEADER_FORMAT = '!Q'
FILE_SIZE_HEADER_LENGTH = struct.calcsize(FILE_SIZE_HEADER_FORMAT)


def send_file_with_hash(client_sock: socket, filepath):
    try:
        filesize = os.path.getsize(filepath)
        print(f"[UPLOAD] Filesize: {filesize}")

        # 1) Send filesize header
        filesize_header = struct.pack(FILE_SIZE_HEADER_FORMAT, filesize)
        print(f"[UPLOAD] Sending filesize header ({len(filesize_header)} bytes)...")
        client_sock.send(filesize_header)  # Uses SecureSocket implicitly

        # 1b) Wait for filesize ACK
        print("[UPLOAD] Waiting for filesize ACK...")
        ack = client_sock.recv(BUFFER_SIZE)  # Uses SecureSocket implicitly
        if ack != b"ACK_SIZE":
            print(f"[ERROR] Did not receive correct filesize ACK. Got: {ack!r}")
            # client_sock.close() # Consider closing strategy
            return False
        print("[UPLOAD] Filesize ACK received. Sending file data...")

        # 2) Send file data (and update hash)
        hash_obj = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk:
                    break
                hash_obj.update(chunk)
                client_sock.send(chunk)  # Uses SecureSocket implicitly

        # 3) Send the final hash digest
        hash_value = hash_obj.digest()
        print(f"[UPLOAD] Sending hash ({len(hash_value)} bytes)...")
        client_sock.send(hash_value)  # Uses SecureSocket implicitly

        print(f"[INFO] Sent file '{filepath}' with hash {hash_value.hex()}")
        return True  # Indicate success
    except Exception as e:
        print(f"[ERROR] Exception in send_file_with_hash: {e}")
        return False
    # Socket closing should ideally be handled by the caller (handle_peer_client)


def receive_file_with_hash(sock: socket, filename):  # Filesize param removed
    try:
        # 1) Receive filesize header
        print("[DOWNLOAD] Receiving filesize header...")
        filesize_header = sock.recv(FILE_SIZE_HEADER_LENGTH)  # Uses SecureSocket implicitly
        if not filesize_header or len(filesize_header) != FILE_SIZE_HEADER_LENGTH:
            print("[ERROR] Failed to receive complete filesize header.")
            return False

        filesize = struct.unpack(FILE_SIZE_HEADER_FORMAT, filesize_header)[0]
        print(f"[DOWNLOAD] Received filesize: {filesize}")

        # 1b) Send ACK for filesize
        print("[DOWNLOAD] Sending filesize ACK...")
        sock.send(b"ACK_SIZE")  # Uses SecureSocket implicitly

        # 2) Receive file data (and update hash)
        print("[DOWNLOAD] Receiving file data...")
        remaining = filesize
        filedata = bytearray()
        hash_obj = hashlib.sha256()

        while remaining > 0:
            bytes_to_read = min(BUFFER_SIZE, remaining)
            chunk = sock.recv(bytes_to_read)  # Uses SecureSocket implicitly
            if not chunk:
                print("[ERROR] Connection closed prematurely while receiving file data.")
                return False
            hash_obj.update(chunk)
            filedata.extend(chunk)
            remaining -= len(chunk)

        if remaining != 0:
            print(f"[ERROR] File data reception incomplete. Remaining bytes: {remaining}")
            return False

        print("[DOWNLOAD] File data received. Receiving hash...")
        # 3) Read the sent hash and compare
        expected_hash_len = hash_obj.digest_size
        received_hash = sock.recv(expected_hash_len)  # Uses SecureSocket implicitly

        if not received_hash or len(received_hash) != expected_hash_len:
            print(f"[ERROR] Hash reception incomplete. Got {len(received_hash)} bytes, expected {expected_hash_len}.")
            return False

        local_hash = hash_obj.digest()
        print(f"[INFO] Received Hash: {received_hash.hex()}")
        print(f"[INFO] Local Hash:    {local_hash.hex()}")
        if received_hash != local_hash:
            print("[ERROR] Hash mismatch! Transfer corrupted.")
            return False

        # 4) Save the file
        print("[DOWNLOAD] Hash check OK. Saving file...")
        save_path = os.path.join(DOWNLOAD_DIR, filename)
        os.makedirs(DOWNLOAD_DIR, exist_ok=True)
        with open(save_path, "wb") as f:
            f.write(filedata)
        print(f"[SUCCESS] File '{filename}' saved to {save_path}")
        return True
    except Exception as e:
        print(f"[ERROR] Exception in receive_file_with_hash: {e}")
        return False
    # Socket closing should ideally be handled by the caller (download_file_from_peer)
