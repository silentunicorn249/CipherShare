import hashlib
import os
from socket import socket

from constants import *


def send_file_with_hash(client_sock: socket, filepath):
    # 1) Send filesize
    filesize = os.path.getsize(filepath)
    client_sock.send(str(filesize).encode("utf-8"))
    ack = client_sock.recv(BUFFER_SIZE)  # wait for ACK

    # 2) Send file data (and update hash)
    hash_obj = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            hash_obj.update(chunk)
            client_sock.send(chunk)

    # 3) Send the final hash digest
    hash_value = hash_obj.digest()
    client_sock.send(hash_value)
    client_sock.close()

    print(f"[INFO] Sent file '{filepath}' with hash {hash_value}")


def receive_file_with_hash(sock: socket, filename, filesize: int):
    sock.send(b"ACK")

    # 2) Receive file data (and update hash)
    remaining = filesize
    filedata = bytearray()
    hash_obj = hashlib.sha256()

    while remaining > 0:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            break
        hash_obj.update(chunk)
        filedata.extend(chunk)
        remaining -= len(chunk)

    # 3) Read the sent hash and compare
    received = sock.recv(hash_obj.digest_size)
    local_hash = hash_obj.digest()
    if received != local_hash:
        raise ValueError("Hash mismatch! Transfer corrupted.")

    print("Hash is ", local_hash)
    # 4) Save the file
    save_path = os.path.join(DOWNLOAD_DIR, filename)
    with open(save_path, "wb") as f:
        f.write(filedata)

    return True
