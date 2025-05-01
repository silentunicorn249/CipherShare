# server.py
import socket

from SecureSocket import SecureSocket

listener = SecureSocket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("0.0.0.0", 5555))
listener.listen(1)

conn, addr = listener.accept()
print(f"secure connection from {addr}")
msg = conn.recv(1024)
print("got:", msg)
conn.send(b"hello, encrypted client!")
