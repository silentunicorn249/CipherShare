# client.py
from SecureSocket import SecureSocket

sock = SecureSocket()
sock.connect(("localhost", 5555))
sock._perform_key_exchange(is_server=False)
sock.send(b"hello, secure server!")
reply = sock.recv(1024)
print("reply:", reply)
