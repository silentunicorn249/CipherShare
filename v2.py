import os
import socket
import threading
import json
import time
import hashlib
from typing import List, Tuple, Dict

# -------------------------------
# Constants and Helper Functions
# -------------------------------

DEFAULT_PORT = 9000
BUFFER_SIZE = 4096  # bytes
CHUNK_SIZE = 1024   # bytes per chunk (for demo purposes; production may use 512KB or more)
SHARED_FOLDER = "shared_data"

def compute_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def secure_send(func):
    """
    Decorator stub for future security layer integration.
    Wraps network send operations.
    """
    def wrapper(*args, **kwargs):
        # Future hook: add encryption/digital signature here.
        return func(*args, **kwargs)
    return wrapper

# -------------------------------
# Network Communication Module
# -------------------------------

class NetworkCommunication:
    """
    Implements low-level message sending/receiving over UDP using JSON.
    """
    def __init__(self, listen_ip: str = '0.0.0.0', listen_port: int = DEFAULT_PORT):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.listen_ip, self.listen_port))
        self.running = True
        self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.receive_thread.start()
        # The callback is set by modules (peer discovery, transfer manager, etc.)
        self.message_callback = None

    def set_message_callback(self, callback):
        """Register a callback function for incoming messages."""
        self.message_callback = callback

    @secure_send
    def send_message(self, target: Tuple[str, int], message: dict):
        data = json.dumps(message).encode('utf-8')
        self.socket.sendto(data, target)

    def _receive_loop(self):
        while self.running:
            try:
                data, addr = self.socket.recvfrom(BUFFER_SIZE)
                message = json.loads(data.decode('utf-8'))
                if self.message_callback:
                    self.message_callback(message, addr)
            except Exception as e:
                print("Error receiving message:", e)

    def close(self):
        self.running = False
        self.socket.close()

# -------------------------------
# Peer Discovery Module
# -------------------------------

class PeerDiscovery:
    """
    Discovers and maintains a table of active peers.
    """
    def __init__(self, net_comm: NetworkCommunication, bootstrap_nodes: List[Tuple[str, int]] = []):
        self.net_comm = net_comm
        # Maps peer_id to a tuple (ip, port, last_seen)
        self.peer_table: Dict[str, Tuple[str, int, float]] = {}
        self.bootstrap_nodes = bootstrap_nodes
        # Register a callback for messages
        self.net_comm.set_message_callback(self.process_message)
        self.heartbeat_interval = 30  # seconds
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

    def process_message(self, message: dict, addr: Tuple[str, int]):
        msg_type = message.get("type")
        sender_id = message.get("sender_id")
        if msg_type == "PING":
            print(f"Received PING from {sender_id} at {addr}")
            self._update_peer(sender_id, addr)
            pong = {
                "version": 1,
                "type": "PONG",
                "sender_id": "my_peer_id",  # Replace with a proper unique peer identifier in production
                "payload": {
                    "peer_list": list(self.peer_table.values())
                }
            }
            self.net_comm.send_message(addr, pong)
        elif msg_type == "PONG":
            print(f"Received PONG from {sender_id} at {addr}")
            self._update_peer(sender_id, addr)
            peer_list = message.get("payload", {}).get("peer_list", [])
            for peer_info in peer_list:
                if len(peer_info) >= 2:
                    peer_ip, peer_port, *_ = peer_info
                    self.add_peer("unknown", (peer_ip, peer_port))
        elif msg_type == "PEER_UPDATE":
            peer_list = message.get("payload", {}).get("peer_list", [])
            for peer_info in peer_list:
                if len(peer_info) >= 2:
                    peer_ip, peer_port, *_ = peer_info
                    self.add_peer("unknown", (peer_ip, peer_port))
        # Other types can be added here.

    def _update_peer(self, peer_id: str, addr: Tuple[str, int]):
        self.peer_table[peer_id] = (addr[0], addr[1], time.time())

    def add_peer(self, peer_id: str, addr: Tuple[str, int]):
        self._update_peer(peer_id, addr)

    def send_ping(self, target: Tuple[str, int]):
        ping_msg = {
            "version": 1,
            "type": "PING",
            "sender_id": "my_peer_id",
            "payload": {}
        }
        self.net_comm.send_message(target, ping_msg)

    def _heartbeat_loop(self):
        while True:
            targets = self.bootstrap_nodes + [(ip, port) for (_, (ip, port, _)) in self.peer_table.items()]
            for target in targets:
                self.send_ping(target)
            time.sleep(self.heartbeat_interval)

# -------------------------------
# File Indexing & Search Module
# -------------------------------

class FileIndex:
    """
    Scans the shared_data folder at startup and creates an in-memory index of files.
    Each file is divided into chunks, and the metadata is stored for search and transfer.
    """
    def __init__(self, shared_folder: str = SHARED_FOLDER, chunk_size: int = CHUNK_SIZE):
        self.shared_folder = shared_folder
        self.chunk_size = chunk_size
        # file_hash -> metadata dictionary
        self.local_index: Dict[str, dict] = {}
        # Build the index at initialization
        self._load_shared_files()

    def _load_shared_files(self):
        if not os.path.isdir(self.shared_folder):
            print(f"Shared folder '{self.shared_folder}' not found. Creating it.")
            os.makedirs(self.shared_folder)
        for file_name in os.listdir(self.shared_folder):
            file_path = os.path.join(self.shared_folder, file_name)
            if os.path.isfile(file_path):
                metadata = self._generate_file_metadata(file_path)
                if metadata:
                    self.local_index[metadata["file_hash"]] = metadata
                    print(f"Indexed file: {metadata['file_name']} with hash {metadata['file_hash']}")

    def _generate_file_metadata(self, file_path: str) -> dict:
        try:
            file_size = os.path.getsize(file_path)
            chunk_hashes = []
            # Also accumulate all data to compute file hash
            file_data = b""
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    file_data += chunk
                    chunk_hash = compute_hash(chunk)
                    chunk_hashes.append(chunk_hash)
            file_hash = compute_hash(file_data)
            metadata = {
                "file_hash": file_hash,
                "file_name": os.path.basename(file_path),
                "file_size": file_size,
                "chunk_size": self.chunk_size,
                "chunks": chunk_hashes,
                "file_path": file_path  # absolute location for uploads
            }
            return metadata
        except Exception as e:
            print(f"Error generating metadata for {file_path}: {e}")
            return {}

    def put_metadata(self, file_hash: str, metadata: dict):
        self.local_index[file_hash] = metadata
        # In a full system, metadata would be propagated in the DHT.
        print(f"Stored metadata for {file_hash}")

    def search_metadata(self, query: str) -> List[dict]:
        results = []
        for meta in self.local_index.values():
            if query.lower() in meta.get("file_name", "").lower():
                results.append(meta)
        return results

    def get_file_metadata(self, file_hash: str) -> dict:
        return self.local_index.get(file_hash)

# -------------------------------
# Transfer Manager Module
# -------------------------------

class DownloadSession:
    """
    Manages the state for downloading a single file.
    """
    def __init__(self, file_metadata: dict, peer_list: List[Tuple[str, int]], net_comm: NetworkCommunication):
        self.metadata = file_metadata
        self.peers = peer_list
        self.net_comm = net_comm
        # Track each chunk: 'pending', 'downloading', or 'complete'
        self.chunk_status: Dict[str, str] = {chunk: 'pending' for chunk in file_metadata["chunks"]}
        # Storage for downloaded chunk data
        self.received_chunks: Dict[str, bytes] = {}

    def initiate_download(self):
        for chunk_hash in self.metadata["chunks"]:
            threading.Thread(target=self.request_chunk, args=(chunk_hash,), daemon=True).start()

    def request_chunk(self, chunk_hash: str):
        if not self.peers:
            print("No peers available to request chunk from.")
            return

        # Use simple round-robin: choose the first peer
        target = self.peers[0]
        request_msg = {
            "version": 1,
            "type": "CHUNK_REQUEST",
            "sender_id": "my_peer_id",
            "payload": {
                "file_hash": self.metadata["file_hash"],
                "chunk_hash": chunk_hash
            }
        }
        self.net_comm.send_message(target, request_msg)
        self.chunk_status[chunk_hash] = "downloading"
        print(f"Requested chunk {chunk_hash} from {target}")

    def handle_chunk_response(self, chunk_hash: str, chunk_data: bytes):
        if compute_hash(chunk_data) == chunk_hash:
            print(f"Chunk {chunk_hash} verified and stored.")
            self.chunk_status[chunk_hash] = "complete"
            self.received_chunks[chunk_hash] = chunk_data
            if all(status == "complete" for status in self.chunk_status.values()):
                self.assemble_file()
        else:
            print(f"Chunk {chunk_hash} verification failed. Retrying...")
            self.chunk_status[chunk_hash] = "pending"
            self.request_chunk(chunk_hash)

    def assemble_file(self):
        file_data = b''.join(self.received_chunks[ch] for ch in self.metadata["chunks"])
        file_name = f"downloaded_{self.metadata.get('file_name', 'file')}"
        with open(file_name, "wb") as f:
            f.write(file_data)
        print(f"File assembled and saved as {file_name}")

class TransferManager:
    """
    Handles uploads and downloads of file chunks.
    """
    def __init__(self, net_comm: NetworkCommunication, file_index: FileIndex):
        self.net_comm = net_comm
        self.file_index = file_index
        self.active_downloads: Dict[str, DownloadSession] = {}
        # Register this module’s transfer handler
        self.net_comm.set_message_callback(self._handle_transfer_message)

    def start_download(self, file_metadata: dict, peer_list: List[Tuple[str, int]]):
        download_session = DownloadSession(file_metadata, peer_list, self.net_comm)
        self.active_downloads[file_metadata["file_hash"]] = download_session
        download_session.initiate_download()
        return download_session

    def _handle_transfer_message(self, message: dict, addr: Tuple[str, int]):
        msg_type = message.get("type")
        if msg_type == "CHUNK_REQUEST":
            self._handle_chunk_request(message, addr)
        elif msg_type == "CHUNK_RESPONSE":
            self._handle_chunk_response(message, addr)
        # Other transfer messages can be added here

    def _handle_chunk_request(self, message: dict, addr: Tuple[str, int]):
        payload = message.get("payload", {})
        file_hash = payload.get("file_hash")
        requested_chunk = payload.get("chunk_hash")
        print(f"Received CHUNK_REQUEST for chunk {requested_chunk} for file {file_hash} from {addr}")

        metadata = self.file_index.get_file_metadata(file_hash)
        if not metadata:
            print(f"File with hash {file_hash} not found in local index.")
            return

        # Find the chunk index corresponding to the requested chunk hash
        try:
            chunk_index = metadata["chunks"].index(requested_chunk)
        except ValueError:
            print(f"Requested chunk {requested_chunk} not found in file {metadata['file_name']}.")
            return

        # Read the requested chunk data from disk
        try:
            with open(metadata["file_path"], "rb") as f:
                f.seek(chunk_index * metadata["chunk_size"])
                chunk_data = f.read(metadata["chunk_size"])
            # Prepare the response message (serialize binary using latin1)
            response = {
                "version": 1,
                "type": "CHUNK_RESPONSE",
                "sender_id": "my_peer_id",
                "payload": {
                    "file_hash": file_hash,
                    "chunk_hash": requested_chunk,
                    "chunk_data": chunk_data.decode('latin1')
                }
            }
            self.net_comm.send_message(addr, response)
            print(f"Sent chunk {requested_chunk} data to {addr}")
        except Exception as e:
            print(f"Error reading chunk data: {e}")

    def _handle_chunk_response(self, message: dict, addr: Tuple[str, int]):
        payload = message.get("payload", {})
        file_hash = payload.get("file_hash")
        chunk_hash = payload.get("chunk_hash")
        chunk_data = payload.get("chunk_data").encode('latin1')
        print(f"Received CHUNK_RESPONSE for chunk {chunk_hash} from {addr}")
        if file_hash in self.active_downloads:
            self.active_downloads[file_hash].handle_chunk_response(chunk_hash, chunk_data)

# -------------------------------
# Main Bootstrapping and Execution
# -------------------------------

if __name__ == "__main__":
    import sys

    # Let the user optionally pass a port number (default 9000)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT

    # Initialize the network module with the chosen port
    net_comm = NetworkCommunication(listen_port=port)

    # Specify bootstrap nodes
    # For instance, if the first instance is on port 9000 and a second is started on port 9001,
    # have the second instance bootstrap off the peer on port 9000.
    bootstrap_nodes = [("127.0.0.1", 9000)]
    peer_discovery = PeerDiscovery(net_comm, bootstrap_nodes=bootstrap_nodes)

    # Build the file index
    file_index = FileIndex(shared_folder=SHARED_FOLDER, chunk_size=CHUNK_SIZE)

    # Create TransferManager with file_index lookup
    transfer_manager = TransferManager(net_comm, file_index)

    # Start a download demo (only if this instance is not the bootstrap with actual shared files)
    query = "example"
    results = file_index.search_metadata(query)
    if results:
        metadata = results[0]
        print(f"Found file {metadata['file_name']} with hash {metadata['file_hash']}")
        # Here, assume the bootstrap peer (port 9000) has the file,
        # so if this instance is on a different port, we simulate the download from port 9000.
        if port != 9000:
            peer_list = [("127.0.0.1", 9000)]
            transfer_manager.start_download(metadata, peer_list)
    else:
        print(f"No files found matching '{query}' in {SHARED_FOLDER}.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down...")
        net_comm.close()
