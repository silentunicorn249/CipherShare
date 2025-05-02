# ---------------------------
# Configuration & Global Variables
# ---------------------------
BUFFER_SIZE = 4096  # bytes per chunk
SHARED_FILES_DIR = "./shared_files"  # directory where files to share are stored
DOWNLOAD_DIR = "./downloads"  # directory where downloaded files are saved
FILE_CHUNK_SIZE = 64 * 1024

# Discovery server configuration
DISCOVERY_SERVER_IP = "127.0.0.1"  # Adjust as needed
DISCOVERY_SERVER_PORT = 6000

# Heartbeat interval (in seconds)
HEARTBEAT_INTERVAL = 90

# This will store the session token globally once the user logs in

# ---------------------------
# Server Configs
# ---------------------------

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 6000


# --- Security Configuration ---
NODE_PRIVATE_KEY_FILE = "node_private.pem"
NODE_PUBLIC_KEY_FILE = "node_public.pem"
SERVER_PUBLIC_KEY_FILE = "server_public.pem"  # Path to server's public key
KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537
SERVER_PRIVATE_KEY_FILE = "server_private.pem"
