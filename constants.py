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
HEARTBEAT_INTERVAL = 10

# This will store the session token globally once the user logs in

# ---------------------------
# Server Configs
# ---------------------------

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 6000
