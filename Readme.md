
---

# Decentralized P2P File Sharing Platform

## Overview

**CipherShare** is a decentralized P2P file sharing platform that ensures secure and resilient file exchange between peers. The system was designed with modularity and scalability in mind, enabling easy integration of future features such as authentication, encryption, and GUI-based interaction.

This version of the project implements a decentralized peer discovery mechanism. Peers attempt to register with a centralized discovery server (by default on port 6000) but automatically fall back to a decentralized model if the discovery server is unavailable. In the decentralized mode, each node maintains its own neighbor list and uses controlled flooding (broadcast messages with TTL and unique identifiers) to search for files and peer information.

## Project Specifications

- **Project Title:**  
  CipherShare: A Secure Distributed File Sharing Platform with User-Centric Credential Management

- **Key Features (Phase 1 + Decentralized Discovery):**
  - **Basic P2P File Sharing:**  
    Peers can list, download, and share files (stored in a local folder).
  - **Centralized Discovery Fallback:**  
    On startup, a node attempts to register with a discovery server (default IP: 127.0.0.1, port: 6000). If unavailable, the node prompts for an alternate peer to bootstrap the network.
  - **Decentralized Peer Discovery:**  
    - **Broadcast Search:** Searches for a file across the network by flooding broadcast messages with a TTL.
    - **Discover Neighbors:** Nodes can query their neighbors (using a new `DISCOVER` command) to receive additional neighbor lists and merge them into their own.
  - **Modular and Extensible Design:**  
    The project abstracts core functionalities like P2P networking, broadcast discovery, and file I/O, making it easy to integrate new features (e.g., authentication, encryption, or GUI modules) in future phases.

- **Technology Stack:**
  - **Programming Language:** Python 3
  - **Networking:** TCP sockets (Python’s `socket` module)
  - **Concurrency:** Threads (Python’s `threading` module)
  - **File I/O:** Local file system operations for file sharing
  - **Utilities:** UUID for message identification; basic locking to ensure thread safety

## Installation & Setup

### Prerequisites

- Python 3.7 or higher
- Git (optional, if you plan to clone the repository)

### Steps to Initialize and Run in a Virtual Environment

1. **Clone the Repository (if using Git):**

   ```bash
   git clone https://github.com/silentunicorn249/CipherShare.git
   cd ciphershare
   ```

2. **Create a Python Virtual Environment:**

   On Linux/macOS:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

   On Windows:
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```


3. **Project Directory Structure:**

   ```
   ciphershare/
   ├── shared_files/              # Directory where shared files are stored
   ├── discovery_server.py        # Centralized discovery server module (optional)
   ├── node.py                # Main P2P node code with decentralized discovery
   ├── README.md                  # This file
   └── requirements.txt           # Optional dependencies file
   ```

4. **Running the Discovery Server (Optional):**

   If you wish to use the discovery server, run it in a separate terminal:
   ```bash
   python discovery_server.py
   ```

5. **Running a P2P Node:**

   To start a node, run the main node script:
   ```bash
   python node.py --port 5000
   ```

   The node will attempt to connect to the discovery server (by default at 127.0.0.1:6000). If the server is unreachable, it will prompt you to enter an alternate node address.

6. **Using the CLI:**

   Once the node is running, you’ll see the CLI prompt. Available commands include:
   - **list_local** – List local shared files.
   - **list_peer \<ip> \<port>** – Get the file list from a specific peer.
   - **add_neighbor \<ip> \<port>** – Manually add a neighbor.
   - **discover** – Query known neighbors for their neighbor lists.
   - **bcast_search \<filename>** – Broadcast a search for a file.
   - **download \<ip> \<port> \<filename>** – Download a file from a peer.
   - **exit** – Exit the application.

## Future Enhancements

- **Authentication & Secure Credential Management:**  
  In upcoming phases, we plan to integrate robust user authentication mechanisms (e.g., secure password hashing, challenge-response protocols) to ensure only authorized users access the network.

- **File Encryption & Integrity Verification:**  
  Subsequent versions will encrypt files prior to transmission and verify file integrity using cryptographic hash functions (e.g., SHA-256).

- **GUI Integration:**  
  While the current interface is CLI-based, the modular design allows for a future GUI to be built on top of the core P2P network libraries.

- **Advanced Peer Discovery Protocols:**  
  Consider integrating more efficient decentralized protocols (e.g., a Distributed Hash Table or gossip-based protocols) for scaling the network.

## Support

For any questions or issues, please open an issue on the repository.

---

This README provides a comprehensive guide to the project, ensuring that users and developers can easily set up, run, and understand the platform's current capabilities and planned enhancements.
