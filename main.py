# ---------------------------
# CLI Interface Module
# ---------------------------
import argparse
import socket

from node import *


def cli_loop(node: P2PNode):
    help_message = (
        "\nAvailable commands:\n"
        "  list_local                                - List files in your shared folder\n"
        "  list_peer <username>                      - List files available at a peer\n"
        "  list_active                               - List active peers from discovery server\n"
        "  search <filename>                         - Search for a file across peers\n"
        "  download <username> <filename>            - Download a file from a peer\n"
        "  disable_file <filename>                   - Disable sharing a file locally\n"
        "  enable_file <filename>                    - Enable sharing a file locally\n"
        "  restrict_file <filename> <ip1,ip2,...>    - Restrict a file to specific nodes\n"
        "  unrestrict_file <filename>                - Remove restrictions on a file\n"
        "  exit                                      - Exit the application\n"
    )
    print(help_message)
    while True:
        try:
            user_input = input(">> ").strip()
            if not user_input:
                continue
            parts = user_input.split()
            cmd = parts[0].lower()

            if cmd == "list_local":
                files = node.list_local_shared_files()
                print("Local shared files:", files)

            elif cmd == "list_peer" and len(parts) == 2:
                username = parts[1]
                files = node.get_peer_file_list(username)
                if files is not None:
                    print(f"Files at {username}:", files)
                else:
                    print("Could not retrieve file list from the peer.")

            elif cmd == "list_active":
                peers = node.get_active_peers()
                if peers:
                    print("Active peers (from discovery):")
                    print(peers)
                    for username, (ip, port, token) in peers.items():
                        print(f"  {username}:{token} -> {ip}:{port}")
                else:
                    print("No active peers found.")

            elif cmd == "search" and len(parts) == 2:
                filename = parts[1]
                peers = node.search_file_discovery(filename)
                if peers:
                    print(f"Peers with '{filename}':", peers)
                else:
                    print(f"No peers found with '{filename}'.")

            elif cmd == "download" and len(parts) == 3:
                username = parts[1]
                filename = parts[2]
                node.download_file_from_peer(username, filename)

            elif cmd == "disable_file" and len(parts) == 2:
                filename = parts[1]
                node.disable_file(filename)
                print(f"File '{filename}' disabled from sharing.")

            elif cmd == "enable_file" and len(parts) == 2:
                filename = parts[1]
                if node.enable_file(filename):
                    print(f"File '{filename}' enabled for sharing.")
                else:
                    print(f"File '{filename}' is not disabled.")

            elif cmd == "restrict_file" and len(parts) == 3:
                filename = parts[1]
                allowed_ips = parts[2].split(",")
                node.restrict_file(filename, allowed_ips)
                print(f"File '{filename}' restricted to nodes: {', '.join(allowed_ips)}")

            elif cmd == "unrestrict_file" and len(parts) == 2:
                filename = parts[1]
                if node.unrestrict_file(filename):
                    print(f"Restrictions removed for file '{filename}'.")
                else:
                    print(f"No restrictions exist for file '{filename}'.")

            elif cmd == "exit":
                print("Exiting CLI...")
                node.running = False
                node.peer_socket.close()
                break

            else:
                print("Unknown command. Available commands:")
                print(help_message)
        except KeyboardInterrupt:
            print("\nExiting...")
            node.running = False
            node.peer_socket.close()
            break


def authentication_loop(p2p_node: P2PNode, ip, port):
    help_message = (
        "\nAvailable commands:\n"
        " Register                  - register <username> <password>\n"
        " Login                     - login <username> <password>\n"
        " exit - Exit the application\n"
    )
    print(help_message)
    while True:
        try:
            user_input = input(">> ").strip()
            if not user_input:
                continue
            parts = user_input.split()
            cmd = parts[0].lower()
            if cmd == "register" and len(parts) == 3:
                username = parts[1]
                password = parts[2]
                if p2p_node.register_user(username, password, ip, port):
                    print(f"User '{username}' registered successfully.")
                    return True
                    # break

            elif cmd == "login" and len(parts) == 3:
                username = parts[1]
                password = parts[2]
                if p2p_node.login_user(username, password):
                    print(f"User '{username}' logged in successfully.")
                    return True
                    # break

            elif cmd == "exit":
                print("Exiting CLI...")
                p2p_node.running = False
                p2p_node.peer_socket.close()
                return False
                # break
            else:
                print("Unknown command. Available commands:")
                print(help_message)
        except KeyboardInterrupt:
            print("\nExiting...")
            p2p_node.running = False
            p2p_node.peer_socket.close()
            break
        except Exception as e:
            print(f"[ERROR] {e}")


# ---------------------------
# Main Entry Point
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="P2P File Sharing Node with Discovery & Heartbeat")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on for P2P connections")
    args = parser.parse_args()

    p2p_node = P2PNode(port=args.port)
    p2p_node.start_server()

    # Determine the own IP address
    try:
        own_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        own_ip = "127.0.0.1"

    # Initial registration with the discovery server

    # register_with_discovery(own_ip, args.port)

    if authentication_loop(p2p_node, own_ip, args.port):
        print("[INFO] Peer node started and registered with discovery server.")
        cli_loop(p2p_node)


if __name__ == "__main__":
    main()
