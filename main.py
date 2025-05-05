# ---------------------------
# CLI Interface Module
# ---------------------------
import argparse
import sys

# Make sure node.py is in the same directory or Python path
from node import P2PNode


# --- Authentication Loop ---
def authentication_loop(p2p_node: P2PNode) -> bool:
    """Handles user registration or login before entering the main CLI."""
    print("\n--- P2P File Sharing Node ---")
    print("Welcome! Please register or login.")
    help_message = (
        "\nAuthentication Commands:\n"
        "  register <username> <password>   - Create a new account\n"
        "  login    <username> <password>   - Log in to an existing account\n"
        "  exit                             - Exit the application\n"
    )
    print(help_message)

    while True:
        try:
            user_input = input("auth> ").strip()
            if not user_input:
                continue

            parts = user_input.split()
            cmd = parts[0].lower()

            if cmd == "register" and len(parts) == 3:
                username = parts[1]
                password = parts[2]
                if p2p_node.register_user(username, password):
                    print(f"\nUser '{username}' registered successfully.")
                    return True  # Proceed to main CLI

            elif cmd == "login" and len(parts) == 3:
                username = parts[1]
                password = parts[2]
                if p2p_node.login_user(username, password):
                    print(f"\nUser '{username}' logged in successfully.")
                    return True  # Proceed to main CLI

            elif cmd == "exit":
                print("Exiting application...")
                p2p_node.shutdown()  # Gracefully shutdown node
                return False  # Do not proceed to main CLI

            else:
                print("Unknown command or incorrect usage.")
                print(help_message)

        except (KeyboardInterrupt, EOFError):
            print("\nExiting application...")
            p2p_node.shutdown()
            return False
        except Exception as e:
            print(f"[AUTH ERROR] An unexpected error occurred: {e}")
            # Decide whether to continue or exit based on error severity
            # For now, just print and continue the loop


# --- Main CLI Loop (Refactored) ---
def main_cli(node: P2PNode):
    """Command-line interface for the P2P Node after authentication."""
    print("\n--- Main Menu ---")
    help_message = (
        "\nAvailable commands:\n"
        "  list_local                                - List files in your shared folder\n"
        "  list_peer <username>                      - List files available at a peer\n"
        "  updatepeers                               - Force refresh of the active peer list\n"
        "  list_active                               - List active peers from discovery server\n"
        "  search <filename>                         - Search for a file across peers\n"
        "  download <username> <filename>            - Download a file from a peer\n"
        "  disable_file <filename>                   - Disable sharing a file locally\n"
        "  enable_file <filename>                    - Enable sharing a file locally\n"
        "  restrict_file <filename> <ip1,ip2,...>    - Restrict a file to specific nodes\n"
        "  unrestrict_file <filename>                - Remove restrictions on a file\n"
        "  help                                      - Show this help message\n"
        "  logout                                    - Log out from the discovery server\n"
        "  exit                                      - Exit the application\n"
    )
    print(help_message)

    while node.running:  # Check node status
        try:
            user_input = input(">> ").strip()
            if not user_input:
                continue

            parts = user_input.split()
            command = parts[0].lower()

            # --- Command Handling ---
            if command == "exit":
                print("Exiting application...")
                node.shutdown()  # Handles logout and cleanup
                break  # Exit CLI loop

            elif command == "logout":
                if node.logout_user():
                    print("Successfully logged out.")
                    # After logout, should probably exit or go back to auth loop?
                    # For now, exit the app.
                    node.shutdown()  # Ensure full cleanup
                    break
                else:
                    print("Logout failed or already logged out.")
                    # Consider if node should still be running here

            elif command == "help":
                print(help_message)

            # --- Commands requiring login ---
            elif not node.session_token:
                print("Please login first to use this command.")
                # Optionally, break or return to auth loop here
                continue

            elif command == "list_local":  # List local shared files
                files = node.list_local_shared_files()
                if files:
                    print("Locally shared files (enabled):")
                    for f in files: print(f" - {f}")
                else:
                    print("No files currently shared or available in shared directory.")

            elif command == "list_active":  # List known peers
                with node.peers_lock:  # Access peer list safely
                    if node.peers:
                        print(node.peers)
                        print("Known active peers:")
                        for uname, (ip, port, key_pem) in node.peers.items():
                            key_status = "Yes" if key_pem else "No"
                            print(f" - {uname} @ {ip}:{port} (Pub Key: {key_status})")
                    else:
                        print("No other active peers known. Try 'updatepeers'.")

            elif command == "updatepeers":  # Force update peer list
                if node.update_peer_list_from_server():
                    print("Peer list updated.")
                    # Optionally list peers after update:
                    # main_cli("peers") # Be careful with direct calls
                else:
                    print("Failed to update peer list from server.")

            elif command == "search":
                if len(parts) == 2:
                    filename = parts[1]
                    # search_file_discovery returns List[Tuple[str, int]] -> [(ip, port), ...]
                    results_locations = node.search_file_discovery(filename)
                    if results_locations:
                        print(f"Peers with file '{filename}':")
                        found_users = []
                        with node.peers_lock:  # Access peer list safely
                            # Map locations back to usernames
                            for res_ip, res_port in results_locations:
                                found = False
                                for uname, (p_ip, p_port, _) in node.peers.items():
                                    if p_ip == res_ip and p_port == res_port:
                                        found_users.append(uname)
                                        found = True
                                        break  # Found user for this ip/port
                                if not found:
                                    # If IP/Port from search doesn't match a known peer
                                    found_users.append(f"Unknown ({res_ip}:{res_port})")

                        if found_users:
                            for user_info in found_users: print(f" - {user_info}")
                        # else: search_file_discovery prints "not found"
                    # else: search_file_discovery prints "not found" or error
                else:
                    print("Usage: search <filename>")

            elif command == "download":  # Download file
                if len(parts) == 3:
                    username = parts[1]
                    filename = parts[2]
                    node.download_file_from_peer(username, filename)  # Handles printing success/failure
                else:
                    print("Usage: get <username> <filename>")

            elif command == "enable_file":
                if len(parts) == 2:
                    filename = parts[1]
                    if node.enable_file(filename):
                        print(f"File '{filename}' enabled for sharing.")
                    # else: enable_file prints messages for failure/already enabled
                else:
                    print("Usage: enable <filename>")

            elif command == "disable_file":
                if len(parts) == 2:
                    filename = parts[1]
                    if node.disable_file(filename):
                        print(f"File '{filename}' disabled from sharing.")
                    # else: disable_file prints message for failure
                else:
                    print("Usage: disable <filename>")

            elif command == "restrict_file":
                if len(parts) >= 3:
                    filename = parts[1]
                    # Join remaining parts in case IPs contain spaces, then split by comma
                    ips_str = "".join(parts[2:])
                    ips = [ip.strip() for ip in ips_str.split(',') if ip.strip()]
                    if ips:
                        if node.restrict_file(filename, ips):
                            print(f"File '{filename}' restricted successfully.")
                        # else: restrict_file prints error messages
                    else:
                        print("Usage: restrict <filename> <ip1,ip2,...> (Provide at least one IP)")
                else:
                    print("Usage: restrict <filename> <ip1,ip2,...>")

            elif command == "unrestrict_file":
                if len(parts) == 2:
                    filename = parts[1]
                    if node.unrestrict_file(filename):
                        print(f"Restrictions removed for file '{filename}'.")
                    # else: unrestrict_file prints message if not restricted
                else:
                    print("Usage: unrestrict <filename>")

            else:
                print(f"Unknown command: '{command}'. Type 'help' for available commands.")

        except (KeyboardInterrupt, EOFError):
            print("\nCaught Ctrl+C / Ctrl+D. Exiting...")
            node.shutdown()  # Gracefully shutdown
            break  # Exit CLI loop
        except Exception as e:
            print(f"\n[CLI ERROR] An unexpected error occurred: {type(e).__name__} - {e}")
            # Log the error, maybe print traceback for debugging
            import traceback
            traceback.print_exc()
            # Decide whether to continue or exit based on error severity
            # For now, just print and continue the loop


# ---------------------------
# Main Entry Point
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="P2P File Sharing Node with Discovery & Heartbeat")
    # Allow specifying listen host and port
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="Host address to bind the listening socket (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on for P2P connections (default: 5000)")
    args = parser.parse_args()

    # --- Node Initialization ---
    try:
        p2p_node = P2PNode(host=args.host, port=args.port)
        # p2p_node.start_server() is called within P2PNode.__init__ now
        if not p2p_node.running:
            print("[ERROR] Failed to initialize P2P Node. Exiting.")
            sys.exit(1)

    except Exception as init_e:
        print(f"[FATAL ERROR] Could not initialize P2P Node: {init_e}")
        sys.exit(1)
    # --- End Node Initialization ---

    # --- Authentication and Main Loop ---
    try:
        # Run authentication loop first
        if authentication_loop(p2p_node):
            # If authentication succeeded, run the main command loop
            main_cli(p2p_node)
        # If authentication_loop returns False (e.g., user chose exit), main ends here.

    except Exception as main_e:
        print(f"[FATAL ERROR] An error occurred in the main execution: {main_e}")
        p2p_node.shutdown()  # Attempt graceful shutdown
        sys.exit(1)

    print("\nApplication finished.")


if __name__ == "__main__":
    main()
