import socket
import threading
import sys
from crypto_utils import CryptoHandler, print_separator

class VPNServer:
    def __init__(self, host='localhost', port=8000):
        self.host = host
        self.port = port
        self.server_socket = None
        self.crypto = CryptoHandler()
        self.clients = []

    def start(self):
        """Start the VPN server and listen for connections"""
        print_separator("VPN SERVER STARTING")

        # Generate server RSA keys
        self.crypto.generate_rsa_keys()

        # Create socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # ✅ Allow port reuse
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"[+] Server listening on {self.host}:{self.port}")

            while True:
                conn, addr = self.server_socket.accept()
                print_separator(f"SECURE TUNNEL ESTABLISHMENT - {addr}")
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
                self.clients.append(conn)

        except KeyboardInterrupt:
            print("\n[+] Server shutting down gracefully…")
        except Exception as e:
            print(f"[!] Server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
            print("[+] Server shutdown complete")
            sys.exit(0)

    def handle_client(self, conn, addr):
        """Handle a new client connection"""
        try:
            # Receive client public key
            client_pub_key = conn.recv(4096)
            self.crypto.load_peer_public_key(client_pub_key)
            print("[+] Received public key from client")

            # Send server public key
            server_pub_key_bytes = self.crypto.get_public_key_bytes()
            conn.send(server_pub_key_bytes)
            print("[+] Sent public key to client")

            # Generate AES key and send encrypted
            encrypted_aes_key = self.crypto.encrypt_aes_key_with_rsa()
            key_length_bytes = len(encrypted_aes_key).to_bytes(4, 'big')
            conn.send(key_length_bytes + encrypted_aes_key)
            print("[+] Sent encrypted AES key to client")

            # Wait for client ACK
            ack = conn.recv(3)
            if ack == b'ACK':
                print("[+] Secure tunnel established successfully!")

        except Exception as e:
            print(f"[!] Error handling client {addr}: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║          VPN PROTOTYPE - SECURE TUNNEL SERVER              ║
    ║    Demonstrating RSA Key Exchange & AES-256 Encryption     ║
    ╚════════════════════════════════════════════════════════════╝
    """)

    host_input = input("Server host (press Enter for localhost): ").strip()
    port_input = input("Server port (press Enter for 8000): ").strip()
    host = host_input or "localhost"
    port = int(port_input) if port_input else 8000

    server = VPNServer(host=host, port=port)
    server.start()
