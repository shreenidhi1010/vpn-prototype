import socket
import threading
import sys
from crypto_utils import CryptoHandler, print_separator


class VPNServer:
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = []  # Track connected clients

    def start(self):
        """Start VPN server and accept multiple clients"""
        print_separator("VPN SERVER STARTING")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # Reuse the same port after a crash
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"[+] Server listening on {self.host}:{self.port}")
            print("[*] Waiting for clients to connect...\n")

            while True:
                client_socket, client_addr = self.server_socket.accept()
                print_separator(f"SECURE TUNNEL ESTABLISHMENT - {client_addr}")

                # Spawn a thread to handle each client independently
                client_thread = threading.Thread(
                    target=self.handle_client, args=(client_socket, client_addr)
                )
                client_thread.daemon = True
                client_thread.start()
                self.clients.append(client_socket)

        except OSError as e:
            print(f"[!] Server error: {e}")
        except KeyboardInterrupt:
            print("\n[!] Server shutting down...")
        finally:
            self.shutdown()

    def handle_client(self, client_socket, client_addr):
        """Handle communication with one client"""
        crypto = CryptoHandler()

        try:
            # Generate RSA key pair for this client session
            crypto.generate_rsa_keys()

            # Receive client's public key
            client_public_key = client_socket.recv(4096)
            crypto.load_peer_public_key(client_public_key)
            print(f"[+] Received client's public key from {client_addr}")

            # Send server's public key
            client_socket.send(crypto.get_public_key_bytes())
            print(f"[+] Sent server public key to {client_addr}")

            # Generate AES key and send to client encrypted with RSA
            crypto.generate_aes_key()
            encrypted_aes_key = crypto.encrypt_aes_key_with_rsa()
            client_socket.send(len(encrypted_aes_key).to_bytes(4, byteorder='big'))
            client_socket.send(encrypted_aes_key)
            print(f"[+] Sent encrypted AES key to {client_addr}")

            # Wait for acknowledgment
            ack = client_socket.recv(1024)
            if ack == b'ACK':
                print(f"[+] Secure tunnel established with {client_addr}")
                print("[*] You can now exchange encrypted messages.\n")

            # Start message loop
            while True:
                length_bytes = client_socket.recv(4)
                if not length_bytes:
                    break

                message_length = int.from_bytes(length_bytes, byteorder='big')
                encrypted_message = client_socket.recv(message_length)
                decrypted_message = crypto.decrypt_message(encrypted_message)
                print(f"[Client {client_addr}] {decrypted_message}")

                # Echo message back to client
                reply = f"Server received: {decrypted_message}"
                encrypted_reply = crypto.encrypt_message(reply)
                reply_length = len(encrypted_reply).to_bytes(4, byteorder='big')
                client_socket.send(reply_length)
                client_socket.send(encrypted_reply)

        except Exception as e:
            print(f"[!] Error handling client {client_addr}: {e}")
        finally:
            print(f"[-] Closing connection with {client_addr}")
            client_socket.close()

    def shutdown(self):
        """Shutdown the server"""
        for c in self.clients:
            c.close()
        if self.server_socket:
            self.server_socket.close()
        print("[+] Server shutdown complete")
        sys.exit(0)


if __name__ == "__main__":
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║             VPN PROTOTYPE - MULTI-CLIENT SERVER            ║
    ║    Demonstrating RSA Key Exchange & AES-256 Encryption     ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    host = input("Enter host (press Enter for 0.0.0.0): ").strip() or "0.0.0.0"
    port_input = input("Enter port (press Enter for 8000): ").strip()
    port = int(port_input) if port_input else 8000

    server = VPNServer(host=host, port=port)
    server.start()
