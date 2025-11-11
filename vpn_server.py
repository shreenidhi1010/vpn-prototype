import socket
import threading
import sys
from crypto_utils import print_separator

class VPNServer:
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}  # {client_socket: (address, public_key)}

    def start(self):
        """Start VPN server and accept multiple clients"""
        print_separator("VPN SERVER STARTING")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"[+] Server listening on {self.host}:{self.port}")
            print("[*] Waiting for clients to connect...\n")

            while True:
                client_socket, client_addr = self.server_socket.accept()
                print_separator(f"NEW CLIENT CONNECTED - {client_addr}")

                thread = threading.Thread(
                    target=self.handle_client, args=(client_socket, client_addr)
                )
                thread.daemon = True
                thread.start()

        except OSError as e:
            print(f"[!] Server error: {e}")
        finally:
            self.shutdown()

    def handle_client(self, client_socket, client_addr):
        """Handle client registration and encrypted message routing"""
        try:
            # Step 1: Receive client's public key
            client_public_key = client_socket.recv(4096)
            self.clients[client_socket] = (client_addr, client_public_key)
            print(f"[+] Registered {client_addr} with public key")

            # Step 2: Send all other clients' public keys
            for sock, (addr, pubkey) in self.clients.items():
                if sock != client_socket:
                    client_socket.send(len(pubkey).to_bytes(4, 'big'))
                    client_socket.send(pubkey)

            # Step 3: Notify others about the new client
            for sock in self.clients:
                if sock != client_socket:
                    sock.send(b'NEW_CLIENT')
                    sock.send(len(client_public_key).to_bytes(4, 'big'))
                    sock.send(client_public_key)

            # Step 4: Forward encrypted messages (server never decrypts)
            while True:
                length_bytes = client_socket.recv(4)
                if not length_bytes:
                    break

                msg_len = int.from_bytes(length_bytes, 'big')
                encrypted_message = client_socket.recv(msg_len)

                # Relay message to all other clients
                for sock in self.clients:
                    if sock != client_socket:
                        sock.send(length_bytes)
                        sock.send(encrypted_message)

        except Exception as e:
            print(f"[!] Error handling {client_addr}: {e}")
        finally:
            print(f"[-] Disconnecting {client_addr}")
            del self.clients[client_socket]
            client_socket.close()

    def shutdown(self):
        """Shutdown the server"""
        for c in self.clients.keys():
            c.close()
        if self.server_socket:
            self.server_socket.close()
        print("[+] Server shutdown complete")
        sys.exit(0)


if __name__ == "__main__":
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║         VPN PROTOTYPE - END-TO-END ENCRYPTION SERVER       ║
    ║   Routes Encrypted Packets Without Reading Their Content   ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    host = input("Enter host (press Enter for 0.0.0.0): ").strip() or "0.0.0.0"
    port_input = input("Enter port (press Enter for 8000): ").strip()
    port = int(port_input) if port_input else 8000

    server = VPNServer(host=host, port=port)
    server.start()

