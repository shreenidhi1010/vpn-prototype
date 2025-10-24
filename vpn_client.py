import socket
import threading
import sys
from crypto_utils import CryptoHandler, print_separator


class VPNServer:
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = []
        
    def start(self):
        """Start the VPN server"""
        print_separator("VPN SERVER STARTING")
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"[+] Server listening on {self.host}:{self.port}")
            print("[+] Waiting for client connections...")
            print_separator()
            
            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"\n[+] New connection from {client_address}")
                
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                self.clients.append(client_socket)
                
        except KeyboardInterrupt:
            print("\n[!] Server shutting down...")
            self.shutdown()
        except Exception as e:
            print(f"[!] Server error: {e}")
            self.shutdown()
    
    def handle_client(self, client_socket, client_address):
        """Handle individual client connection"""
        client_crypto = CryptoHandler()
        
        try:
            print_separator(f"SECURE TUNNEL ESTABLISHMENT - {client_address}")
            
            client_crypto.generate_rsa_keys()
            
            client_public_key = client_socket.recv(4096)
            client_crypto.load_peer_public_key(client_public_key)
            print(f"[+] Received public key from {client_address}")
            
            server_public_key = client_crypto.get_public_key_bytes()
            client_socket.send(server_public_key)
            print(f"[+] Sent public key to {client_address}")
            
            aes_key = client_crypto.generate_aes_key()
            encrypted_aes_key = client_crypto.encrypt_aes_key_with_rsa(aes_key)
            
            key_length = len(encrypted_aes_key).to_bytes(4, byteorder='big')
            client_socket.send(key_length)
            client_socket.send(encrypted_aes_key)
            print(f"[+] Sent encrypted AES key to {client_address}")
            
            ack = client_socket.recv(1024)
            if ack == b'ACK':
                print("[+] Secure tunnel established successfully!")
                print_separator()
                print(f"\n[*] Ready to receive encrypted messages from {client_address}")
                print("[*] Type your messages below (or 'quit' to disconnect):\n")
                
                receive_thread = threading.Thread(
                    target=self.receive_messages,
                    args=(client_socket, client_address, client_crypto)
                )
                receive_thread.daemon = True
                receive_thread.start()
                
                self.send_messages(client_socket, client_address, client_crypto)
            else:
                print("[!] Failed to establish secure tunnel")
                client_socket.close()
                
        except Exception as e:
            print(f"[!] Error handling client {client_address}: {e}")
            client_socket.close()
    
    def receive_messages(self, client_socket, client_address, client_crypto):
        """Receive and decrypt messages from client"""
        while True:
            try:
                length_bytes = client_socket.recv(4)
                if not length_bytes:
                    break
                    
                message_length = int.from_bytes(length_bytes, byteorder='big')
                encrypted_message = b''
                
                while len(encrypted_message) < message_length:
                    chunk = client_socket.recv(min(4096, message_length - len(encrypted_message)))
                    if not chunk:
                        break
                    encrypted_message += chunk
                
                if encrypted_message:
                    decrypted_message = client_crypto.decrypt_message(encrypted_message)
                    print(f"\n[Client {client_address}] {decrypted_message}")
                    print("[Server] ", end='', flush=True)
                    
            except Exception as e:
                print(f"\n[!] Error receiving message from {client_address}: {e}")
                break
    
    def send_messages(self, client_socket, client_address, client_crypto):
        """Send encrypted messages to client"""
        while True:
            try:
                message = input(f"[Server to {client_address}] ")
                
                if message.lower() == 'quit':
                    print(f"[!] Disconnecting from {client_address}...")
                    client_socket.close()
                    break
                
                if message:
                    encrypted_message = client_crypto.encrypt_message(message)
                    
                    message_length = len(encrypted_message).to_bytes(4, byteorder='big')
                    client_socket.send(message_length)
                    client_socket.send(encrypted_message)
                    
            except Exception as e:
                print(f"[!] Error sending message to {client_address}: {e}")
                break
    
    def shutdown(self):
        """Shutdown the server"""
        for client in self.clients:
            try:
                client.close()
            except:
                pass
        
        if self.server_socket:
            self.server_socket.close()
        
        print("[+] Server shutdown complete")
        sys.exit(0)


if __name__ == "__main__":
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║          VPN PROTOTYPE - SECURE TUNNEL SERVER              ║
    ║    Demonstrating RSA Key Exchange & AES-256 Encryption     ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    
    server = VPNServer()
    server.start()
