import socket
import threading
import sys
from crypto_utils import CryptoHandler, print_separator


class VPNClient:
    def __init__(self, server_host='localhost', server_port=8000):
        self.server_host = server_host
        self.server_port = server_port
        self.client_socket = None
        self.crypto = CryptoHandler()
        
    def connect(self):
        """Connect to the VPN server and establish secure tunnel"""
        print_separator("VPN CLIENT STARTING")
        
        self.crypto.generate_rsa_keys()
        
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_host, self.server_port))
            print(f"[+] Connected to server at {self.server_host}:{self.server_port}")
            
            print_separator("SECURE TUNNEL ESTABLISHMENT")
            
            client_public_key = self.crypto.get_public_key_bytes()
            self.client_socket.send(client_public_key)
            print("[+] Sent public key to server")
            
            server_public_key = self.client_socket.recv(4096)
            self.crypto.load_peer_public_key(server_public_key)
            print("[+] Received public key from server")
            
            key_length_bytes = self.client_socket.recv(4)
            key_length = int.from_bytes(key_length_bytes, byteorder='big')
            
            encrypted_aes_key = b''
            while len(encrypted_aes_key) < key_length:
                chunk = self.client_socket.recv(min(4096, key_length - len(encrypted_aes_key)))
                if not chunk:
                    break
                encrypted_aes_key += chunk
            
            print("[+] Received encrypted AES key from server")
            
            self.crypto.decrypt_aes_key_with_rsa(encrypted_aes_key)
            
            self.client_socket.send(b'ACK')
            print("[+] Secure tunnel established successfully!")
            print_separator()
            print("\n[*] You can now send encrypted messages to the server")
            print("[*] Type your messages below (or 'quit' to disconnect):\n")
            
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            self.send_messages()
            
        except ConnectionRefusedError:
            print(f"[!] Connection refused. Is the server running at {self.server_host}:{self.server_port}?")
        except Exception as e:
            print(f"[!] Connection error: {e}")
        finally:
            self.disconnect()
    
    def receive_messages(self):
        """Receive and decrypt messages from server"""
        while True:
            try:
                if self.client_socket is None:
                    break
                length_bytes = self.client_socket.recv(4)
                if not length_bytes:
                    break
                
                message_length = int.from_bytes(length_bytes, byteorder='big')
                encrypted_message = b''
                
                while len(encrypted_message) < message_length:
                    chunk = self.client_socket.recv(min(4096, message_length - len(encrypted_message)))
                    if not chunk:
                        break
                    encrypted_message += chunk
                
                if encrypted_message:
                    decrypted_message = self.crypto.decrypt_message(encrypted_message)
                    print(f"\n[Server] {decrypted_message}")
                    print("[Client] ", end='', flush=True)
                    
            except Exception as e:
                print(f"\n[!] Error receiving message: {e}")
                break
    
    def send_messages(self):
        """Send encrypted messages to server"""
        while True:
            try:
                message = input("[Client] ")
                
                if message.lower() == 'quit':
                    print("[!] Disconnecting from server...")
                    break
                
                if message and self.client_socket is not None:
                    encrypted_message = self.crypto.encrypt_message(message)
                    
                    message_length = len(encrypted_message).to_bytes(4, byteorder='big')
                    self.client_socket.send(message_length)
                    self.client_socket.send(encrypted_message)
                    
            except Exception as e:
                print(f"[!] Error sending message: {e}")
                break
    
    def disconnect(self):
        """Disconnect from the server"""
        if self.client_socket:
            self.client_socket.close()
        print("[+] Disconnected from server")
        sys.exit(0)


if __name__ == "__main__":
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║          VPN PROTOTYPE - SECURE TUNNEL CLIENT              ║
    ║    Demonstrating RSA Key Exchange & AES-256 Encryption     ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    
    print("\n[*] Enter server details:")
    host = input("Server host (press Enter for localhost): ").strip() or "localhost"
    port_input = input("Server port (press Enter for 8000): ").strip()
    port = int(port_input) if port_input else 8000
    
    client = VPNClient(server_host=host, server_port=port)
    client.connect()
