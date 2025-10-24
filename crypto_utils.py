import os
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
 
 
class CryptoHandler:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.aes_key = None
        
    def generate_rsa_keys(self):
        """Generate RSA key pair for key exchange"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print("[+] RSA key pair generated successfully")
        
    def get_public_key_bytes(self):
        """Serialize public key to bytes for transmission"""
        if self.public_key is None:
            raise ValueError("Public key not generated")
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def load_peer_public_key(self, key_bytes):
        """Load peer's public key from bytes"""
        self.peer_public_key = serialization.load_pem_public_key(
            key_bytes,
            backend=default_backend()
        )
        print("[+] Peer public key loaded successfully")
        
    def generate_aes_key(self):
        """Generate a random AES-256 key"""
        self.aes_key = secrets.token_bytes(32)
        print("[+] AES-256 key generated")
        return self.aes_key
    
    def encrypt_aes_key_with_rsa(self, aes_key):
        """Encrypt AES key using peer's RSA public key"""
        if self.peer_public_key is None:
            raise ValueError("Peer public key not loaded")
        encrypted_key = self.peer_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key
    
    def decrypt_aes_key_with_rsa(self, encrypted_key):
        """Decrypt AES key using own RSA private key"""
        if self.private_key is None:
            raise ValueError("Private key not generated")
        self.aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("[+] AES key decrypted successfully")
        return self.aes_key
    
    def encrypt_message(self, message):
        """Encrypt message using AES-256 in GCM mode"""
        if self.aes_key is None:
            raise ValueError("AES key not set")
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        iv = os.urandom(12)
        
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(message) + encryptor.finalize()
        
        return iv + encryptor.tag + ciphertext
    
    def decrypt_message(self, encrypted_data):
        """Decrypt message using AES-256 in GCM mode"""
        if self.aes_key is None:
            raise ValueError("AES key not set")
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode('utf-8')
 
 
def print_separator(title=""):
    """Print a formatted separator for console output"""
    print("\n" + "="*60)
    if title:
        print(f"  {title}")
        print("="*60)
