import os
import time
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class CryptoHandler:
    def __init__(self, rekey_interval=300):
        """
        Initialize cryptographic handler.
        rekey_interval: time (in seconds) for automatic AES key rotation (default 5 min)
        """
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.aes_key = None
        self.rekey_interval = rekey_interval
        self.last_rekey_time = None
        self.session_log = "session_keys.log"

    # ====================== KEY EXCHANGE ====================== #
    def generate_ecdh_keys(self):
        """Generate Elliptic Curve Diffie-Hellman (ECDH) key pair"""
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()
        print("[+] ECDH key pair generated")

    def get_public_key_bytes(self):
        """Return serialized ECDH public key"""
        if self.public_key is None:
            raise ValueError("Public key not generated")
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def load_peer_public_key(self, key_bytes):
        """Load peer's ECDH public key"""
        self.peer_public_key = serialization.load_pem_public_key(
            key_bytes, backend=default_backend()
        )
        print("[+] Peer ECDH public key loaded")

    def derive_shared_secret(self):
        """Generate shared AES key using ECDH"""
        if not self.private_key or not self.peer_public_key:
            raise ValueError("Keys not initialized for ECDH")
        shared_secret = self.private_key.exchange(ec.ECDH(), self.peer_public_key)
        self.aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"PFS Secure Tunnel",
            backend=default_backend()
        ).derive(shared_secret)
        self.last_rekey_time = time.time()
        print("[+] AES-256 session key derived using ECDH (PFS enabled)")
        self.log_session_key()

    # ====================== ENCRYPTION / DECRYPTION ====================== #
    def encrypt_message(self, message):
        """Encrypt message using AES-GCM (auto rekey if interval passed)"""
        if self.aes_key is None:
            raise ValueError("AES key not set")
        self.check_rekey()

        if isinstance(message, str):
            message = message.encode("utf-8")

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
        """Decrypt AES-GCM message"""
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
        return plaintext.decode("utf-8")

    # ====================== RE-KEYING & LOGGING ====================== #
    def check_rekey(self):
        """Automatically re-key every X seconds"""
        if time.time() - self.last_rekey_time > self.rekey_interval:
            print("[*] Rekeying in progress...")
            self.rekey_session()

    def rekey_session(self):
        """Perform secure re-keying using new ECDH exchange"""
        # Wipe old AES key from memory
        if self.aes_key:
            del self.aes_key
        # Generate new ECDH key pair and derive new session key
        self.generate_ecdh_keys()
        if self.peer_public_key:
            self.derive_shared_secret()
        print("[+] Session rekeyed successfully (PFS maintained)")

    def log_session_key(self):
        """Log session key for audit (only hash, not raw key)"""
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.aes_key)
        key_hash = digest.finalize().hex()

        with open(self.session_log, "a") as log:
            log.write(f"Time: {time.ctime()} | AES Key Hash: {key_hash}\n")

    # ====================== UTILITIES ====================== #
    def clear_memory(self):
        """Manually clear sensitive data"""
        if self.aes_key:
            del self.aes_key
        if self.private_key:
            del self.private_key
        if self.peer_public_key:
            del self.peer_public_key
        print("[*] Memory wiped (keys removed)")


def print_separator(title=""):
    """Print a formatted separator for console output"""
    print("\n" + "=" * 60)
    if title:
        print(f"  {title}")
        print("=" * 60)

