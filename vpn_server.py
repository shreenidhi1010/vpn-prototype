# vpn_server.py
import socket
import threading
import struct
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

HOST = '0.0.0.0'
PORT = 8000

# helpers for length-prefixed messaging
def recv_exact(conn, n):
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def recv_msg(conn):
    hdr = recv_exact(conn, 4)
    if not hdr:
        return None
    length = int.from_bytes(hdr, byteorder='big')
    return recv_exact(conn, length)

def send_msg(conn, payload: bytes):
    conn.sendall(len(payload).to_bytes(4, byteorder='big') + payload)

# derive AES-256 key from ECDH shared secret using HKDF-SHA256
def derive_aes_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'vpn-ecdh-session',
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

# AES-GCM encrypt/decrypt helpers
def aes_gcm_encrypt(aes_key: bytes, plaintext: bytes):
    iv = os.urandom(12)  # 96-bit nonce recommended for GCM
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return iv, ct, tag

def aes_gcm_decrypt(aes_key: bytes, iv: bytes, ct: bytes, tag: bytes):
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    return pt

class ClientSession:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.aes_key = None  # derived per-session
        # ephemeral ECDH private key for the server side of this session
        self.ec_private = None

    def close(self):
        try:
            self.conn.close()
        except:
            pass

def handle_client(conn, addr):
    sess = ClientSession(conn, addr)
    try:
        print(f"[+] Connection from {addr}")

        # 1) Server creates ephemeral EC key pair and sends its public bytes
        sess.ec_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
        server_pub = sess.ec_private.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        # send server pub length-prefixed
        send_msg(conn, server_pub)
        # 2) Receive client's ephemeral public key
        client_pub_bytes = recv_msg(conn)
        if client_pub_bytes is None:
            print("[!] Handshake failed: no client public key")
            return

        # load client public key
        client_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), client_pub_bytes)

        # 3) Compute shared secret and derive AES key (PFS)
        shared_secret = sess.ec_private.exchange(ec.ECDH(), client_pubkey)
        sess.aes_key = derive_aes_key(shared_secret)
        print("[+] Ephemeral ECDH handshake complete — AES session key derived (PFS)")

        # Acknowledge handshake
        send_msg(conn, b'OK')

        # Now exchange encrypted messages: expect length-prefixed frames
        while True:
            raw = recv_msg(conn)
            if raw is None:
                break
            # message format: iv (12) | tag (16) | ciphertext (rest)
            if len(raw) < 28:
                print("[!] Received malformed encrypted frame")
                continue
            iv = raw[:12]
            tag = raw[12:28]
            ct = raw[28:]
            try:
                pt = aes_gcm_decrypt(sess.aes_key, iv, ct, tag)
                print(f"[{addr}] {pt.decode(errors='replace')}")
                # Example: server can optionally reply (encrypt with same session key)
                reply_text = f"Server ACK: received {len(pt)} bytes"
                iv_r, ct_r, tag_r = aes_gcm_encrypt(sess.aes_key, reply_text.encode())
                send_msg(conn, iv_r + tag_r + ct_r)
            except Exception as e:
                print(f"[!] Decrypt error for {addr}: {e}")
                # do not reveal details to client
                continue

    except Exception as e:
        print(f"[!] Exception in client handler {addr}: {e}")
    finally:
        print(f"[-] Closing {addr}")
        sess.close()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(8)
    print(f"[+] ECDH-PFS VPN server listening on {HOST}:{PORT}")
    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[+] Server shutting down")
    finally:
        s.close()
        sys.exit(0)

if __name__ == "__main__":
    main()


