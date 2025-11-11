# vpn_client.py
import socket
import struct
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import threading

HOST = '127.0.0.1'
PORT = 8000

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

def derive_aes_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'vpn-ecdh-session',
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

def aes_gcm_encrypt(aes_key: bytes, plaintext: bytes):
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return iv, ct, tag

def aes_gcm_decrypt(aes_key: bytes, iv: bytes, ct: bytes, tag: bytes):
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    return pt

def client_run():
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((HOST, PORT))
    try:
        # 1) Receive server ephemeral public key
        server_pub_bytes = recv_msg(conn)
        if server_pub_bytes is None:
            print("[!] Failed to receive server public key")
            return

        server_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), server_pub_bytes)

        # 2) Create client ephemeral keypair and send public bytes
        client_priv = ec.generate_private_key(ec.SECP384R1(), default_backend())
        client_pub = client_priv.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        send_msg(conn, client_pub)

        # 3) Derive shared secret & AES key
        shared_secret = client_priv.exchange(ec.ECDH(), server_pubkey)
        aes_key = derive_aes_key(shared_secret)
        print("[+] Ephemeral ECDH handshake complete — AES session key derived (PFS)")

        # Wait for server OK
        ok = recv_msg(conn)
        if ok != b'OK':
            print("[!] Server handshake not OK")
            return

        # Start receiver thread
        def recv_loop():
            while True:
                raw = recv_msg(conn)
                if raw is None:
                    break
                if len(raw) < 28:
                    print("[!] Malformed encrypted frame")
                    continue
                iv = raw[:12]
                tag = raw[12:28]
                ct = raw[28:]
                try:
                    pt = aes_gcm_decrypt(aes_key, iv, ct, tag)
                    print(f"\n[Server] {pt.decode(errors='replace')}\n[You] ", end='', flush=True)
                except Exception as e:
                    print(f"\n[!] Decrypt error: {e}")

        threading.Thread(target=recv_loop, daemon=True).start()

        print("[*] Secure channel established. Type messages (or 'quit').")
        while True:
            msg = input("[You] ")
            if msg.lower() == 'quit':
                break
            iv, ct, tag = aes_gcm_encrypt(aes_key, msg.encode())
            send_msg(conn, iv + tag + ct)

    finally:
        conn.close()
        print("[+] Client disconnected")

if __name__ == "__main__":
    client_run()

