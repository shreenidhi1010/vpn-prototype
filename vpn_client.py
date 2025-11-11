# vpn_client.py
import socket, json, struct, base64, threading, sys, os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

HOST = '127.0.0.1'
PORT = 8000

def recv_msg(conn):
    hdr = conn.recv(4)
    if not hdr:
        return None
    length = struct.unpack('>I', hdr)[0]
    data = b''
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data

def send_msg(conn, data_bytes):
    conn.sendall(struct.pack('>I', len(data_bytes)) + data_bytes)

class E2EEClient:
    def __init__(self, client_id):
        self.id = client_id
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.pub = self.priv.public_key()
        self.known_pubs = {}  # id -> public key object

    def pub_pem_b64(self):
        pem = self.pub.public_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return base64.b64encode(pem).decode()

    def start(self, host=HOST, port=PORT):
        self.sock.connect((host, port))
        reg = {"type":"register", "id": self.id, "pub_key": self.pub_pem_b64()}
        send_msg(self.sock, json.dumps(reg).encode())
        threading.Thread(target=self._recv_loop, daemon=True).start()

    def _recv_loop(self):
        while True:
            raw = recv_msg(self.sock)
            if raw is None:
                break
            msg = json.loads(raw.decode())
            typ = msg.get('type')
            if typ == 'registered':
                print("[*] Registered with relay server.")
            elif typ == 'list':
                print("[*] Clients:", msg.get('clients'))
            elif typ == 'pubkey':
                other = msg['id']
                pem_b64 = msg['pub_key']
                pem = base64.b64decode(pem_b64)
                pubk = serialization.load_pem_public_key(pem, backend=default_backend())
                self.known_pubs[other] = pubk
                print(f"[*] Got public key for {other}")
            elif typ == 'deliver':
                frm = msg['from']
                payload_b64 = msg['payload']
                inner = json.loads(base64.b64decode(payload_b64).decode())
                enc_key = base64.b64decode(inner['enc_key'])
                iv = base64.b64decode(inner['iv'])
                tag = base64.b64decode(inner['tag'])
                ct = base64.b64decode(inner['ciphertext'])
                # decrypt AES key
                aes_key = self.priv.decrypt(enc_key,
                                           padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(), label=None))
                # AES-GCM decrypt
                decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
                plaintext = decryptor.update(ct) + decryptor.finalize()
                print(f"\n[{frm}] {plaintext.decode()}\n[You] ", end='', flush=True)
            elif typ == 'error':
                print("[ERROR]", msg.get('error'))
            elif typ == 'sent':
                print("[*] Message forwarded by server.")
            else:
                print("[*] Unknown server msg:", msg)

    def request_pub(self, other_id):
        send_msg(self.sock, json.dumps({"type":"get_pub", "id": other_id}).encode())

    def list_clients(self):
        send_msg(self.sock, json.dumps({"type":"list"}).encode())

    def send_to(self, to_id, plaintext):
        if to_id not in self.known_pubs:
            self.request_pub(to_id)
            print("[*] Requested recipient public key. Try again after you receive it.")
            return
        recipient_pub = self.known_pubs[to_id]
        aes_key = os.urandom(32)   # AES-256
        iv = os.urandom(12)        # GCM nonce
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
        ct = encryptor.update(plaintext.encode()) + encryptor.finalize()
        tag = encryptor.tag
        enc_key = recipient_pub.encrypt(aes_key,
                                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(), label=None))
        inner = {
            "enc_key": base64.b64encode(enc_key).decode(),
            "iv": base64.b64encode(iv).decode(),
            "tag": base64.b64encode(tag).decode(),
            "ciphertext": base64.b64encode(ct).decode()
        }
        payload_b64 = base64.b64encode(json.dumps(inner).encode()).decode()
        send_msg(self.sock, json.dumps({"type":"send","to": to_id, "from": self.id, "payload": payload_b64}).encode())

if __name__ == "__main__":
    cid = input("Enter client id: ").strip()
    c = E2EEClient(cid)
    c.start()
    print("Commands: /list, /get <id>, /send <id> <message>, /quit")
    while True:
        try:
            cmd = input("[You] ").strip()
            if not cmd:
                continue
            if cmd == "/list":
                c.list_clients()
            elif cmd.startswith("/get "):
                _, other = cmd.split(maxsplit=1)
                c.request_pub(other)
            elif cmd.startswith("/send "):
                parts = cmd.split(maxsplit=2)
                if len(parts) < 3:
                    print("Usage: /send <id> <message>")
                    continue
                _, to_id, msg = parts
                c.send_to(to_id, msg)
            elif cmd in ("/quit", "/exit"):
                break
            else:
                print("Unknown command.")
        except KeyboardInterrupt:
            break
    print("Exiting.")
    sys.exit(0)
