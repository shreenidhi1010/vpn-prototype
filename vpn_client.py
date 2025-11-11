# vpn_client_rekey.py
import socket, struct, json, time, os, sys, threading, gc
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

SERVER = '127.0.0.1'
PORT = 8000
# NOTE: client rekey interval not used here because server initiates rekey;
# client may also request rekey via control message if desired.

def send_frame(conn, mtype: bytes, payload: bytes):
    conn.sendall(mtype + struct.pack('>I', len(payload)) + payload)

def recv_frame(conn):
    hdr = conn.recv(1)
    if not hdr:
        return None, None
    mtype = hdr
    length_bytes = conn.recv(4)
    if not length_bytes:
        return None, None
    length = struct.unpack('>I', length_bytes)[0]
    data = b''
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return mtype, data

def derive_aes_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'vpn-rekey-hkdf', backend=default_backend())
    return hkdf.derive(shared_secret)

def aes_gcm_encrypt(aes_key: bytes, plaintext: bytes):
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return iv, tag, ct

def aes_gcm_decrypt(aes_key: bytes, iv: bytes, tag: bytes, ct: bytes):
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def secure_wipe(b):
    try:
        if isinstance(b, bytearray):
            for i in range(len(b)):
                b[i] = 0
        else:
            b = os.urandom(len(b))
    except:
        pass
    try:
        del b
    except:
        pass
    gc.collect()

def audit_store_key(client_id, key_bytes):
    fname = f"session_keys_{client_id}.log"
    entry = {"ts": int(time.time()), "key_hex": key_bytes.hex()}
    with open(fname, "a") as f:
        f.write(json.dumps(entry) + "\n")

class Client:
    def __init__(self, client_id="client"):
        self.client_id = client_id
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.aes_key = None
        self.ec_private = None
        self.running = True

    def initial_handshake(self):
        # receive server handshake pub
        mtype, payload = recv_frame(self.sock)
        if mtype != b'\x01':
            raise RuntimeError("Expected control frame with server pub")
        msg = json.loads(payload.decode())
        if msg.get("type") != "handshake_pub":
            raise RuntimeError("bad handshake pub")
        server_pub_bytes = bytes.fromhex(msg["pub"])
        server_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), server_pub_bytes)

        # client creates ephemeral key and sends its pub
        self.ec_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
        client_pub = self.ec_private.public_key().public_bytes(encoding=serialization.Encoding.X962,
                                                               format=serialization.PublicFormat.UncompressedPoint)
        ctrl = {"type":"handshake_pub", "pub": client_pub.hex()}
        send_frame(self.sock, b'\x01', json.dumps(ctrl).encode())

        # derive shared key
        shared = self.ec_private.exchange(ec.ECDH(), server_pub)
        new_key = derive_aes_key(shared)
        self.set_aes_key(new_key)
        audit_store_key(self.client_id, new_key)

        # expect ack
        mtype, payload = recv_frame(self.sock)
        if mtype != b'\x01' or json.loads(payload.decode()).get("type") != "handshake_ack":
            raise RuntimeError("handshake ack failed")
        print("[+] Handshake complete, session key derived (PFS)")

    def set_aes_key(self, new_key):
        old = getattr(self, "aes_key", None)
        self.aes_key = new_key
        if old:
            secure_wipe(old)

    def handle_server_frames(self):
        try:
            while True:
                mtype, payload = recv_frame(self.sock)
                if mtype is None:
                    break
                if mtype == b'\x01':
                    msg = json.loads(payload.decode())
                    if msg.get("type") == "rekey_request":
                        # server sends new pub in rekey request: respond with client's pub
                        server_pub_bytes = bytes.fromhex(msg["pub"])
                        server_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), server_pub_bytes)
                        # generate new ephemeral
                        self.ec_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
                        client_pub = self.ec_private.public_key().public_bytes(encoding=serialization.Encoding.X962,
                                                                               format=serialization.PublicFormat.UncompressedPoint)
                        # send rekey_response
                        send_frame(self.sock, b'\x01', json.dumps({"type":"rekey_response", "pub": client_pub.hex()}).encode())
                        # derive new key
                        shared = self.ec_private.exchange(ec.ECDH(), server_pub)
                        new_key = derive_aes_key(shared)
                        self.set_aes_key(new_key)
                        audit_store_key(self.client_id, new_key)
                        # wait for rekey_ack
                        mtype2, payload2 = recv_frame(self.sock)
                        # ignore ack content for now
                        print("[+] Rekey complete (server-initiated). New session key active.")
                    else:
                        # other control messages
                        pass
                elif mtype == b'\x02':
                    if self.aes_key is None:
                        print("[!] no session key")
                        continue
                    if len(payload) < 28:
                        print("[!] malformed encrypted frame")
                        continue
                    iv = payload[:12]; tag = payload[12:28]; ct = payload[28:]
                    try:
                        pt = aes_gcm_decrypt(self.aes_key, iv, tag, ct)
                        print(f"\n[Server] {pt.decode(errors='replace')}\n[You] ", end='', flush=True)
                    except Exception as e:
                        print(f"[!] decrypt error: {e}")
                else:
                    print("[!] unknown frame type")
        except Exception as e:
            print(f"[!] frame loop error: {e}")
        finally:
            self.running = False

    def run(self, host=SERVER, port=PORT):
        self.sock.connect((host, port))
        self.initial_handshake()
        threading.Thread(target=self.handle_server_frames, daemon=True).start()

        try:
            while self.running:
                msg = input("[You] ")
                if msg.lower() in ("quit","exit"):
                    break
                if self.aes_key is None:
                    print("[!] no session key, cannot send")
                    continue
                iv, tag, ct = aes_gcm_encrypt(self.aes_key, msg.encode())
                send_frame(self.sock, b'\x02', iv + tag + ct)
        except KeyboardInterrupt:
            pass
        finally:
            print("[+] client exiting")
            try:
                if self.aes_key:
                    secure_wipe(self.aes_key)
            except:
                pass
            try:
                self.sock.close()
            except:
                pass
            sys.exit(0)

if __name__ == "__main__":
    cid = input("Client id (for audit filename): ").strip() or "client"
    c = Client(client_id=cid)
    c.run()


