# vpn_server_rekey.py
import socket, threading, struct, json, time, os, sys, gc
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

HOST = '0.0.0.0'
PORT = 8000
REKEY_INTERVAL = 300        # seconds (5 minutes). For testing set to e.g. 30

# helpers for framed protocol: 1-byte type + 4-byte length + payload
# type: 0x01 = CONTROL (JSON), 0x02 = ENCRYPTED (binary)

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

def audit_store_key(client_id, key_bytes):
    # WARNING: audit log contains raw session key. Protect this file in production.
    fname = f"session_keys_{client_id}.log"
    entry = {
        "ts": int(time.time()),
        "key_hex": key_bytes.hex()
    }
    with open(fname, "a") as f:
        f.write(json.dumps(entry) + "\n")

def secure_wipe(b):
    # overwrite mutable bytearray if possible, else attempt overwrite via new random bytes
    try:
        if isinstance(b, bytearray):
            for i in range(len(b)):
                b[i] = 0
        else:
            # create dummy var and delete original reference
            dummy = os.urandom(len(b))
            b = dummy
    except Exception:
        pass
    try:
        del b
    except:
        pass
    gc.collect()

class ClientHandler:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.lock = threading.Lock()
        self.aes_key = None
        self.ec_private = None
        self.client_id = f"{addr[0]}_{addr[1]}"
        self.running = True
        self.rekey_timer = None

    def perform_handshake(self):
        # server generates ephemeral ECDH key and sends its public
        self.ec_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
        server_pub = self.ec_private.public_key().public_bytes(encoding=serialization.Encoding.X962,
                                                               format=serialization.PublicFormat.UncompressedPoint)
        # control handshake: send server pub as base64 JSON
        ctrl = {"type":"handshake_pub", "pub": server_pub.hex()}
        send_frame(self.conn, b'\x01', json.dumps(ctrl).encode())

        # receive client's pub control
        mtype, data = recv_frame(self.conn)
        if mtype != b'\x01':
            raise RuntimeError("Expected control frame for client pub")
        msg = json.loads(data.decode())
        if msg.get("type") != "handshake_pub":
            raise RuntimeError("Bad handshake message")
        client_pub_bytes = bytes.fromhex(msg["pub"])
        client_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), client_pub_bytes)

        shared = self.ec_private.exchange(ec.ECDH(), client_pub)
        new_key = derive_aes_key(shared)
        # store key in handler
        self.set_aes_key(new_key)
        audit_store_key(self.client_id, new_key)
        # ack
        send_frame(self.conn, b'\x01', json.dumps({"type":"handshake_ack"}).encode())

    def set_aes_key(self, new_key: bytes):
        with self.lock:
            old = self.aes_key
            self.aes_key = new_key
            # wipe old
            if old:
                secure_wipe(old)

    def start_rekey_timer(self):
        # schedule server-initiated rekey
        def timer_action():
            try:
                self.initiate_rekey()
            except Exception as e:
                print(f"[!] Rekey error for {self.client_id}: {e}")
            finally:
                # reschedule if still running
                if self.running:
                    self.rekey_timer = threading.Timer(REKEY_INTERVAL, timer_action)
                    self.rekey_timer.daemon = True
                    self.rekey_timer.start()
        self.rekey_timer = threading.Timer(REKEY_INTERVAL, timer_action)
        self.rekey_timer.daemon = True
        self.rekey_timer.start()

    def initiate_rekey(self):
        # server sends control: REKEY_REQUEST; server sends its new ephemeral public; client responds with its pub
        print(f"[+] Initiating rekey with {self.client_id}")
        self.ec_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
        server_pub = self.ec_private.public_key().public_bytes(encoding=serialization.Encoding.X962,
                                                               format=serialization.PublicFormat.UncompressedPoint)
        ctrl = {"type":"rekey_request", "pub": server_pub.hex()}
        send_frame(self.conn, b'\x01', json.dumps(ctrl).encode())

        # expect client's rekey_pub
        mtype, data = recv_frame(self.conn)
        if mtype != b'\x01':
            raise RuntimeError("Expected control frame for rekey response")
        msg = json.loads(data.decode())
        if msg.get("type") != "rekey_response":
            raise RuntimeError("Bad rekey response")
        client_pub_bytes = bytes.fromhex(msg["pub"])
        client_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), client_pub_bytes)
        shared = self.ec_private.exchange(ec.ECDH(), client_pub)
        new_key = derive_aes_key(shared)
        self.set_aes_key(new_key)
        audit_store_key(self.client_id, new_key)
        send_frame(self.conn, b'\x01', json.dumps({"type":"rekey_ack"}).encode())
        print(f"[+] Rekey complete with {self.client_id}")

    def handle(self):
        try:
            self.perform_handshake()
            self.start_rekey_timer()
            # main loop: expect control or encrypted frames
            while True:
                mtype, payload = recv_frame(self.conn)
                if mtype is None:
                    break
                if mtype == b'\x01':
                    # control messages (we could handle client-initiated rekey here)
                    msg = json.loads(payload.decode())
                    if msg.get("type") == "client_initiate_rekey":
                        # client wants to rekey; respond by server sending its pub and following same flow
                        self.initiate_rekey()
                elif mtype == b'\x02':
                    # encrypted frame: iv(12)|tag(16)|ct
                    with self.lock:
                        key = self.aes_key
                    if key is None:
                        print("[!] No session key yet for", self.client_id)
                        continue
                    if len(payload) < 28:
                        print("[!] malformed encrypted frame from", self.client_id)
                        continue
                    iv = payload[:12]; tag = payload[12:28]; ct = payload[28:]
                    try:
                        pt = aes_gcm_decrypt(key, iv, tag, ct)
                        print(f"[TUNNEL] {self.client_id} -> server payload: {pt.decode(errors='replace')}")
                        # optional server reply encrypted with same key:
                        reply_text = f"ACK {int(time.time())}"
                        iv_r, tag_r, ct_r = aes_gcm_encrypt(key, reply_text.encode())
                        send_frame(self.conn, b'\x02', iv_r + tag_r + ct_r)
                    except Exception as e:
                        print(f"[!] decrypt error from {self.client_id}: {e}")
                else:
                    print("[!] unknown frame type")
        except Exception as e:
            print(f"[!] client handler error {self.client_id}: {e}")
        finally:
            self.running = False
            if self.rekey_timer:
                self.rekey_timer.cancel()
            if self.aes_key:
                secure_wipe(self.aes_key)
            try:
                self.conn.close()
            except:
                pass
            print(f"[-] connection closed {self.client_id}")

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(8)
    print(f"[+] PFS+Rekey server listening on {HOST}:{PORT} (rekey every {REKEY_INTERVAL}s)")
    try:
        while True:
            conn, addr = s.accept()
            h = ClientHandler(conn, addr)
            t = threading.Thread(target=h.handle, daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[+] shutting down")
    finally:
        s.close()
        sys.exit(0)

if __name__ == "__main__":
    main()



