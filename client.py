"""
SecureVault — Client
=====================
Run in Terminal 2 (AFTER server.py is running):   python3 client.py

Flow:
  1. Loads CA root key from ca_root.json (created by server.py)
  2. Generates its own ElGamal key pair + gets cert from CA
  3. Connects to server on 127.0.0.1:6000
  4. Mutual certificate exchange & verification
  5. ECDH P-256 key exchange → Twofish key + RC4 key
  6. Interactive loop: type a message → encrypted → server decrypts → ACK
  7. All messages logged to messages_log.json
"""

import sys, os, socket, json, struct
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.ca       import CertificateAuthority
from crypto.elgamal  import ElGamal
from crypto.ecdh_kdf import ECDHParty, kdf_derive
from crypto.twofish  import SimplifiedTwofish
from crypto.rc4      import RC4
from crypto.md5      import md5_hex

HOST     = '127.0.0.1'
PORT     = 6000
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'messages_log.json')

# ── Terminal colours ──────────────────────────────────────────────────────────
R = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
RED = "\033[91m"; GRN = "\033[92m"; YEL = "\033[93m"
BLU = "\033[94m"; CYN = "\033[96m"; MAG = "\033[95m"

def _c(t, c): return f"{c}{t}{R}"
def ok(m):    print(f"  {_c('✓', GRN)}  {m}")
def fail(m):  print(f"  {_c('✗', RED)}  {m}")
def info(m):  print(f"  {_c('ℹ', CYN)}  {DIM}{m}{R}")
def hdr(m):   print(f"\n{MAG}{'─'*4} {BOLD}{m}{R} {MAG}{'─'*(60-len(m))}{R}")

# ── Socket helpers ────────────────────────────────────────────────────────────

def _send(sock: socket.socket, data: dict):
    raw = json.dumps(data).encode('utf-8')
    sock.sendall(struct.pack('>I', len(raw)) + raw)


def _recv(sock: socket.socket) -> dict:
    def exact(n):
        buf = b''
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed")
            buf += chunk
        return buf
    length = struct.unpack('>I', exact(4))[0]
    return json.loads(exact(length).decode('utf-8'))

# ── JSON log ──────────────────────────────────────────────────────────────────

def _log(entry: dict):
    records = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as fh:
                records = json.load(fh)
        except json.JSONDecodeError:
            pass
    records.append(entry)
    with open(LOG_FILE, 'w') as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)

# ── Crypto helpers ────────────────────────────────────────────────────────────

def _encrypt_message(plaintext: bytes, twofish_key: bytes, rc4_key: bytes,
                     recipient_elgamal_pub: dict) -> dict:
    """Twofish → RC4 → MD5 tag → ElGamal key-wrap."""
    tf_ct  = SimplifiedTwofish(twofish_key).encrypt(plaintext)
    rc4_ct = RC4(rc4_key).encrypt(tf_ct)
    tag    = md5_hex(rc4_ct)

    p = int(recipient_elgamal_pub['p'])
    g = int(recipient_elgamal_pub['g'])
    y = int(recipient_elgamal_pub['y'])
    bundle = int.from_bytes(twofish_key + rc4_key, 'big') % p
    eg_pub = ElGamal.from_keys(p=p, g=g, y=y)
    c1, c2 = eg_pub.encrypt(bundle)

    return {
        'ciphertext': rc4_ct.hex(),
        'integrity':  tag,
        'eg_c1':      str(c1),
        'eg_c2':      str(c2),
    }


def _decrypt_message(packet: dict, client_eg: ElGamal) -> bytes:
    """Verify integrity, unwrap keys via ElGamal, peel RC4 → Twofish."""
    rc4_ct = bytes.fromhex(packet['ciphertext'])
    if md5_hex(rc4_ct) != packet['integrity']:
        raise ValueError("INTEGRITY CHECK FAILED — response tampered!")
    c1, c2    = int(packet['eg_c1']), int(packet['eg_c2'])
    bundle     = client_eg.decrypt((c1, c2))
    bnd_bytes  = bundle.to_bytes(32, 'big')
    rec_tf     = bnd_bytes[:16]
    rec_rc4    = bnd_bytes[16:]
    after_rc4  = RC4(rec_rc4).decrypt(rc4_ct)
    return SimplifiedTwofish(rec_tf).decrypt(after_rc4)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{MAG}{'═'*66}")
    print(f"  SecureVault Client")
    print(f"{'═'*66}{R}\n")

    # 1. Load CA (must exist — run server.py first)
    hdr("Loading Certificate Authority")
    if not os.path.exists(os.path.join(os.path.dirname(__file__), 'ca_root.json')):
        print(f"  {RED}ca_root.json not found — start server.py first!{R}")
        sys.exit(1)
    ca = CertificateAuthority(bits=256)

    # 2. Generate client ElGamal key + certificate
    hdr("Generating Client Keys & Certificate")
    print("  [Client] Generating ElGamal key pair…")
    client_eg   = ElGamal(bits=256)
    client_cert = ca.issue_certificate('SecureVault-Client', client_eg.public_key)
    ok(f"Client certificate issued by {client_cert['issuer']}")

    # 3. Connect
    hdr(f"Connecting to Server {HOST}:{PORT}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
    except ConnectionRefusedError:
        print(f"  {RED}Cannot connect — is server.py running?{R}")
        sys.exit(1)
    ok(f"Connected to {HOST}:{PORT}")

    try:
        # ── Step 1: Certificate exchange ──────────────────────────────────
        hdr("Step 1 — Certificate Exchange")

        msg = _recv(sock)
        if msg['type'] != 'SERVER_CERT':
            raise ValueError("Expected SERVER_CERT")
        server_cert = msg['cert']
        info(f"Received certificate for '{server_cert['subject']}'")

        if CertificateAuthority.verify_certificate(server_cert):
            ok("Server certificate VALID — signed by SecureVault-RootCA")
            _send(sock, {'type': 'CLIENT_CERT', 'cert': client_cert})
        else:
            fail("Server certificate INVALID — aborting")
            _send(sock, {'type': 'CERT_FAIL'})
            return

        ack = _recv(sock)
        if ack.get('type') != 'CERT_OK':
            fail("Server rejected client certificate — aborting")
            return
        ok("Server confirmed client certificate as VALID")
        _send(sock, {'type': 'CERT_OK'})

        # ── Step 2: ECDH key exchange ─────────────────────────────────────
        hdr("Step 2 — ECDH P-256 Key Exchange")
        client_ecdh = ECDHParty()
        info(f"Client ECDH pub x: {hex(client_ecdh.public_key[0])[:50]}…")

        srv_ecdh = _recv(sock)
        server_pub = (int(srv_ecdh['pub_x']), int(srv_ecdh['pub_y']))
        info(f"Server ECDH pub x: {hex(server_pub[0])[:50]}…")

        _send(sock, {
            'type':  'ECDH_PUB',
            'pub_x': str(client_ecdh.public_key[0]),
            'pub_y': str(client_ecdh.public_key[1]),
        })

        key_material = kdf_derive(client_ecdh.shared_x_bytes(server_pub),
                                  key_len=32,
                                  salt=b"SecureVault-Session-Salt",
                                  info=b"server-client-session")
        twofish_key = key_material[:16]
        rc4_key     = key_material[16:]
        ok(f"Session keys derived — Twofish: {twofish_key.hex()[:16]}…  RC4: {rc4_key.hex()[:16]}…")

        server_eg_pub = server_cert['elgamal_pub']

        # ── Step 3: Interactive messaging ─────────────────────────────────
        hdr("Step 3 — Secure Chat  (type 'quit' to exit)")
        print(f"  {DIM}Messages are encrypted with Twofish + RC4, integrity by MD5,")
        print(f"  keys wrapped with ElGamal, identity verified by CA.{R}\n")

        msg_count = 0
        while True:
            try:
                text = input(f"{YEL}  You › {R}").strip()
            except (EOFError, KeyboardInterrupt):
                text = 'quit'

            if text.lower() == 'quit':
                _send(sock, {'type': 'DISCONNECT'})
                print(f"\n  {DIM}Disconnected.{R}")
                break

            if not text:
                continue

            msg_count += 1

            # Encrypt & send
            payload = _encrypt_message(
                text.encode('utf-8'),
                twofish_key, rc4_key, server_eg_pub
            )
            _send(sock, {'type': 'MSG', 'payload': payload})
            info(f"Encrypted & sent  |  ciphertext: {payload['ciphertext'][:32]}…")
            info(f"Integrity tag: {payload['integrity']}")

            # Log sent message
            _log({
                'timestamp':        datetime.now(timezone.utc).isoformat(),
                'direction':        'client → server',
                'original_message': text,
                'before_decryption': {
                    'ciphertext_hex': payload['ciphertext'],
                    'integrity_tag':  payload['integrity'],
                },
                'after_decryption': {
                    'recovered_message': text,   # client side knows it
                },
            })

            # Receive & decrypt ACK
            ack = _recv(sock)
            if ack.get('type') == 'ACK':
                response = _decrypt_message(ack['payload'], client_eg)
                decoded  = response.decode('utf-8', errors='replace')
                print(f"  {GRN}Server › {R}{decoded}\n")

    except ConnectionError:
        print(f"\n  {RED}Server connection lost.{R}")
    except Exception as e:
        print(f"\n  {RED}Error: {e}{R}")
        import traceback; traceback.print_exc()
    finally:
        sock.close()


if __name__ == '__main__':
    main()
