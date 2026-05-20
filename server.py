"""
SecureVault — Server
=====================
Run in Terminal 1:   python3 server.py

Flow:
  1. CA initialised (creates ca_root.json on first run)
  2. Server generates its own ElGamal key pair + gets cert from CA
  3. Listens on 127.0.0.1:6000
  4. Per client:
       a. Mutual certificate exchange & verification
       b. ECDH P-256 key exchange → Twofish key + RC4 key
       c. Receive encrypted messages → decrypt → display → send ACK
       d. Log everything to messages_log.json
"""

import sys, os, socket, json, struct, random
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.ca      import CertificateAuthority
from crypto.elgamal import ElGamal
from crypto.ecdh_kdf import ECDHParty, kdf_derive
from crypto.twofish import SimplifiedTwofish
from crypto.rc4     import RC4
from crypto.md5     import md5_hex

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
def hdr(m):   print(f"\n{BLU}{'─'*4} {BOLD}{m}{R} {BLU}{'─'*(60-len(m))}{R}")

# ── Socket helpers ────────────────────────────────────────────────────────────

def _send(sock: socket.socket, data: dict):
    """Length-prefix framed JSON send."""
    raw = json.dumps(data).encode('utf-8')
    sock.sendall(struct.pack('>I', len(raw)) + raw)


def _recv(sock: socket.socket) -> dict:
    """Length-prefix framed JSON receive."""
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

# ── JSON log helper ───────────────────────────────────────────────────────────

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


def _decrypt_message(packet: dict, twofish_key: bytes, rc4_key: bytes,
                     server_eg: ElGamal) -> bytes:
    """Verify integrity, unwrap keys via ElGamal, peel RC4 → Twofish."""
    rc4_ct = bytes.fromhex(packet['ciphertext'])
    # Integrity check
    if md5_hex(rc4_ct) != packet['integrity']:
        raise ValueError("INTEGRITY CHECK FAILED — packet tampered!")
    # ElGamal key unwrap
    c1, c2 = int(packet['eg_c1']), int(packet['eg_c2'])
    bundle  = server_eg.decrypt((c1, c2))
    bnd_bytes = bundle.to_bytes(32, 'big')
    rec_tf  = bnd_bytes[:16]
    rec_rc4 = bnd_bytes[16:]
    # Decrypt layers
    after_rc4 = RC4(rec_rc4).decrypt(rc4_ct)
    plaintext  = SimplifiedTwofish(rec_tf).decrypt(after_rc4)
    return plaintext

# ── Per-client handler ────────────────────────────────────────────────────────

def handle_client(conn: socket.socket, addr, ca: CertificateAuthority,
                  server_eg: ElGamal, server_cert: dict):
    print(f"\n{GRN}{'═'*66}{R}")
    print(f"  Client connected from {addr[0]}:{addr[1]}")

    try:
        # ── Step 1: Certificate exchange ──────────────────────────────────
        hdr("Step 1 — Certificate Exchange")
        _send(conn, {'type': 'SERVER_CERT', 'cert': server_cert})
        info("Server certificate sent to client.")

        msg = _recv(conn)
        if msg['type'] != 'CLIENT_CERT':
            raise ValueError("Expected CLIENT_CERT")
        client_cert = msg['cert']
        info(f"Received certificate for '{client_cert['subject']}'")

        if CertificateAuthority.verify_certificate(client_cert):
            ok("Client certificate VALID — signed by SecureVault-RootCA")
            _send(conn, {'type': 'CERT_OK'})
        else:
            fail("Client certificate INVALID — rejecting connection")
            _send(conn, {'type': 'CERT_FAIL'})
            return

        ack = _recv(conn)
        if ack.get('type') != 'CERT_OK':
            fail("Server cert rejected by client")
            return
        ok("Client confirmed server certificate as VALID")

        # ── Step 2: ECDH key exchange ─────────────────────────────────────
        hdr("Step 2 — ECDH P-256 Key Exchange")
        server_ecdh = ECDHParty()
        info(f"Server ECDH pub x: {hex(server_ecdh.public_key[0])[:50]}…")

        _send(conn, {
            'type':  'ECDH_PUB',
            'pub_x': str(server_ecdh.public_key[0]),
            'pub_y': str(server_ecdh.public_key[1]),
        })

        ecdh_msg = _recv(conn)
        client_pub = (int(ecdh_msg['pub_x']), int(ecdh_msg['pub_y']))
        info(f"Client ECDH pub x: {hex(client_pub[0])[:50]}…")

        key_material  = kdf_derive(server_ecdh.shared_x_bytes(client_pub),
                                   key_len=32,
                                   salt=b"SecureVault-Session-Salt",
                                   info=b"server-client-session")
        twofish_key = key_material[:16]
        rc4_key     = key_material[16:]
        ok(f"Session keys derived — Twofish: {twofish_key.hex()[:16]}…  RC4: {rc4_key.hex()[:16]}…")

        # ── Step 3: Messaging loop ────────────────────────────────────────
        hdr("Step 3 — Secure Messaging (Ctrl-C to stop server)")
        client_eg_pub = client_cert['elgamal_pub']

        msg_count = 0
        while True:
            pkt = _recv(conn)

            if pkt.get('type') == 'DISCONNECT':
                print(f"\n  Client disconnected cleanly.")
                break

            if pkt.get('type') != 'MSG':
                continue

            msg_count += 1
            hdr(f"Message #{msg_count} received")

            # Decrypt
            plaintext = _decrypt_message(pkt['payload'], twofish_key, rc4_key, server_eg)
            decoded   = plaintext.decode('utf-8', errors='replace')
            ok(f"Integrity: PASSED")
            print(f"\n  {BLU}Client says:{R}  {YEL}{decoded}{R}\n")

            # Log
            _log({
                'timestamp':          datetime.now(timezone.utc).isoformat(),
                'direction':          'client → server',
                'client':             client_cert['subject'],
                'original_message':   decoded,
                'before_decryption': {
                    'ciphertext_hex': pkt['payload']['ciphertext'],
                    'integrity_tag':  pkt['payload']['integrity'],
                },
                'after_decryption': {
                    'recovered_message': decoded,
                },
            })

            # Send encrypted ACK
            ack_text = f"[Server] Message #{msg_count} received securely. ✓"
            ack_pkt  = _encrypt_message(
                ack_text.encode('utf-8'),
                twofish_key, rc4_key, client_eg_pub
            )
            _send(conn, {'type': 'ACK', 'payload': ack_pkt})
            info(f"Encrypted ACK sent to client.")

    except ConnectionError:
        print(f"  {YEL}Client disconnected.{R}")
    except Exception as e:
        print(f"  {RED}Error: {e}{R}")
    finally:
        conn.close()

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{CYN}{'═'*66}")
    print(f"  SecureVault Server")
    print(f"{'═'*66}{R}\n")

    # 1. Initialise CA
    hdr("Initialising Certificate Authority")
    ca = CertificateAuthority(bits=256)

    # 2. Generate server key pair + certificate
    hdr("Generating Server Keys & Certificate")
    print("  [Server] Generating ElGamal key pair…")
    server_eg   = ElGamal(bits=256)
    server_cert = ca.issue_certificate('SecureVault-Server', server_eg.public_key)
    ok(f"Server certificate issued by {server_cert['issuer']}")

    # 3. Listen
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(5)
        print(f"\n{GRN}  ✓ Server listening on {HOST}:{PORT}{R}")
        print(f"  {DIM}Start the client in another terminal: python3 client.py{R}\n")

        while True:
            conn, addr = srv.accept()
            handle_client(conn, addr, ca, server_eg, server_cert)


if __name__ == '__main__':
    main()
