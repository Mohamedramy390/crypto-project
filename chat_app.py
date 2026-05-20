"""
SecureVault — GUI Chat App
===========================
Beautiful split-screen web interface for client-server communication.
Run: python3 chat_app.py  →  open http://localhost:5001
"""

import sys, os, json
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.ca       import CertificateAuthority
from crypto.elgamal  import ElGamal
from crypto.ecdh_kdf import ECDHParty, kdf_derive
from crypto.twofish  import SimplifiedTwofish
from crypto.rc4      import RC4
from crypto.md5      import md5_hex

app     = Flask(__name__)
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'messages_log.json')
_S      = {}   # global session state


# ── Log helper ────────────────────────────────────────────────────────────────

def _log(entry: dict):
    records = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as f:
                records = json.load(f)
        except json.JSONDecodeError:
            pass
    records.append(entry)
    with open(LOG_FILE, 'w') as f:
        json.dump(records, f, indent=2, ensure_ascii=False)


# ── Crypto helpers ────────────────────────────────────────────────────────────

def _encrypt(plaintext: bytes, tf_key: bytes, rc4_key: bytes,
             recipient_eg_pub: dict) -> dict:
    tf_ct  = SimplifiedTwofish(tf_key).encrypt(plaintext)
    rc4_ct = RC4(rc4_key).encrypt(tf_ct)
    tag    = md5_hex(rc4_ct)
    p = int(recipient_eg_pub['p'])
    g = int(recipient_eg_pub['g'])
    y = int(recipient_eg_pub['y'])
    bundle  = int.from_bytes(tf_key + rc4_key, 'big') % p
    c1, c2  = ElGamal.from_keys(p=p, g=g, y=y).encrypt(bundle)
    return {'ciphertext': rc4_ct.hex(), 'integrity': tag,
            'eg_c1': str(c1), 'eg_c2': str(c2),
            'twofish_ct': tf_ct.hex()}


def _decrypt(packet: dict, eg: ElGamal,
             tf_key: bytes, rc4_key: bytes) -> tuple:
    """
    Returns (plaintext, elgamal_keys_match).
    Decrypts with the known session keys (tf_key, rc4_key).
    Also unwraps the ElGamal bundle to verify it matches — for demonstration.
    """
    rc4_ct = bytes.fromhex(packet['ciphertext'])
    if md5_hex(rc4_ct) != packet['integrity']:
        raise ValueError("Integrity check FAILED — packet tampered!")

    # ── ElGamal key-unwrap (verify only) ──────────────────────────────────
    bundle     = eg.decrypt((int(packet['eg_c1']), int(packet['eg_c2'])))
    bnd        = bundle.to_bytes(32, 'big')
    rec_tf     = bnd[:16]
    rec_rc4    = bnd[16:]
    keys_match = (rec_tf == tf_key and rec_rc4 == rc4_key)

    # ── Decrypt with session keys (always correct) ─────────────────────────
    after_rc4 = RC4(rc4_key).decrypt(rc4_ct)
    plaintext = SimplifiedTwofish(tf_key).decrypt(after_rc4)
    return plaintext, keys_match


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('chat.html')


@app.route('/api/initialize', methods=['POST'])
def initialize():
    """Generate CA, keys, certificates and perform ECDH handshake."""
    global _S

    # 1 — Certificate Authority
    ca = CertificateAuthority(bits=256)

    # 2 — Server identity
    server_eg   = ElGamal(bits=256)
    server_cert = ca.issue_certificate('SecureVault-Server', server_eg.public_key)

    # 3 — Client identity
    client_eg   = ElGamal(bits=256)
    client_cert = ca.issue_certificate('SecureVault-Client', client_eg.public_key)

    # 4 — Verify certs
    sv = CertificateAuthority.verify_certificate(server_cert)
    cv = CertificateAuthority.verify_certificate(client_cert)

    # 5 — ECDH P-256 key exchange
    server_ecdh = ECDHParty()
    client_ecdh = ECDHParty()
    sx_srv = server_ecdh.shared_x_bytes(client_ecdh.public_key)
    sx_cli = client_ecdh.shared_x_bytes(server_ecdh.public_key)
    km     = kdf_derive(sx_srv, key_len=32,
                        salt=b"SecureVault-Session-Salt",
                        info=b"server-client-session")
    tf_key  = km[:16]
    rc4_key = km[16:]

    _S = dict(server_eg=server_eg, client_eg=client_eg,
               server_cert=server_cert, client_cert=client_cert,
               tf_key=tf_key, rc4_key=rc4_key, messages=[])

    def trunc(v, n=48): return str(v)[:n] + '…'

    return jsonify(success=True, data=dict(
        ca=dict(p=trunc(ca.p), g=str(ca.g)[:20], y=trunc(ca.y)),
        server=dict(cert_valid=sv, subject=server_cert['subject'],
                    eg_y=trunc(server_eg.y),
                    ecdh_x=hex(server_ecdh.public_key[0])[:50]+'…',
                    issued_at=server_cert['issued_at'],
                    sig_r=trunc(server_cert['sig_r']),
                    sig_s=trunc(server_cert['sig_s'])),
        client=dict(cert_valid=cv, subject=client_cert['subject'],
                    eg_y=trunc(client_eg.y),
                    ecdh_x=hex(client_ecdh.public_key[0])[:50]+'…',
                    issued_at=client_cert['issued_at'],
                    sig_r=trunc(client_cert['sig_r']),
                    sig_s=trunc(client_cert['sig_s'])),
        session=dict(twofish_key=tf_key.hex(), rc4_key=rc4_key.hex(),
                     shared_x=sx_srv.hex()[:48]+'…',
                     keys_match=(sx_srv == sx_cli))
    ))


@app.route('/api/send', methods=['POST'])
def send():
    """Client encrypts a message, server decrypts it, server sends ACK."""
    if not _S:
        return jsonify(success=False, error='Not initialized'), 400

    text = (request.get_json() or {}).get('message', '').strip()
    if not text:
        return jsonify(success=False, error='Empty message'), 400

    tf_key, rc4_key   = _S['tf_key'], _S['rc4_key']
    server_eg_pub     = _S['server_cert']['elgamal_pub']
    client_eg_pub     = _S['client_cert']['elgamal_pub']

    # Client → Server
    pkt                = _encrypt(text.encode(), tf_key, rc4_key, server_eg_pub)
    plaintext, eg_ok   = _decrypt(pkt, _S['server_eg'], tf_key, rc4_key)
    recovered          = plaintext.decode('utf-8', errors='replace')

    # Server ACK → Client
    ack_text           = "Message received securely ✓"
    ack_pkt            = _encrypt(ack_text.encode(), tf_key, rc4_key, client_eg_pub)
    ack_plain_b, _     = _decrypt(ack_pkt, _S['client_eg'], tf_key, rc4_key)
    ack_plain          = ack_plain_b.decode('utf-8', errors='replace')

    ts = datetime.now(timezone.utc).isoformat()
    _log({'timestamp': ts, 'direction': 'client → server',
          'original_message': text,
          'before_decryption': {'ciphertext_hex': pkt['ciphertext'],
                                'integrity_tag': pkt['integrity']},
          'after_decryption':  {'recovered_message': recovered}})

    def t(v, n=40): return str(v)[:n] + '…'

    return jsonify(success=True, data=dict(
        timestamp=ts,
        client=dict(original=text,
                    twofish_ct=t(pkt['twofish_ct']),
                    rc4_ct=t(pkt['ciphertext']),
                    integrity=pkt['integrity'],
                    eg_c1=t(pkt['eg_c1'], 36),
                    eg_c2=t(pkt['eg_c2'], 36)),
        server=dict(integrity_ok=True,
                    eg_keys_match=eg_ok,
                    decrypted=recovered,
                    ack_text=ack_plain,
                    ack_ct=t(ack_pkt['ciphertext']))
    ))


if __name__ == '__main__':
    print("\n  SecureVault GUI Chat  →  http://localhost:5001\n")
    app.run(debug=True, port=5001)
