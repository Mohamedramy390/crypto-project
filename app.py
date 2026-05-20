"""
SecureVault — Flask Web Simulation Backend
"""
import sys, os, traceback, json
from datetime import datetime, timezone
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'messages_log.json')


def _append_log(entry: dict) -> None:
    """Append *entry* to the JSON log file (creates it if absent)."""
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r', encoding='utf-8') as fh:
            try:
                records = json.load(fh)
            except json.JSONDecodeError:
                records = []
    else:
        records = []
    records.append(entry)
    with open(LOG_FILE, 'w', encoding='utf-8') as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/simulate', methods=['POST'])
def simulate():
    from crypto.rc4 import RC4
    from crypto.twofish import SimplifiedTwofish
    from crypto.elgamal import ElGamal
    from crypto.ecdh_kdf import ECDHParty, kdf_derive
    from crypto.md5 import md5_hex

    try:
        data = request.get_json() or {}
        message_text = data.get(
            'message',
            'Bob, the board approved the merger. Transfer the funds to '
            'account #4471-XXXX by Friday. Do not use email - this channel only. - Alice'
        )
        message = message_text.encode('utf-8')
        result = {}

        # ── Phase 0: Key generation ──────────────────────────────────────
        bob_eg = ElGamal(bits=256)
        result['phase0'] = {
            'elgamal_p': str(bob_eg.public_key['p']),
            'elgamal_g': str(bob_eg.public_key['g']),
            'elgamal_y': str(bob_eg.public_key['y']),
            'elgamal_x': str(bob_eg.private_key['x']),
        }

        # ── Phase 1: Alice's message ─────────────────────────────────────
        result['phase1'] = {
            'message': message_text,
            'message_bytes': len(message),
            'message_hex': message[:32].hex(),
        }

        # ── Phase 2: ECDH + KDF ──────────────────────────────────────────
        alice_ecdh = ECDHParty()
        bob_ecdh   = ECDHParty()

        shared_x_alice = alice_ecdh.shared_x_bytes(bob_ecdh.public_key)
        shared_x_bob   = bob_ecdh.shared_x_bytes(alice_ecdh.public_key)

        key_material = kdf_derive(shared_x_alice, key_len=32,
                                  salt=b"SecureVault-ECDH-Salt-v1",
                                  info=b"ecdh-kdf-expand")
        twofish_key = key_material[:16]
        rc4_key     = key_material[16:]

        result['phase2'] = {
            'alice_private': hex(alice_ecdh.private_scalar)[:52] + '...',
            'alice_pub_x':   hex(alice_ecdh.public_key[0])[:52] + '...',
            'alice_pub_y':   hex(alice_ecdh.public_key[1])[:52] + '...',
            'bob_private':   hex(bob_ecdh.private_scalar)[:52] + '...',
            'bob_pub_x':     hex(bob_ecdh.public_key[0])[:52] + '...',
            'bob_pub_y':     hex(bob_ecdh.public_key[1])[:52] + '...',
            'shared_x':      shared_x_alice.hex(),
            'shared_match':  shared_x_alice == shared_x_bob,
            'kdf_output':    key_material.hex(),
            'twofish_key':   twofish_key.hex(),
            'rc4_key':       rc4_key.hex(),
        }

        # ── Phase 3: Encryption ──────────────────────────────────────────
        tf         = SimplifiedTwofish(twofish_key)
        twofish_ct = tf.encrypt(message)

        rc4        = RC4(rc4_key)
        rc4_ct     = rc4.encrypt(twofish_ct)

        integrity_tag = md5_hex(rc4_ct)

        key_bundle_int = int.from_bytes(twofish_key + rc4_key, 'big') % bob_eg.p
        eg_pub = ElGamal.from_keys(
            p=bob_eg.public_key['p'],
            g=bob_eg.public_key['g'],
            y=bob_eg.public_key['y']
        )
        eg_ct = eg_pub.encrypt(key_bundle_int)

        packet = {
            'ciphertext':  rc4_ct.hex(),
            'integrity':   integrity_tag,
            'elgamal_c1':  eg_ct[0],
            'elgamal_c2':  eg_ct[1],
            'orig_length': len(message),
        }

        result['phase3'] = {
            'plaintext_hex':   message[:16].hex(),
            'twofish_ct':      twofish_ct[:32].hex(),
            'twofish_ct_size': len(twofish_ct),
            'rc4_ct':          rc4_ct[:32].hex(),
            'rc4_ct_size':     len(rc4_ct),
            'integrity_tag':   integrity_tag,
            'elgamal_c1':      str(eg_ct[0])[:64],
            'elgamal_c2':      str(eg_ct[1])[:64],
            'full_ciphertext': rc4_ct.hex()[:128],
        }

        # ── Phase 4: Decryption ──────────────────────────────────────────
        received_ct  = bytes.fromhex(packet['ciphertext'])
        computed_tag = md5_hex(received_ct)
        integrity_ok = computed_tag == packet['integrity']

        unwrapped_int   = bob_eg.decrypt((packet['elgamal_c1'], packet['elgamal_c2']))
        unwrapped_bytes = unwrapped_int.to_bytes(32, 'big')
        rec_twofish_key = unwrapped_bytes[:16]
        rec_rc4_key     = unwrapped_bytes[16:]

        rc4_dec              = RC4(rec_rc4_key)
        twofish_ct_recovered = rc4_dec.decrypt(received_ct)

        tf_dec             = SimplifiedTwofish(rec_twofish_key)
        plaintext_recovered = tf_dec.decrypt(twofish_ct_recovered)

        result['phase4'] = {
            'integrity_check':  integrity_ok,
            'received_tag':     packet['integrity'],
            'computed_tag':     computed_tag,
            'rec_twofish_key':  rec_twofish_key.hex(),
            'rec_rc4_key':      rec_rc4_key.hex(),
            'keys_match':       rec_twofish_key == twofish_key and rec_rc4_key == rc4_key,
            'rc4_ct':           received_ct[:32].hex(),
            'after_rc4':        twofish_ct_recovered[:32].hex(),
            'after_twofish':    plaintext_recovered[:32].hex(),
        }

        # ── Phase 5: Bob reads ───────────────────────────────────────────
        result['phase5'] = {
            'recovered_message': plaintext_recovered.decode('utf-8', errors='replace'),
            'recovered_bytes':   len(plaintext_recovered),
            'match':             plaintext_recovered == message,
        }

        # ── Phase 6: Tamper attack ───────────────────────────────────────
        tampered_hex_list = list(packet['ciphertext'])
        original_bytes    = ''.join(tampered_hex_list[8:12])
        tampered_hex_list[8:12] = list('DEAD')
        tampered_ct  = bytes.fromhex(''.join(tampered_hex_list))
        tampered_tag = md5_hex(tampered_ct)

        result['phase6'] = {
            'original_bytes': original_bytes,
            'tampered_bytes': 'DEAD',
            'original_tag':   packet['integrity'],
            'tampered_tag':   tampered_tag,
            'detected':       tampered_tag != packet['integrity'],
        }

        # ── Persist to JSON log ──────────────────────────────────────────
        log_entry = {
            'timestamp':        datetime.now(timezone.utc).isoformat(),
            'original_message': message_text,
            'encryption': {
                'twofish_ciphertext':  result['phase3']['twofish_ct'],
                'rc4_ciphertext':      result['phase3']['rc4_ct'],
                'full_ciphertext_hex': result['phase3']['full_ciphertext'],
                'integrity_tag':       result['phase3']['integrity_tag'],
                'elgamal_c1':          result['phase3']['elgamal_c1'],
                'elgamal_c2':          result['phase3']['elgamal_c2'],
            },
            'before_decryption': {
                'received_ciphertext_hex': packet['ciphertext'],
                'received_integrity_tag':  packet['integrity'],
                'integrity_verified':      result['phase4']['integrity_check'],
            },
            'after_decryption': {
                'recovered_message':  result['phase5']['recovered_message'],
                'recovered_bytes':    result['phase5']['recovered_bytes'],
                'match_original':     result['phase5']['match'],
            },
            'tamper_detected':  result['phase6']['detected'],
        }
        _append_log(log_entry)

        return jsonify({'success': True, 'data': result})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e),
                        'trace': traceback.format_exc()}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
