"""
SecureVault — Cryptographic Pipeline
======================================
This module ties together all implemented algorithms into a unified
secure-communication pipeline:

  SENDER side:
    1.  ECDH (P-256) key exchange + KDF → derive shared symmetric key
    2.  Twofish  → encrypt payload (block cipher layer)
    3.  RC4      → encrypt again (stream cipher layer, double encryption)
    4.  ElGamal  → encrypt the Twofish/RC4 key bundle
    5.  MD5      → attach integrity tag

  RECEIVER side:
    1.  MD5      → verify integrity
    2.  ElGamal  → decrypt key bundle
    3.  RC4      → decrypt outer layer
    4.  Twofish  → decrypt inner layer

All from scratch — no external crypto libraries.
"""

import os
import json
import struct

from crypto.rc4         import RC4
from crypto.twofish     import SimplifiedTwofish
from crypto.elgamal     import ElGamal
from crypto.ecdh_kdf    import ECDHParty, kdf_derive
from crypto.md5         import md5_hex, verify_integrity


# ─── Utility ──────────────────────────────────────────────────────────────────

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def int_to_bytes(n: int, length: int = None) -> bytes:
    blen = length or ((n.bit_length() + 7) // 8)
    return n.to_bytes(blen, 'big')


# ─── Session — represents one secure communication session ───────────────────

class SecureSession:
    """
    Establishes a secure session between two parties using:
      • ECDH (P-256) + KDF for session key
      • Twofish + RC4 for double-layer symmetric encryption
      • ElGamal for asymmetric key wrapping
      • MD5 for integrity checking
    """

    def __init__(self, elgamal_bits: int = 256):
        """
        :param elgamal_bits: Key size for ElGamal (256 for speed in demos, 512+ for security)
        """
        print("[SecureVault] ══════ Initializing SecureSession ══════")

        # 1. Generate ElGamal key pair (asymmetric)
        print("[SecureVault] Generating ElGamal key pair…")
        self.elgamal = ElGamal(bits=elgamal_bits)

        # 2. ECDH on secp256r1 — no parameter negotiation needed
        print("[SecureVault] ECDH on P-256 ready — curve parameters are built-in.")

    def sender_encrypt(self, plaintext: bytes, recipient_pub: dict) -> dict:
        """
        Full encryption pipeline (Sender side).

        :param plaintext:     The message to encrypt (bytes)
        :param recipient_pub: Recipient's ElGamal public key dict {p, g, y}
        :return: envelope dict containing all ciphertext components
        """
        print("\n[SecureVault] ── ENCRYPTING ─────────────────────────────")

        # ── Step 1: ECDH + KDF ─────────────────────────────────────────────────────
        sender_ecdh   = ECDHParty()
        receiver_ecdh = ECDHParty()  # In real use: receiver sends their public key over the network

        shared_x = sender_ecdh.shared_x_bytes(receiver_ecdh.public_key)
        shared_key = kdf_derive(shared_x, key_len=32,
                                salt=b"SecureVault-ECDH-Salt-v1",
                                info=b"ecdh-kdf-expand")
        print(f"[Step 1] ECDH shared key (KDF) : {shared_key.hex()}")

        # ── Step 2: Twofish encryption (inner layer) ───────────────────────────
        twofish_key = shared_key[:16]  # Use first 16 bytes for Twofish
        tf_cipher   = SimplifiedTwofish(twofish_key)
        twofish_ct  = tf_cipher.encrypt(plaintext)
        print(f"[Step 2] Twofish CT       : {twofish_ct[:16].hex()}…")

        # ── Step 3: RC4 encryption (outer layer) ──────────────────────────────
        rc4_key    = shared_key[16:]   # Use last 16 bytes for RC4
        rc4_cipher = RC4(rc4_key)
        rc4_ct     = rc4_cipher.encrypt(twofish_ct)
        print(f"[Step 3] RC4 CT           : {rc4_ct[:16].hex()}…")

        # ── Step 4: MD5 integrity tag ─────────────────────────────────────────
        integrity_tag = md5_hex(rc4_ct)
        print(f"[Step 4] MD5 integrity tag: {integrity_tag}")

        # ── Step 5: ElGamal-wrap the key bundle ───────────────────────────────
        # Build a tiny key bundle: twofish_key (16 bytes) + rc4_key (16 bytes)
        key_bundle_int = bytes_to_int(twofish_key + rc4_key)

        eg_pub = ElGamal.from_keys(
            p=recipient_pub['p'],
            g=recipient_pub['g'],
            y=recipient_pub['y'],
        )
        eg_ct = eg_pub.encrypt(key_bundle_int % eg_pub.p)
        print(f"[Step 5] ElGamal key wrap  : c1={str(eg_ct[0])[:30]}…")

        # ── Assemble envelope ─────────────────────────────────────────────────
        envelope = {
            "version": "SecureVault/2.0",
            "ciphertext": rc4_ct.hex(),
            "integrity": integrity_tag,
            "elgamal_c1": eg_ct[0],
            "elgamal_c2": eg_ct[1],
            "ecdh_sender_pub_x": sender_ecdh.public_key[0],
            "ecdh_sender_pub_y": sender_ecdh.public_key[1],
            "ecdh_receiver_pub_x": receiver_ecdh.public_key[0],
            "ecdh_receiver_pub_y": receiver_ecdh.public_key[1],
            "original_length": len(plaintext),
        }

        print("[SecureVault] Encryption complete ✓")
        return envelope

    def receiver_decrypt(self, envelope: dict) -> bytes:
        """
        Full decryption pipeline (Receiver side).

        :param envelope: The envelope dict produced by sender_encrypt()
        :return: Decrypted plaintext bytes
        """
        print("\n[SecureVault] ── DECRYPTING ──────────────────────────────")

        rc4_ct = bytes.fromhex(envelope["ciphertext"])

        # ── Step 1: Verify MD5 integrity ──────────────────────────────────────
        if not verify_integrity(rc4_ct, envelope["integrity"]):
            raise ValueError("[SecureVault] INTEGRITY CHECK FAILED — message tampered!")
        print("[Step 1] MD5 integrity    : ✓ OK")

        # ── Step 2: ElGamal decrypt key bundle ────────────────────────────────
        eg_ct = (envelope["elgamal_c1"], envelope["elgamal_c2"])
        key_bundle_int = self.elgamal.decrypt(eg_ct)
        # Re-derive twofish + rc4 keys
        key_bundle_bytes = int_to_bytes(key_bundle_int, 32)
        twofish_key = key_bundle_bytes[:16]
        rc4_key     = key_bundle_bytes[16:]
        print(f"[Step 2] ElGamal key unwrap: ✓  twofish={twofish_key.hex()} rc4={rc4_key.hex()}")

        # ── Step 3: RC4 decrypt (outer layer) ─────────────────────────────────
        rc4_cipher  = RC4(rc4_key)
        twofish_ct  = rc4_cipher.decrypt(rc4_ct)
        print(f"[Step 3] RC4 decrypted    : {twofish_ct[:16].hex()}…")

        # ── Step 4: Twofish decrypt (inner layer) ─────────────────────────────
        tf_cipher  = SimplifiedTwofish(twofish_key)
        plaintext  = tf_cipher.decrypt(twofish_ct)
        print(f"[Step 4] Twofish decrypted: {plaintext[:40]}…")

        print("[SecureVault] Decryption complete ✓")
        return plaintext


# ─── Quick demo ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  SecureVault — Full Cryptographic Pipeline Demo")
    print("=" * 60)

    session = SecureSession(elgamal_bits=256)

    message = (
        b"Confidential: The quarterly revenue report shows a 42% "
        b"increase in Q3. Do not share outside board members."
    )
    print(f"\n[DEMO] Original message ({len(message)} bytes):")
    print(f"  {message.decode()}")

    # Encrypt
    envelope = session.sender_encrypt(message, session.elgamal.public_key)

    # Decrypt
    recovered = session.receiver_decrypt(envelope)

    print(f"\n[DEMO] Recovered message:")
    print(f"  {recovered.decode()}")

    # Tampering test
    print("\n[DEMO] Tampering test…")
    tampered = dict(envelope)
    tampered["ciphertext"] = ("ff" * (len(message) + 16))
    try:
        session.receiver_decrypt(tampered)
    except ValueError as e:
        print(f"  Caught expected error: {e}")

    assert recovered == message, "Pipeline integrity failed!"
    print("\n[SecureVault] ✓ Full pipeline test passed!")
