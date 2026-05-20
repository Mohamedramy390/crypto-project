"""
ECDH (Elliptic-Curve Diffie-Hellman) + KDF — Implemented from scratch
=======================================================================
Replaces the classic finite-field Diffie-Hellman with its elliptic-curve
variant, which achieves equivalent security with much smaller key sizes.

Curve   : secp256r1 (NIST P-256) — industry standard, RFC 8422
Math    :
  • A point P = (x, y) on the curve satisfies  y² ≡ x³ + ax + b  (mod p)
  • Group operation: point addition / doubling (uses projective coordinates)
  • Alice picks random scalar a → Q_A = a·G  (G = base/generator point)
  • Bob   picks random scalar b → Q_B = b·G
  • Shared secret = a·Q_B = b·Q_A = ab·G  ← same for both parties!
  • Only the x-coordinate of the shared point is used as raw secret.

KDF     : HKDF-like expand built on MD5-HMAC (no SHA-256 used anywhere)
  Step 1 — Extract : PRK  = HMAC-MD5(salt, shared_x_bytes)
  Step 2 — Expand  : OKM  = T(1) || T(2) || …  where
                             T(0) = b""
                             T(i) = HMAC-MD5(PRK, T(i-1) || info || i)
  Output : first `key_len` bytes of OKM  (up to 255 × 16 = 4080 bytes)

Security :
  • P-256 ECDH: ~128-bit security — equivalent to RSA-3072 or DH-3072
  • KDF separates shared secret from key material (avoids direct use)
"""

import random


# ══════════════════════════════════════════════════════════════════════════════
#  secp256r1 (NIST P-256) curve parameters  (all from the NIST FIPS 186-4 spec)
# ══════════════════════════════════════════════════════════════════════════════

# Field prime
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

# Curve coefficients  y² = x³ + a·x + b  (mod _P)
_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

# Base point G = (Gx, Gy)
_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# Group order n  (number of points on the curve)
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# A sentinel for the point at infinity
_INFINITY = (None, None)


# ══════════════════════════════════════════════════════════════════════════════
#  Low-level elliptic-curve arithmetic (affine coordinates over F_p)
# ══════════════════════════════════════════════════════════════════════════════

def _modinv(a: int, m: int) -> int:
    """Extended Euclidean algorithm — modular inverse of a mod m."""
    if a == 0:
        raise ZeroDivisionError("No inverse for 0")
    old_r, r = a % m, m
    old_s, s = 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % m


def _point_add(P: tuple, Q: tuple) -> tuple:
    """
    Elliptic-curve point addition over F_p (secp256r1).
    Handles the point at infinity and the P == Q (doubling) case.
    """
    if P == _INFINITY:
        return Q
    if Q == _INFINITY:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2:
        if y1 != y2:                        # P + (-P) = O
            return _INFINITY
        # Point doubling: λ = (3x² + a) / (2y)
        lam = (3 * x1 * x1 + _A) * _modinv(2 * y1, _P) % _P
    else:
        # Point addition: λ = (y2 - y1) / (x2 - x1)
        lam = (y2 - y1) * _modinv(x2 - x1, _P) % _P

    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _scalar_mult(k: int, P: tuple) -> tuple:
    """
    Scalar multiplication: Q = k·P  (double-and-add, constant-ish iteration count).
    """
    result = _INFINITY
    addend = P
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _on_curve(P: tuple) -> bool:
    """Check that (x, y) satisfies  y² ≡ x³ + ax + b  (mod p)."""
    if P == _INFINITY:
        return True
    x, y = P
    return (y * y - x * x * x - _A * x - _B) % _P == 0


# Base point G
_G = (_GX, _GY)


# ══════════════════════════════════════════════════════════════════════════════
#  MD5-HMAC  (re-uses the project's own MD5 from crypto/md5.py)
# ══════════════════════════════════════════════════════════════════════════════

def _md5_hmac(key: bytes, msg: bytes) -> bytes:
    """
    HMAC built on the project's internal MD5 implementation.
    Uses the standard HMAC constructioan:
      HMAC(K, m) = MD5((K' ⊕ opad) || MD5((K' ⊕ ipad) || m))
    where K' is K zero-padded (or hashed) to 64 bytes (MD5 block size).
    """
    # Late import to avoid circular dependency
    from crypto.md5 import md5 as md5_bytes

    BLOCK = 64          # MD5 block size in bytes
    IPAD  = bytes([0x36] * BLOCK)
    OPAD  = bytes([0x5C] * BLOCK)

    if len(key) > BLOCK:
        key = md5_bytes(key)        # hash long keys
    key = key.ljust(BLOCK, b'\x00')

    inner = bytes(a ^ b for a, b in zip(key, IPAD))
    outer = bytes(a ^ b for a, b in zip(key, OPAD))

    inner_hash = md5_bytes(inner + msg)
    return md5_bytes(outer + inner_hash)


# ══════════════════════════════════════════════════════════════════════════════
#  KDF — HKDF-style using MD5-HMAC  (no SHA-256)
# ══════════════════════════════════════════════════════════════════════════════

def kdf_derive(
    shared_x: bytes,
    key_len:  int   = 32,
    salt:     bytes = b"SecureVault-ECDH-Salt-v1",
    info:     bytes = b"ecdh-kdf-expand",
) -> bytes:
    """
    HKDF-like KDF over the ECDH shared x-coordinate.

    :param shared_x: Raw shared secret (x-coordinate bytes of the shared point)
    :param key_len:  Desired output length in bytes (max 4080 = 255 × 16)
    :param salt:     Optional context bytes for the Extract step
    :param info:     Context / application-specific label for the Expand step
    :return:         `key_len` bytes of uniformly distributed key material
    """
    if key_len > 255 * 16:
        raise ValueError("Requested key_len exceeds HKDF-MD5 limit (4080 bytes)")

    # ── Extract ───────────────────────────────────────────────────────────────
    # PRK = HMAC-MD5(salt, IKM)  — map raw DH output into a pseudo-random key
    prk = _md5_hmac(salt, shared_x)         # 16-byte pseudo-random key

    # ── Expand ────────────────────────────────────────────────────────────────
    # OKM = T(1) || T(2) || …  until we have enough bytes
    # T(i) = HMAC-MD5(PRK, T(i-1) || info || i_byte)
    okm   = b""
    T     = b""
    block = 0
    while len(okm) < key_len:
        block += 1
        T   = _md5_hmac(prk, T + info + bytes([block]))
        okm += T

    return okm[:key_len]


# ══════════════════════════════════════════════════════════════════════════════
#  ECDHParty — one participant in an ECDH exchange
# ══════════════════════════════════════════════════════════════════════════════

class ECDHParty:
    """
    One participant in an ECDH (P-256) key exchange.

    Usage:
        alice = ECDHParty()
        bob   = ECDHParty()

        # Exchange public keys (just the compressed point coordinates)
        alice_pub = alice.public_key   # (x, y) on P-256
        bob_pub   = bob.public_key

        # Each derives the same 32-byte shared key via ECDH + KDF
        key_alice = alice.derive_key(bob_pub)
        key_bob   = bob.derive_key(alice_pub)

        assert key_alice == key_bob   # True ✓
    """

    def __init__(self):
        # Private scalar: random in [1, n-1]
        self._private_key: int = random.randint(1, _N - 1)
        # Public point:  Q = private · G
        self._public_key: tuple = _scalar_mult(self._private_key, _G)

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def public_key(self) -> tuple:
        """The (x, y) point on P-256 to send to the other party."""
        return self._public_key

    @property
    def private_scalar(self) -> int:
        """The secret scalar (never share this)."""
        return self._private_key

    # ── Core operations ───────────────────────────────────────────────────────

    def raw_shared_point(self, other_public_key: tuple) -> tuple:
        """
        Compute the raw shared EC point = private · other_public_key.
        Result = ab·G — same for both parties.

        :param other_public_key: (x, y) tuple received from the other party
        :return: Shared point (x, y)
        """
        if not _on_curve(other_public_key):
            raise ValueError("Received public key is not a valid P-256 point!")
        shared = _scalar_mult(self._private_key, other_public_key)
        if shared == _INFINITY:
            raise ValueError("ECDH produced the point at infinity — abort!")
        return shared

    def shared_x_bytes(self, other_public_key: tuple) -> bytes:
        """
        Return the x-coordinate of the shared point as 32 bytes (big-endian).
        This is the raw ECDH output used as input to the KDF.
        """
        shared = self.raw_shared_point(other_public_key)
        return shared[0].to_bytes(32, 'big')

    def derive_key(
        self,
        other_public_key: tuple,
        key_len:  int   = 32,
        salt:     bytes = b"SecureVault-ECDH-Salt-v1",
        info:     bytes = b"ecdh-kdf-expand",
    ) -> bytes:
        """
        Full ECDH + KDF pipeline → ready-to-use symmetric key material.

        :param other_public_key: (x, y) point from the peer
        :param key_len:          Desired key material length in bytes
        :param salt:             KDF salt (public, can be a nonce)
        :param info:             KDF context label
        :return:                 `key_len` bytes suitable for use as symmetric keys
        """
        raw_x = self.shared_x_bytes(other_public_key)
        return kdf_derive(raw_x, key_len=key_len, salt=salt, info=info)


# ══════════════════════════════════════════════════════════════════════════════
#  Quick demo
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("[ECDH] secp256r1 (P-256) key exchange…")

    alice = ECDHParty()
    bob   = ECDHParty()

    print(f"[ECDH] Alice private scalar  : {hex(alice.private_scalar)[:50]}…")
    print(f"[ECDH] Alice public key  (x) : {hex(alice.public_key[0])[:50]}…")
    print(f"[ECDH] Bob   public key  (x) : {hex(bob.public_key[0])[:50]}…")

    # Each party derives the symmetric key from the other's public key
    key_alice = alice.derive_key(bob.public_key,   key_len=32)
    key_bob   = bob.derive_key(alice.public_key,   key_len=32)

    assert key_alice == key_bob, "ECDH shared keys do not match!"
    print(f"[ECDH] Derived shared key    : {key_alice.hex()}")
    print("[ECDH] ✓ Keys match — ECDH + KDF test passed!")

    # Verify the shared x-coordinates match too
    x_alice = alice.shared_x_bytes(bob.public_key)
    x_bob   = bob.shared_x_bytes(alice.public_key)
    assert x_alice == x_bob, "Shared x-coords do not match!"
    print(f"[ECDH] Shared x-coord        : {x_alice.hex()}")
    print("[ECDH] ✓ All checks passed.")
