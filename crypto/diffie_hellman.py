"""
Diffie-Hellman Key Exchange — Implemented from scratch
=======================================================
Diffie-Hellman allows two parties (Alice & Bob) to establish a shared
secret over an insecure channel without ever transmitting the secret itself.

Math:
  Public params : large prime p, generator g
  Alice picks   : private a  →  sends A = g^a mod p
  Bob picks     : private b  →  sends B = g^b mod p
  Shared secret : Alice computes B^a mod p
                  Bob   computes A^b mod p
                  Both equal g^(ab) mod p  ✓

Security: hardness of Discrete Logarithm Problem (DLP).
"""

import random
import hashlib as _hashlib  # only used in derive_key() for HKDF — not SHA256 for crypto


# ─── Reuse prime utilities from elgamal ────────────────────────────────────────
def _is_prime(n: int, k: int = 20) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int = 512) -> int:
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(candidate):
            return candidate


# ─── Well-known DH groups (RFC 3526) — faster for demos ──────────────────────
# Group 1 (768-bit) — educational use only
DH_P_768 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)
DH_G_768 = 2

# Group 14 (2048-bit) — recommended minimum for real use
DH_P_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
DH_G_2048 = 2


# ─── DHParty — represents one side of a DH exchange ──────────────────────────

class DHParty:
    """
    One participant in a Diffie-Hellman key exchange.

    Usage:
        alice = DHParty(p, g)
        bob   = DHParty(p, g)

        # Exchange public keys
        shared_alice = alice.compute_shared_secret(bob.public_key)
        shared_bob   = bob.compute_shared_secret(alice.public_key)

        assert shared_alice == shared_bob  # True ✓
    """

    def __init__(self, p: int, g: int):
        """
        :param p: Large prime modulus
        :param g: Generator (primitive root mod p)
        """
        self.p = p
        self.g = g
        # Private key: random in [2, p-2]
        self._private_key = random.randint(2, p - 2)
        # Public key: g^private mod p
        self._public_key = pow(g, self._private_key, p)

    @property
    def public_key(self) -> int:
        """The value to send to the other party."""
        return self._public_key

    def compute_shared_secret(self, other_public_key: int) -> int:
        """
        Compute shared secret from the other party's public key.
        Result = other_public_key ^ private_key mod p
               = g^(ab) mod p
        """
        return pow(other_public_key, self._private_key, self.p)

    def derive_key(self, other_public_key: int, key_len: int = 32) -> bytes:
        """
        Derive a symmetric encryption key from the shared secret.
        Uses a simple KDF: XOR-fold the shared secret bytes to desired length.
        (Production systems would use HKDF or similar.)
        """
        secret = self.compute_shared_secret(other_public_key)
        # Convert to bytes
        secret_bytes = secret.to_bytes((secret.bit_length() + 7) // 8, 'big')
        # XOR-fold to key_len bytes (simple KDF without SHA-256)
        key = bytearray(key_len)
        for i, byte in enumerate(secret_bytes):
            key[i % key_len] ^= byte
        return bytes(key)


# ─── Convenience: generate fresh DH parameters ────────────────────────────────

class DHParameters:
    """
    Generate or use pre-defined DH group parameters.
    """

    @staticmethod
    def from_rfc3526_768() -> tuple:
        """Return (p, g) from RFC 3526 Group 1 (768-bit) — fast for demos."""
        return DH_P_768, DH_G_768

    @staticmethod
    def from_rfc3526_2048() -> tuple:
        """Return (p, g) from RFC 3526 Group 14 (2048-bit)."""
        return DH_P_2048, DH_G_2048

    @staticmethod
    def generate(bits: int = 512) -> tuple:
        """Generate a fresh random prime p and generator g=2."""
        p = _generate_prime(bits)
        g = 2  # 2 is a generator for most safe primes
        return p, g


# ─── Quick demo ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[DH] Using RFC 3526 768-bit group (fast demo)…")
    p, g = DHParameters.from_rfc3526_768()

    alice = DHParty(p, g)
    bob   = DHParty(p, g)

    print(f"[DH] Alice public key (first 40 hex): {alice.public_key:x}"[:60])
    print(f"[DH] Bob   public key (first 40 hex): {bob.public_key:x}"[:60])

    # Each derives the shared secret from the other's public key
    secret_alice = alice.compute_shared_secret(bob.public_key)
    secret_bob   = bob.compute_shared_secret(alice.public_key)

    assert secret_alice == secret_bob, "Shared secrets do not match!"
    print(f"[DH] Shared secret match: ✓")

    # Derive a 16-byte symmetric key
    key_alice = alice.derive_key(bob.public_key, key_len=16)
    key_bob   = bob.derive_key(alice.public_key, key_len=16)
    assert key_alice == key_bob
    print(f"[DH] Derived symmetric key: {key_alice.hex()}")
    print("[DH] ✓ Test passed")
