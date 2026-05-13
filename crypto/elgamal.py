"""
ElGamal Asymmetric Encryption — Implemented from scratch
=========================================================
ElGamal is a public-key cryptosystem based on the Diffie-Hellman key exchange
and the hardness of the Discrete Logarithm Problem (DLP).

Key concepts:
  • Public key  : (p, g, y)  where y = g^x mod p
  • Private key : x  (the secret exponent)
  • Encryption  : Choose random k, send (g^k mod p, m * y^k mod p)
  • Decryption  : Recover m = c2 * (c1^x)^-1 mod p

Security note: each encryption uses a fresh random k → probabilistic cipher.
"""

import random
import math


# ─── Prime & primitive-root utilities ─────────────────────────────────────────

def _is_prime(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test — probabilistic, k rounds."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
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
    """Generate a random prime of the given bit-length."""
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1  # odd, MSB set
        if _is_prime(candidate):
            return candidate


def _find_primitive_root(p: int) -> int:
    """
    Find a primitive root g modulo p.
    For a safe prime p = 2q+1 (q prime), g is a primitive root iff
    g^q ≠ 1 mod p and g ≠ 1.
    We iterate until we find one.
    """
    phi = p - 1
    # Factorize phi = p-1 (for safe primes this is 2 * (p-1)/2)
    factors = set()
    n = phi
    for prime in [2, 3, 5, 7, 11, 13]:
        if n % prime == 0:
            factors.add(prime)
            while n % prime == 0:
                n //= prime
    if n > 1:
        factors.add(n)

    for g in range(2, p):
        if all(pow(g, phi // f, p) != 1 for f in factors):
            return g
    raise ValueError("No primitive root found — is p prime?")


def _mod_inverse(a: int, m: int) -> int:
    """Extended Euclidean Algorithm to find modular inverse of a mod m."""
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse: gcd({a}, {m}) = {g}")
    return x % m


def _extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


# ─── ElGamal Key Generation ────────────────────────────────────────────────────

class ElGamal:
    """
    ElGamal public-key encryption over Z_p*.

    Usage:
        eg = ElGamal(bits=512)          # generates fresh key pair
        # --- or load an existing key ---
        eg = ElGamal.from_keys(p, g, y, x)

        ct = eg.encrypt(message_int)
        pt = eg.decrypt(ct)
    """

    def __init__(self, bits: int = 512, _p=None, _g=None, _x=None, _y=None):
        if _p is not None:
            # Load from existing params
            self.p = _p
            self.g = _g
            self.x = _x           # private key
            self.y = _y           # public key component
        else:
            self._generate_keys(bits)

    def _generate_keys(self, bits: int):
        print(f"[ElGamal] Generating {bits}-bit prime p … (this may take a moment)")
        self.p = _generate_prime(bits)
        self.g = _find_primitive_root(self.p)
        # Private key: random x in [2, p-2]
        self.x = random.randint(2, self.p - 2)
        # Public key component: y = g^x mod p
        self.y = pow(self.g, self.x, self.p)
        print(f"[ElGamal] Key generation complete.")

    @classmethod
    def from_keys(cls, p: int, g: int, y: int, x: int = None):
        return cls(_p=p, _g=g, _x=x, _y=y)

    @property
    def public_key(self) -> dict:
        return {"p": self.p, "g": self.g, "y": self.y}

    @property
    def private_key(self) -> dict:
        return {"x": self.x}

    # ── Core operations ───────────────────────────────────────────────────────

    def encrypt(self, m: int) -> tuple:
        """
        Encrypt integer m (0 ≤ m < p).
        Returns ciphertext tuple (c1, c2).
          c1 = g^k mod p
          c2 = m * y^k mod p
        """
        if not (0 <= m < self.p):
            raise ValueError(f"Message must be in range [0, p). Got {m}")
        # Choose fresh random k
        k = random.randint(2, self.p - 2)
        c1 = pow(self.g, k, self.p)
        c2 = (m * pow(self.y, k, self.p)) % self.p
        return (c1, c2)

    def decrypt(self, ciphertext: tuple) -> int:
        """
        Decrypt ciphertext (c1, c2) using private key x.
          s  = c1^x mod p          (shared secret)
          m  = c2 * s^-1 mod p
        """
        if self.x is None:
            raise ValueError("Private key not available — cannot decrypt.")
        c1, c2 = ciphertext
        s = pow(c1, self.x, self.p)
        s_inv = _mod_inverse(s, self.p)
        m = (c2 * s_inv) % self.p
        return m

    # ── Byte-level helpers ────────────────────────────────────────────────────

    def encrypt_bytes(self, data: bytes) -> list:
        """
        Encrypt arbitrary bytes by splitting into chunks < p and encrypting each.
        Returns list of (c1, c2) pairs.
        """
        chunk_size = (self.p.bit_length() - 1) // 8  # safe chunk size in bytes
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            m = int.from_bytes(chunk, 'big')
            chunks.append(self.encrypt(m))
        return chunks

    def decrypt_bytes(self, ciphertext_list: list, original_length: int) -> bytes:
        """
        Decrypt a list of (c1, c2) pairs back to bytes.
        original_length needed to strip padding from last chunk.
        """
        chunk_size = (self.p.bit_length() - 1) // 8
        result = b""
        for i, ct in enumerate(ciphertext_list):
            m = self.decrypt(ct)
            # Determine byte length of this chunk
            is_last = (i == len(ciphertext_list) - 1)
            remaining = original_length - i * chunk_size
            size = min(chunk_size, remaining) if is_last else chunk_size
            result += m.to_bytes(size, 'big')
        return result


# ─── Quick demo ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Use small bit-size for fast demo; use 512+ in production
    eg = ElGamal(bits=256)

    message = b"Hello ElGamal"
    print(f"[ElGamal] Plaintext : {message}")

    ct_list = eg.encrypt_bytes(message)
    print(f"[ElGamal] Ciphertext (first chunk): c1={ct_list[0][0]}, c2={ct_list[0][1]}")

    pt = eg.decrypt_bytes(ct_list, len(message))
    print(f"[ElGamal] Decrypted : {pt}")
    assert pt == message, "ElGamal decryption failed!"
    print("[ElGamal] ✓ Test passed")
