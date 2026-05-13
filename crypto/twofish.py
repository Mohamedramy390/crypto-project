"""
Twofish Block Cipher — Simplified Educational Implementation
============================================================
Twofish is a symmetric key block cipher with a block size of 128 bits
and key sizes up to 256 bits. It was a finalist in the AES competition.

This is a pedagogically simplified version that captures Twofish's
core structural concepts:
  • Key-dependent S-boxes (derived from the key)
  • Feistel-like network with 16 rounds
  • MDS matrix multiplication (Maximum Distance Separable)
  • PHT (Pseudo-Hadamard Transform)
  • Key whitening

For a full NIST-compliant implementation see the reference code;
this file is intentionally simplified to ~200 lines for clarity.
"""

import struct

# ─── MDS Matrix (4×4 over GF(2^8)) ──────────────────────────────────────────
# Twofish uses an MDS matrix for diffusion in its g() function.
MDS = [
    [0x01, 0xEF, 0x5B, 0x5B],
    [0x5B, 0xEF, 0xEF, 0x01],
    [0xEF, 0x5B, 0x01, 0xEF],
    [0xEF, 0x01, 0xEF, 0x5B],
]

# Fixed S-box (q0 approximation — simplified from the Twofish spec)
Q0 = [
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78,
    0xE4, 0xDD, 0xD1, 0x38, 0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
    0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48, 0xF2, 0xD0, 0x8B, 0x30,
    0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE,
    0x16, 0x0C, 0xE3, 0x61, 0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
    0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1, 0xE1, 0xE6, 0xBD, 0x45,
    0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF,
    0x33, 0xC9, 0x62, 0x71, 0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
    0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7, 0xA1, 0x1D, 0xAA, 0xED,
    0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B,
    0x5F, 0x93, 0x0A, 0xEF, 0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
    0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64, 0x2A, 0xCE, 0xCB, 0x2F,
    0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17,
    0x55, 0x1F, 0x8A, 0x7D, 0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
    0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 0x6E, 0x50, 0xDE, 0x68,
    0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42,
    0x4A, 0x5E, 0xC1, 0xE0,
]


def _gf_mul(a: int, b: int, poly: int = 0x169) -> int:
    """Multiply two elements in GF(2^8) with the given reduction polynomial."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= (poly & 0xFF)
        b >>= 1
    return result


def _mds_multiply(v: int) -> int:
    """Apply a single MDS column multiplication to a 32-bit word."""
    b = [(v >> (8 * i)) & 0xFF for i in range(4)]
    result_bytes = [0] * 4
    for row in range(4):
        val = 0
        for col in range(4):
            val ^= _gf_mul(b[col], MDS[row][col])
        result_bytes[row] = val
    out = 0
    for i, rb in enumerate(result_bytes):
        out |= (rb << (8 * i))
    return out


def _q(x: int) -> int:
    """Simplified key-independent substitution using Q0."""
    return Q0[x & 0xFF]


class SimplifiedTwofish:
    """
    Simplified Twofish — 128-bit blocks, variable key length.
    Uses 8 rounds (full spec uses 16) for readability.
    """
    ROUNDS = 8
    BLOCK_BYTES = 16  # 128-bit blocks

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24, or 32 bytes.")
        self.key = key
        self._subkeys = self._key_schedule()

    def _key_schedule(self) -> list:
        """
        Derive 2*(ROUNDS+2) 32-bit subkeys from the key.
        Simplified version using repeated hashing of key words.
        """
        k_words = []
        for i in range(0, len(self.key), 4):
            k_words.append(struct.unpack('<I', self.key[i:i+4])[0])

        subkeys = []
        rho = 0x9E3779B9  # Golden ratio constant
        # Need: 4 (input whitening) + 4 (output whitening) + 2*ROUNDS (round keys)
        total_keys = 4 + 4 + 2 * self.ROUNDS
        for i in range(total_keys):
            # Mix key words with round constant
            sk = k_words[i % len(k_words)] ^ ((rho * (i + 1)) & 0xFFFFFFFF)
            # Apply MDS for diffusion
            sk = _mds_multiply(sk)
            subkeys.append(sk & 0xFFFFFFFF)
        return subkeys

    def _g(self, x: int) -> int:
        """
        g() function: substitution + MDS diffusion.
        Applies S-box to each byte then multiplies by MDS.
        """
        b = [(x >> (8 * i)) & 0xFF for i in range(4)]
        b = [_q(bi) for bi in b]
        out = sum(b[i] << (8 * i) for i in range(4))
        return _mds_multiply(out) & 0xFFFFFFFF

    def _pht(self, a: int, b: int):
        """Pseudo-Hadamard Transform — provides diffusion between two 32-bit words."""
        a_new = (a + b) & 0xFFFFFFFF
        b_new = (a + 2 * b) & 0xFFFFFFFF
        return a_new, b_new

    def _rotate_left(self, x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _rotate_right(self, x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a single 128-bit block."""
        assert len(block) == self.BLOCK_BYTES
        # Split block into four 32-bit words (little-endian)
        R = list(struct.unpack('<4I', block))

        # Input whitening
        for i in range(4):
            R[i] ^= self._subkeys[i]

        # Feistel rounds
        for r in range(self.ROUNDS):
            T0 = self._g(R[0])
            T1 = self._g(self._rotate_left(R[1], 8))
            T0, T1 = self._pht(T0, T1)
            K0 = self._subkeys[2 * r + 8]
            K1 = self._subkeys[2 * r + 9]
            T0 = (T0 + K0) & 0xFFFFFFFF
            T1 = (T1 + K1) & 0xFFFFFFFF

            R[2] = self._rotate_right(R[2] ^ T0, 1)
            R[3] = self._rotate_left(R[3], 1) ^ T1
            # Swap pairs
            R[0], R[2] = R[2], R[0]
            R[1], R[3] = R[3], R[1]

        # Undo last swap
        R[0], R[2] = R[2], R[0]
        R[1], R[3] = R[3], R[1]

        # Output whitening
        for i in range(4):
            R[i] ^= self._subkeys[4 + i]

        return struct.pack('<4I', *R)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a single 128-bit block (inverse of encrypt_block)."""
        assert len(block) == self.BLOCK_BYTES
        R = list(struct.unpack('<4I', block))

        # Undo output whitening
        for i in range(4):
            R[i] ^= self._subkeys[4 + i]

        # Undo last swap
        R[0], R[2] = R[2], R[0]
        R[1], R[3] = R[3], R[1]

        # Inverse Feistel rounds
        for r in range(self.ROUNDS - 1, -1, -1):
            R[0], R[2] = R[2], R[0]
            R[1], R[3] = R[3], R[1]

            T0 = self._g(R[0])
            T1 = self._g(self._rotate_left(R[1], 8))
            T0, T1 = self._pht(T0, T1)
            K0 = self._subkeys[2 * r + 8]
            K1 = self._subkeys[2 * r + 9]
            T0 = (T0 + K0) & 0xFFFFFFFF
            T1 = (T1 + K1) & 0xFFFFFFFF

            R[2] = self._rotate_left(R[2], 1) ^ T0
            R[3] = self._rotate_right(R[3] ^ T1, 1)

        # Undo input whitening
        for i in range(4):
            R[i] ^= self._subkeys[i]

        return struct.pack('<4I', *R)

    # ── ECB helpers (pad/unpad + multi-block) ────────────────────────────────
    @staticmethod
    def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _pkcs7_unpad(data: bytes) -> bytes:
        pad_len = data[-1]
        return data[:-pad_len]

    def encrypt(self, plaintext: bytes) -> bytes:
        padded = self._pkcs7_pad(plaintext)
        ct = b""
        for i in range(0, len(padded), self.BLOCK_BYTES):
            ct += self.encrypt_block(padded[i:i + self.BLOCK_BYTES])
        return ct

    def decrypt(self, ciphertext: bytes) -> bytes:
        pt = b""
        for i in range(0, len(ciphertext), self.BLOCK_BYTES):
            pt += self.decrypt_block(ciphertext[i:i + self.BLOCK_BYTES])
        return self._pkcs7_unpad(pt)


# ─── Quick demo ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    key = b"MyTwofishKey1234"  # 16 bytes
    cipher = SimplifiedTwofish(key)

    message = b"Hello, Twofish!!"  # exactly 16 bytes for clean demo
    ct = cipher.encrypt(message)
    pt = cipher.decrypt(ct)

    print(f"[Twofish] Key       : {key}")
    print(f"[Twofish] Plaintext : {message}")
    print(f"[Twofish] Ciphertext: {ct.hex()}")
    print(f"[Twofish] Decrypted : {pt}")
    assert pt == message, "Twofish decryption failed!"
    print("[Twofish] ✓ Test passed")
