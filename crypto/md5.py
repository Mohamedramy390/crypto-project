"""
MD5 Hash Function — Implemented from scratch
============================================
MD5 produces a 128-bit (16-byte) hash digest.
Used here for MESSAGE INTEGRITY only (not for password storage).

Algorithm overview:
  1. Pre-processing: pad message to 512-bit blocks
  2. Initialize four 32-bit state words: A, B, C, D
  3. Process each 512-bit block through 64 rounds (4 × 16 rounds)
     - Each round uses a different auxiliary function (F, G, H, I)
     - Each round uses a pre-computed constant T[i] = floor(2^32 * |sin(i+1)|)
  4. Final hash = concatenation of A, B, C, D (little-endian)
"""

import math
import struct


# ─── Pre-compute T constants ──────────────────────────────────────────────────
# T[i] = floor(2^32 * |sin(i+1)|)  for i = 0..63
T = [int(2**32 * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]

# ─── Shift amounts per round ──────────────────────────────────────────────────
S = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  # Round 1
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  # Round 2
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  # Round 3
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  # Round 4
]

# ─── Initial hash values (magic constants from MD5 spec) ─────────────────────
INIT_A = 0x67452301
INIT_B = 0xEFCDAB89
INIT_C = 0x98BADCFE
INIT_D = 0x10325476


def _left_rotate(x: int, n: int) -> int:
    """Rotate 32-bit integer x left by n bits."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _pad_message(message: bytes) -> bytes:
    """
    Pad message to a multiple of 512 bits (64 bytes):
      1. Append 0x80 byte
      2. Append zeros until length ≡ 56 (mod 64)
      3. Append original length in bits as 64-bit little-endian integer
    """
    original_length_bits = len(message) * 8
    message += b'\x80'
    # Pad with zeros
    while len(message) % 64 != 56:
        message += b'\x00'
    # Append length as 64-bit little-endian
    message += struct.pack('<Q', original_length_bits)
    return message


def _process_block(block: bytes, A: int, B: int, C: int, D: int):
    """
    Process one 512-bit (64-byte) block.
    Returns updated (A, B, C, D).
    """
    assert len(block) == 64
    # Break block into sixteen 32-bit little-endian words
    M = struct.unpack('<16I', block)

    a, b, c, d = A, B, C, D

    for i in range(64):
        if 0 <= i <= 15:
            # Round 1: F(B,C,D) = (B AND C) OR (NOT B AND D)
            F = (b & c) | (~b & d)
            g = i
        elif 16 <= i <= 31:
            # Round 2: G(B,C,D) = (B AND D) OR (C AND NOT D)
            F = (b & d) | (c & ~d)
            g = (5 * i + 1) % 16
        elif 32 <= i <= 47:
            # Round 3: H(B,C,D) = B XOR C XOR D
            F = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            # Round 4: I(B,C,D) = C XOR (B OR NOT D)
            F = c ^ (b | ~d)
            g = (7 * i) % 16

        F = (F + a + T[i] + M[g]) & 0xFFFFFFFF
        temp = (b + _left_rotate(F, S[i])) & 0xFFFFFFFF

        a = d
        d = c
        c = b
        b = temp

    # Add this block's result to the running totals
    A = (A + a) & 0xFFFFFFFF
    B = (B + b) & 0xFFFFFFFF
    C = (C + c) & 0xFFFFFFFF
    D = (D + d) & 0xFFFFFFFF

    return A, B, C, D


def md5(message: bytes) -> bytes:
    """
    Compute MD5 digest of message.
    :param message: bytes
    :return: 16-byte digest
    """
    padded = _pad_message(message)
    A, B, C, D = INIT_A, INIT_B, INIT_C, INIT_D

    for i in range(0, len(padded), 64):
        block = padded[i:i + 64]
        A, B, C, D = _process_block(block, A, B, C, D)

    # Pack final hash as little-endian 32-bit words
    return struct.pack('<4I', A, B, C, D)


def md5_hex(message: bytes) -> str:
    """Return MD5 digest as lowercase hex string."""
    return md5(message).hex()


def verify_integrity(data: bytes, expected_hex: str) -> bool:
    """Check if data matches expected MD5 hex digest."""
    return md5_hex(data) == expected_hex.lower()


# ─── Quick demo ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import hashlib  # only for verification against stdlib

    test_vectors = [
        b"",
        b"a",
        b"abc",
        b"message digest",
        b"Hello, SecureVault!",
    ]

    print("[MD5] Running test vectors (comparing against stdlib):")
    all_pass = True
    for msg in test_vectors:
        our   = md5_hex(msg)
        theirs = hashlib.md5(msg).hexdigest()
        status = "✓" if our == theirs else "✗"
        if our != theirs:
            all_pass = False
        print(f"  {status}  '{msg.decode()[:30]}' => {our}")

    if all_pass:
        print("[MD5] ✓ All test vectors pass!")
    else:
        print("[MD5] ✗ Some tests failed!")

    # Integrity check demo
    data = b"Important document content"
    digest = md5_hex(data)
    print(f"\n[MD5] Digest of document : {digest}")
    print(f"[MD5] Integrity verified : {verify_integrity(data, digest)}")
    print(f"[MD5] Tampered data check: {verify_integrity(b'Tampered!', digest)}")
