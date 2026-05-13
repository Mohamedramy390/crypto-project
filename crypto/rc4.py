"""
RC4 Stream Cipher — Implemented from scratch
=============================================
RC4 (Rivest Cipher 4) is a stream cipher that generates a pseudo-random
keystream which is XOR'd with the plaintext to produce ciphertext.

Steps:
  1. Key Scheduling Algorithm (KSA): Initialize S-box using the key.
  2. Pseudo-Random Generation Algorithm (PRGA): Generate keystream bytes.
  3. XOR keystream with plaintext/ciphertext.
"""


class RC4:
    def __init__(self, key: bytes):
        """
        Initialize RC4 with a key.
        :param key: bytes — the encryption key (1 to 256 bytes)
        """
        self.key = key
        self.S = self._ksa(key)

    def _ksa(self, key: bytes) -> list:
        """
        Key Scheduling Algorithm (KSA).
        Produces a permutation of 0..255 based on the key.
        """
        key_length = len(key)
        # Step 1: Initialize S-box with identity permutation
        S = list(range(256))

        j = 0
        for i in range(256):
            # Step 2: Shuffle based on key bytes
            j = (j + S[i] + key[i % key_length]) % 256
            S[i], S[j] = S[j], S[i]  # Swap

        return S

    def _prga(self, length: int) -> bytes:
        """
        Pseudo-Random Generation Algorithm (PRGA).
        Generates `length` bytes of keystream.
        """
        S = self.S[:]  # Work on a copy so we can re-use the object
        i = 0
        j = 0
        keystream = []

        for _ in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            keystream.append(K)

        return bytes(keystream)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext using RC4.
        :param plaintext: bytes
        :return: ciphertext bytes
        """
        keystream = self._prga(len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, keystream))

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext using RC4.
        RC4 is symmetric — same operation as encrypt.
        """
        return self.encrypt(ciphertext)


# ─── Standalone helpers ───────────────────────────────────────────────────────

def rc4_encrypt(key: bytes, plaintext: bytes) -> bytes:
    cipher = RC4(key)
    return cipher.encrypt(plaintext)


def rc4_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = RC4(key)
    return cipher.decrypt(ciphertext)


# ─── Quick demo ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    key = b"SecretKey123"
    message = b"Hello, SecureVault!"

    ct = rc4_encrypt(key, message)
    pt = rc4_decrypt(key, ct)

    print(f"[RC4] Key       : {key}")
    print(f"[RC4] Plaintext : {message}")
    print(f"[RC4] Ciphertext: {ct.hex()}")
    print(f"[RC4] Decrypted : {pt}")
    assert pt == message, "RC4 decryption failed!"
    print("[RC4] ✓ Test passed")
