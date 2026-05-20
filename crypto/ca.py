"""
Certificate Authority (CA) — Implemented from scratch
======================================================
Simulates a root CA that:
  • Holds an ElGamal root key pair (generated once, saved to ca_root.json)
  • Issues certificates: subject name + party's ElGamal public key + CA signature
  • Verifies certificate authenticity via ElGamal Digital Signature

ElGamal Digital Signature:
  Sign(m):   choose random k coprime with p-1
             r = g^k mod p
             s = (H(m) - x·r) · k⁻¹ mod (p-1)
  Verify:    g^H(m) ≡ y^r · r^s (mod p)
  y = g^x (mod p)
  where H(m) = MD5(message) as integer.
"""

import json, os, random
from datetime import datetime, timezone

# reuse prime utilities already in the project
from crypto.elgamal import _generate_prime, _find_primitive_root
from crypto.md5 import md5_hex

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CA_STATE_FILE = os.path.join(_BASE, 'ca_root.json')


# ── Math helpers ──────────────────────────────────────────────────────────────

def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def _ext_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _ext_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _modinv(a, m):
    g, x, _ = _ext_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse: gcd={g}")
    return x % m


def _hash_int(data: str) -> int:
    """MD5 of data string → 128-bit integer."""
    return int(md5_hex(data.encode('utf-8')), 16)


# ── Certificate Authority ─────────────────────────────────────────────────────

class CertificateAuthority:
    """
    Root CA.  Call CertificateAuthority() in server.py (creates ca_root.json)
    and in client.py (loads the existing ca_root.json).
    """

    def __init__(self, bits: int = 256):
        self.bits = bits
        self._load_or_generate()

    # ── Key management ────────────────────────────────────────────────────────

    def _load_or_generate(self):
        if os.path.exists(CA_STATE_FILE):
            with open(CA_STATE_FILE, 'r') as fh:
                s = json.load(fh)
            self.p = int(s['p'])
            self.g = int(s['g'])
            self.x = int(s['x'])   # private
            self.y = int(s['y'])   # public
            print(f"[CA] Root key loaded from ca_root.json")
        else:
            self._generate()

    def _generate(self):
        print(f"[CA] Generating {self.bits}-bit root key pair…")
        self.p = _generate_prime(self.bits)
        self.g = _find_primitive_root(self.p)
        self.x = random.randint(2, self.p - 2)
        self.y = pow(self.g, self.x, self.p)
        state = {'p': str(self.p), 'g': str(self.g),
                 'x': str(self.x), 'y': str(self.y)}
        with open(CA_STATE_FILE, 'w') as fh:
            json.dump(state, fh, indent=2)
        print(f"[CA] Root key saved to ca_root.json")

    @property
    def public_key(self) -> dict:
        return {'p': str(self.p), 'g': str(self.g), 'y': str(self.y)}

    # ── ElGamal signature ─────────────────────────────────────────────────────

    def _sign(self, h: int) -> tuple:
        """Sign integer h. Returns (r, s)."""
        phi = self.p - 1
        for _ in range(1000):
            k = random.randint(2, phi - 1)
            if _gcd(k, phi) != 1:
                continue
            r = pow(self.g, k, self.p)
            s = (_modinv(k, phi) * (h - self.x * r)) % phi
            if s != 0:
                return (r, s)
        raise RuntimeError("ElGamal sign failed after 1000 attempts")

    @staticmethod
    def _verify_sig(p: int, g: int, y: int, h: int, r: int, s: int) -> bool:
        if not (0 < r < p):
            return False
        lhs = pow(g, h, p)
        rhs = (pow(y, r, p) * pow(r, s, p)) % p
        return lhs == rhs

    # ── Certificate operations ────────────────────────────────────────────────

    def _cert_payload(self, subject: str, elgamal_pub: dict, issued_at: str) -> str:
        return (f"{subject}|"
                f"{elgamal_pub['p']}|{elgamal_pub['g']}|{elgamal_pub['y']}|"
                f"{issued_at}")

    def issue_certificate(self, subject: str, elgamal_pub: dict) -> dict:
        """
        Issue a signed certificate for *subject* holding *elgamal_pub*.
        Returns a dict that can be sent over the network as JSON.
        """
        issued_at = datetime.now(timezone.utc).isoformat()
        # Normalise keys to strings for consistent hashing
        eg = {k: str(v) for k, v in elgamal_pub.items()}
        payload = self._cert_payload(subject, eg, issued_at)
        h = _hash_int(payload)
        r, s = self._sign(h)
        cert = {
            'subject':     subject,
            'elgamal_pub': eg,
            'issued_at':   issued_at,
            'issuer':      'SecureVault-RootCA',
            'ca_pub':      self.public_key,   # receivers need this to verify
            'sig_r':       str(r),
            'sig_s':       str(s),
        }
        print(f"[CA] Certificate issued for '{subject}'")
        return cert

    @staticmethod
    def verify_certificate(cert: dict) -> bool:
        """
        Verify a certificate without holding the CA private key.
        Anyone with the cert (which embeds ca_pub) can call this.
        """
        try:
            ca = cert['ca_pub']
            p, g, y = int(ca['p']), int(ca['g']), int(ca['y'])
            eg = cert['elgamal_pub']
            payload = (f"{cert['subject']}|"
                       f"{eg['p']}|{eg['g']}|{eg['y']}|"
                       f"{cert['issued_at']}")
            h = _hash_int(payload)
            r, s = int(cert['sig_r']), int(cert['sig_s'])
            return CertificateAuthority._verify_sig(p, g, y, h, r, s)
        except Exception:
            return False


# ── Quick demo ────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    from crypto.elgamal import ElGamal
    ca = CertificateAuthority(bits=256)

    party = ElGamal(bits=256)
    cert = ca.issue_certificate('Alice', party.public_key)
    ok = CertificateAuthority.verify_certificate(cert)
    print(f"[CA] Certificate valid: {ok}")
    assert ok, "CA verification failed!"
    print("[CA] ✓ Test passed")
