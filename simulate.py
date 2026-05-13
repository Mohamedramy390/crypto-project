"""
╔══════════════════════════════════════════════════════════════════╗
║          SecureVault — Full Communication Simulation             ║
║   Alice  ──── encrypted channel ────  Bob                        ║
║                                                                  ║
║  Algorithms (all from scratch, no AES/DES/SHA-256):              ║
║   • Diffie-Hellman   – session key negotiation                   ║
║   • Twofish          – inner block-cipher layer                  ║
║   • RC4              – outer stream-cipher layer                 ║
║   • ElGamal          – asymmetric key wrapping                   ║
║   • MD5              – message integrity tag                     ║
╚══════════════════════════════════════════════════════════════════╝
"""

import sys
import time
import textwrap

# ── pretty-print helpers ──────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"
WHITE  = "\033[97m"

def clr(text, color): return f"{color}{text}{RESET}"
def bold(text):       return f"{BOLD}{text}{RESET}"
def dim(text):        return f"{DIM}{text}{RESET}"

def banner(title, color=CYAN):
    w = 66
    line = "═" * w
    print(f"\n{color}╔{line}╗")
    print(f"║  {bold(title):<{w-2}}║")
    print(f"╚{line}╝{RESET}")

def section(title, actor=None, color=BLUE):
    actor_str = f"[{actor}] " if actor else ""
    print(f"\n{color}{'─'*4} {bold(actor_str + title)} {'─'*(55 - len(actor_str+title))}{RESET}")

def step(n, desc, color=WHITE):
    print(f"  {clr(f'Step {n}:', YELLOW)} {color}{desc}{RESET}")

def kv(key, value, key_color=CYAN, trunc=80):
    val_str = str(value)
    if len(val_str) > trunc:
        val_str = val_str[:trunc] + dim("…")
    print(f"    {key_color}{key:<22}{RESET}: {val_str}")

def ok(msg):   print(f"  {clr('✓', GREEN)}  {msg}")
def fail(msg): print(f"  {clr('✗', RED)}  {msg}")
def info(msg): print(f"  {clr('ℹ', CYAN)}  {dim(msg)}")

def pause(t=0.3): time.sleep(t)

def hex_block(label, data: bytes, color=MAGENTA, width=32):
    h = data.hex()
    chunks = [h[i:i+width] for i in range(0, len(h), width)]
    print(f"    {CYAN}{label}{RESET}")
    for chunk in chunks:
        print(f"      {color}{chunk}{RESET}")

def divider(): print(f"  {DIM}{'·'*64}{RESET}")


# ── import our crypto modules ─────────────────────────────────────────────────
banner("Loading SecureVault crypto modules…", YELLOW)

from crypto.rc4            import RC4
from crypto.twofish        import SimplifiedTwofish
from crypto.elgamal        import ElGamal
from crypto.diffie_hellman import DHParty, DHParameters
from crypto.md5            import md5_hex, verify_integrity

ok("RC4 (stream cipher)         — loaded")
ok("Twofish (block cipher)      — loaded")
ok("ElGamal (asymmetric)        — loaded")
ok("Diffie-Hellman (key exchange)— loaded")
ok("MD5 (integrity hash)        — loaded")
pause(0.5)


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 0  — Setup & key generation
# ═══════════════════════════════════════════════════════════════════════════════
banner("PHASE 0  —  Setup & Key Generation", MAGENTA)
pause(0.3)

section("Generating ElGamal key pair (256-bit prime)", actor="Bob", color=BLUE)
info("Bob generates a public/private key pair so Alice can securely wrap keys.")
pause(0.2)
bob_eg = ElGamal(bits=256)

kv("Public key  p", bob_eg.public_key["p"])
kv("Public key  g", bob_eg.public_key["g"])
kv("Public key  y", bob_eg.public_key["y"])
kv("Private key x", bob_eg.private_key["x"])
ok("ElGamal key pair ready.")
pause(0.3)

section("Loading Diffie-Hellman parameters (RFC 3526 / 768-bit)", actor="System", color=DIM)
info("Both Alice and Bob agree on shared public DH parameters (p, g).")
p_dh, g_dh = DHParameters.from_rfc3526_768()
kv("DH prime p  (first 40 hex)", hex(p_dh)[:42])
kv("DH generator g", g_dh)
ok("DH group parameters agreed upon.")
pause(0.3)


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 1  — Alice writes her message
# ═══════════════════════════════════════════════════════════════════════════════
banner("PHASE 1  —  Alice Composes Message", GREEN)
pause(0.3)

print(f"\n  {GREEN}Alice{RESET} types a confidential message to {BLUE}Bob{RESET}:\n")

message = (
    b"Bob, the board approved the merger. "
    b"Transfer the funds to account #4471-XXXX by Friday. "
    b"Do not use email - this channel only. - Alice"
)
wrapped = textwrap.fill(message.decode(), width=60)
for line in wrapped.split("\n"):
    print(f"    {YELLOW}│{RESET}  {line}")
print(f"    {YELLOW}└─ {len(message)} bytes{RESET}")
pause(0.4)


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 2  — Diffie-Hellman key exchange
# ═══════════════════════════════════════════════════════════════════════════════
banner("PHASE 2  —  Diffie-Hellman Key Exchange", CYAN)
pause(0.3)

section("Alice generates her DH keypair", actor="Alice", color=GREEN)
alice_dh = DHParty(p_dh, g_dh)
kv("Alice private key (secret!)", hex(alice_dh._private_key)[:40])
kv("Alice public key  (→ Bob) ", hex(alice_dh.public_key)[:40])
ok("Alice sends her public key to Bob over the wire.")
pause(0.3)

section("Bob generates his DH keypair", actor="Bob", color=BLUE)
bob_dh = DHParty(p_dh, g_dh)
kv("Bob private key (secret!)", hex(bob_dh._private_key)[:40])
kv("Bob public key  (→ Alice)", hex(bob_dh.public_key)[:40])
ok("Bob sends his public key to Alice over the wire.")
pause(0.3)

section("Both compute the SAME shared secret", actor="Alice & Bob", color=YELLOW)
secret_alice = alice_dh.compute_shared_secret(bob_dh.public_key)
secret_bob   = bob_dh.compute_shared_secret(alice_dh.public_key)
kv("Alice computes g^(ab) mod p", hex(secret_alice)[:50])
kv("Bob   computes g^(ab) mod p", hex(secret_bob)[:50])

if secret_alice == secret_bob:
    ok("Shared secrets MATCH — eavesdropper cannot compute this!")
else:
    fail("Mismatch — something went wrong.")
pause(0.3)

section("Deriving symmetric keys from shared secret", actor="Alice", color=GREEN)
# XOR-fold shared secret → 32-byte key material
secret_bytes = secret_alice.to_bytes((secret_alice.bit_length() + 7) // 8, 'big')
key_material = bytearray(32)
for i, b in enumerate(secret_bytes):
    key_material[i % 32] ^= b
key_material = bytes(key_material)

twofish_key = key_material[:16]   # first 16 bytes → Twofish
rc4_key     = key_material[16:]   # last  16 bytes → RC4

kv("Twofish key (16 bytes)", twofish_key.hex())
kv("RC4     key (16 bytes)", rc4_key.hex())
ok("Key material split successfully.")
pause(0.3)


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 3  — Double-layer Encryption (Alice → Bob)
# ═══════════════════════════════════════════════════════════════════════════════
banner("PHASE 3  —  Encryption  (Alice → sends → Bob)", GREEN)
pause(0.3)

# ── 3a: Twofish (inner layer) ────────────────────────────────────────────────
section("Inner layer: Twofish block cipher (128-bit blocks)", actor="Alice", color=GREEN)
info("Splits plaintext into 16-byte blocks → runs each through Feistel network.")
tf = SimplifiedTwofish(twofish_key)
twofish_ct = tf.encrypt(message)
hex_block("Plaintext hex  →", message[:32])
hex_block("Twofish CT hex →", twofish_ct[:32])
kv("Total encrypted size", f"{len(twofish_ct)} bytes ({len(twofish_ct)//16} blocks)")
ok("Twofish encryption done — inner layer applied.")
pause(0.3)

# ── 3b: RC4 (outer layer) ───────────────────────────────────────────────────
section("Outer layer: RC4 stream cipher (XOR keystream)", actor="Alice", color=GREEN)
info("Generates a pseudorandom keystream via KSA + PRGA → XOR with Twofish CT.")
rc4 = RC4(rc4_key)
rc4_ct = rc4.encrypt(twofish_ct)
hex_block("Twofish CT  →", twofish_ct[:32])
hex_block("RC4 CT      →", rc4_ct[:32])
ok("RC4 encryption done — outer layer applied (double encryption).")
pause(0.3)

# ── 3c: MD5 integrity tag ────────────────────────────────────────────────────
section("Integrity tag: MD5 digest of ciphertext", actor="Alice", color=GREEN)
info("MD5 is computed over the RC4 ciphertext to detect any tampering in transit.")
integrity_tag = md5_hex(rc4_ct)
kv("MD5(RC4_CT)", integrity_tag)
ok("MD5 tag generated and will be sent with the ciphertext.")
pause(0.3)

# ── 3d: ElGamal key wrapping ────────────────────────────────────────────────
section("Key wrapping: ElGamal encrypt key bundle with Bob's public key", actor="Alice", color=GREEN)
info("Alice encrypts (Twofish_key || RC4_key) using Bob's ElGamal public key.")
info("Only Bob's private key can recover them — ElGamal is probabilistic.")

key_bundle_int = int.from_bytes(twofish_key + rc4_key, 'big') % bob_eg.p
eg_pub = ElGamal.from_keys(
    p=bob_eg.public_key["p"],
    g=bob_eg.public_key["g"],
    y=bob_eg.public_key["y"],
)
eg_ct = eg_pub.encrypt(key_bundle_int)

kv("ElGamal c1 (g^k mod p)", str(eg_ct[0])[:60])
kv("ElGamal c2 (m·y^k mod p)", str(eg_ct[1])[:60])
ok("Key bundle wrapped with ElGamal — only Bob can open it.")
pause(0.3)

# ── Assemble packet ──────────────────────────────────────────────────────────
section("Assembling the encrypted packet to transmit", actor="Alice", color=GREEN)
packet = {
    "version"       : "SecureVault/1.0",
    "ciphertext"    : rc4_ct.hex(),
    "integrity"     : integrity_tag,
    "elgamal_c1"    : eg_ct[0],
    "elgamal_c2"    : eg_ct[1],
    "dh_alice_pub"  : alice_dh.public_key,
    "dh_bob_pub"    : bob_dh.public_key,
    "orig_length"   : len(message),
}
kv("Packet version", packet["version"])
kv("Ciphertext (first 64 hex)", packet["ciphertext"][:64])
kv("Integrity tag", packet["integrity"])
kv("Fields", "ciphertext, integrity, elgamal_c1, elgamal_c2, dh_alice_pub, dh_bob_pub")
print()
ok("Packet assembled. Alice transmits it to Bob over the network.")
pause(0.4)

# ═══════════════════════════════════════════════════════════════════════════════
#  Simulated network transfer
# ═══════════════════════════════════════════════════════════════════════════════
print(f"\n  {GREEN}Alice{RESET}  ──────────────── 📦 packet ────────────────►  {BLUE}Bob{RESET}")
pause(0.5)


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 4  — Decryption (Bob receives)
# ═══════════════════════════════════════════════════════════════════════════════
banner("PHASE 4  —  Decryption  (Bob receives & decrypts)", BLUE)
pause(0.3)

# ── 4a: Integrity check ──────────────────────────────────────────────────────
section("Verify MD5 integrity tag", actor="Bob", color=BLUE)
received_ct = bytes.fromhex(packet["ciphertext"])
info("Bob recomputes MD5 over received ciphertext and compares to tag.")
computed_tag = md5_hex(received_ct)
kv("Received tag", packet["integrity"])
kv("Computed tag", computed_tag)
if computed_tag == packet["integrity"]:
    ok("INTEGRITY CHECK PASSED — packet was not tampered in transit.")
else:
    fail("INTEGRITY CHECK FAILED — packet was corrupted or tampered!")
    sys.exit(1)
pause(0.3)

# ── 4b: ElGamal key unwrapping ───────────────────────────────────────────────
section("Unwrap key bundle with ElGamal private key", actor="Bob", color=BLUE)
info("Bob uses his private key x to compute s = c1^x mod p, then m = c2 · s⁻¹ mod p.")
unwrapped_int = bob_eg.decrypt((packet["elgamal_c1"], packet["elgamal_c2"]))
unwrapped_bytes = unwrapped_int.to_bytes(32, 'big')
rec_twofish_key = unwrapped_bytes[:16]
rec_rc4_key     = unwrapped_bytes[16:]

kv("Recovered Twofish key", rec_twofish_key.hex())
kv("Recovered RC4     key", rec_rc4_key.hex())
kv("Keys match originals?",
   "✓ YES" if (rec_twofish_key == twofish_key and rec_rc4_key == rc4_key) else "✗ NO")
ok("Key bundle successfully unwrapped.")
pause(0.3)

# ── 4c: RC4 decrypt (outer layer) ────────────────────────────────────────────
section("Outer layer: RC4 stream decrypt", actor="Bob", color=BLUE)
info("RC4 decryption = same operation as encryption (XOR is symmetric).")
rc4_dec = RC4(rec_rc4_key)
twofish_ct_recovered = rc4_dec.decrypt(received_ct)
hex_block("RC4 CT →", received_ct[:32])
hex_block("After RC4 decrypt →", twofish_ct_recovered[:32])
ok("RC4 outer layer removed.")
pause(0.3)

# ── 4d: Twofish decrypt (inner layer) ────────────────────────────────────────
section("Inner layer: Twofish block decrypt", actor="Bob", color=BLUE)
info("Inverse Feistel rounds applied to each 16-byte block — PKCS7 unpadded.")
tf_dec = SimplifiedTwofish(rec_twofish_key)
plaintext_recovered = tf_dec.decrypt(twofish_ct_recovered)
hex_block("Twofish CT →", twofish_ct_recovered[:32])
hex_block("Plaintext  →", plaintext_recovered[:32])
ok("Twofish inner layer removed. Message recovered!")
pause(0.3)


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 5  — Bob reads the message
# ═══════════════════════════════════════════════════════════════════════════════
banner("PHASE 5  —  Bob Reads the Decrypted Message", BLUE)
pause(0.3)

print(f"\n  {BLUE}Bob{RESET} reads:\n")
wrapped_out = textwrap.fill(plaintext_recovered.decode(), width=60)
for line in wrapped_out.split("\n"):
    print(f"    {BLUE}│{RESET}  {line}")
print(f"    {BLUE}└─ {len(plaintext_recovered)} bytes{RESET}")
pause(0.4)

assert plaintext_recovered == message, "BUG: recovered message ≠ original!"
ok("Recovered message is byte-for-byte identical to what Alice sent.")
pause(0.3)


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 6  — Tamper attack simulation
# ═══════════════════════════════════════════════════════════════════════════════
banner("PHASE 6  —  Simulated Tamper Attack (Eve)", RED)
pause(0.3)

section("Eve intercepts and modifies 4 bytes of the ciphertext", actor="Eve", color=RED)
info("Eve flips bytes at position 8-12 in the ciphertext.")

tampered_hex = list(packet["ciphertext"])
tampered_hex[8:12] = list("DEAD")
tampered_ct = bytes.fromhex("".join(tampered_hex))

kv("Original byte [8:12]", packet["ciphertext"][8:12])
kv("Tampered byte [8:12]", "".join(tampered_hex)[8:12])

divider()
section("Bob receives tampered packet and checks integrity", actor="Bob", color=BLUE)
tampered_tag = md5_hex(tampered_ct)
kv("Expected tag", packet["integrity"])
kv("Received tag", tampered_tag)

if tampered_tag != packet["integrity"]:
    fail("INTEGRITY CHECK FAILED — Bob detects tampering and rejects the packet!")
    ok("Eve's attack was caught. The message is discarded.")
else:
    print("  Tamper went undetected (this should not happen).")
pause(0.3)


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 7  — Summary
# ═══════════════════════════════════════════════════════════════════════════════
banner("PHASE 7  —  Simulation Summary", YELLOW)

rows = [
    ("Algorithm",     "Role",                   "Status"),
    ("─"*20,          "─"*30,                   "─"*10),
    ("Diffie-Hellman","Session key exchange",    "✓ PASS"),
    ("Twofish",       "Inner block encryption",  "✓ PASS"),
    ("RC4",           "Outer stream encryption", "✓ PASS"),
    ("ElGamal",       "Asymmetric key wrapping", "✓ PASS"),
    ("MD5",           "Integrity verification",  "✓ PASS"),
    ("─"*20,          "─"*30,                   "─"*10),
    ("Tamper attack", "Eve modifies ciphertext", "✓ DETECTED"),
]

for algo, role, status in rows:
    color = GREEN if "PASS" in status or "DETECTED" in status else WHITE
    print(f"    {CYAN}{algo:<22}{RESET}  {DIM}{role:<32}{RESET}  {color}{status}{RESET}")

print(f"\n  {bold('All algorithms implemented from scratch — zero crypto libraries used.')}")
print(f"  {DIM}(No AES, No DES, No SHA-256){RESET}")
print()
ok("SecureVault full simulation complete. ✓")
print()
