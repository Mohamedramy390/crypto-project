# 🔐 SecureVault — Cryptographic Pipeline

A full cryptographic communication system built **from scratch**.
---

## 👥 Team Members

| Name | ID |
|---|---|
| Mohamed Ramy | 320230086 |
| Omar Elragabi | 320230206 |
| Yousef Hamed | 320230192 |

---

## 🔬 Algorithms Implemented

| Algorithm | Type | Role |
|---|---|---|
| ECDH (P-256) | Asymmetric | Session key exchange |
| HKDF-MD5 (KDF) | Key Derivation | Derive symmetric keys from shared secret |
| Twofish | Symmetric (Block) | Inner encryption layer |
| RC4 | Symmetric (Stream) | Outer encryption layer |
| ElGamal | Asymmetric | Key wrapping / transport |
| MD5 | Hash | Message integrity verification |

---

## 🚀 How to Run

### Prerequisites

Install Flask (only needed once):

```bash
pip3 install flask --break-system-packages
```

### Option 1 — Web Simulation (Recommended)

Launches an interactive browser-based simulation of the full cryptographic pipeline.

```bash
cd crypto-project
python3 app.py
```

Then open your browser and go to:

```
http://localhost:5000
```

Type a message, click **"Run Full Simulation"**, and watch all 7 phases animate step by step.

---

### Option 2 — Terminal Simulation

Runs the full Alice → Bob simulation in the terminal with colored output.

```bash
cd crypto-project
python3 simulate.py
```

---

### Option 3 — Quick Pipeline Test

Runs a minimal self-test of the encrypt/decrypt pipeline and exits.

```bash
cd crypto-project
python3 securevault.py
```

---

## 📁 Project Structure

```
crypto-project/
├── app.py              # Flask web server
├── simulate.py         # Terminal simulation (colored, 7 phases)
├── securevault.py      # Core pipeline demo / self-test
├── templates/
│   └── index.html      # Web UI
└── crypto/
    ├── rc4.py          # RC4 stream cipher (from scratch)
    ├── twofish.py      # Twofish block cipher (from scratch)
    ├── elgamal.py      # ElGamal asymmetric cipher (from scratch)
    ├── ecdh_kdf.py     # ECDH P-256 + HKDF-MD5 (from scratch)
    └── md5.py          # MD5 hash (from scratch)
```

---

## 🔄 Simulation Phases

| Phase | Description |
|---|---|
| 0 | Setup — ElGamal key generation |
| 1 | Alice composes her message |
| 2 | ECDH P-256 key exchange + KDF |
| 3 | Double-layer encryption (Twofish → RC4 → MD5 → ElGamal wrap) |
| 4 | Decryption (Bob reverses all layers) |
| 5 | Bob reads the recovered message |
| 6 | Tamper attack — Eve modifies ciphertext, Bob detects it |
| 7 | Summary of all algorithm results |
