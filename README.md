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
| CA (ElGamal Sig) | PKI / Signature | Root Certificate Authority, issues & verifies identity certificates |
| ECDH (P-256) | Asymmetric | Session key exchange |
| HKDF-MD5 (KDF) | Key Derivation | Derive symmetric keys from shared secret |
| Twofish | Symmetric (Block) | Inner encryption layer |
| RC4 | Symmetric (Stream) | Outer encryption layer |
| ElGamal | Asymmetric | Key wrapping / transport |
| MD5 | Hash | Message integrity verification |

*(Note: Zero external cryptographic libraries are used. All math and logic is implemented purely from scratch.)*

---

## 🚀 How to Run

### Prerequisites

Install Flask (only needed once):

```bash
pip3 install flask --break-system-packages
```

### Option 1 — Live Chat Web GUI (New!)

Launches a beautiful split-screen browser chat that simulates the client, server, and CA all at once.

```bash
cd crypto-project
python3 chat_app.py
```

Then open your browser and go to: `http://localhost:5001`
- Click "Initialize" to generate keys and exchange certificates.
- Type a message on the Client side and watch the Server decrypt it.

### Option 2 — True Client-Server over TCP (New!)

Runs a real network simulation over raw TCP sockets on port 6000. 

**Terminal 1 (Start Server):**
```bash
cd crypto-project
python3 server.py
```
*(Wait until it says it's listening)*

**Terminal 2 (Start Client):**
```bash
cd crypto-project
python3 client.py
```
Type messages in the Client terminal and see them securely arrive at the Server.

### Option 3 — Original Web Simulation

Launches the interactive browser-based simulation of the 7-phase cryptographic pipeline.

```bash
cd crypto-project
python3 app.py
```
Go to `http://localhost:5000`, type a message, and click **"Run Full Simulation"** to watch the phases animate step by step.

### Option 4 — Original Terminal Simulation

Runs the full Alice → Bob simulation in the terminal with colored output.

```bash
cd crypto-project
python3 simulate.py
```

---

## 📁 Project Structure

```text
crypto-project/
├── crypto/
│   ├── ca.py             # Certificate Authority (ElGamal Digital Signatures)
│   ├── rc4.py            # RC4 stream cipher 
│   ├── twofish.py        # Twofish block cipher 
│   ├── elgamal.py        # ElGamal asymmetric cipher 
│   ├── ecdh_kdf.py       # ECDH P-256 + HKDF-MD5 
│   ├── md5.py            # MD5 hash 
│   └── diffie_hellman.py # Classic Diffie-Hellman
├── server.py             # Live TCP server
├── client.py             # Live TCP client
├── chat_app.py           # Live Web GUI Chat (port 5001)
├── app.py                # Web Simulation (port 5000)
├── simulate.py           # Terminal Simulation
├── securevault.py        # Minimal core pipeline demo 
├── templates/
│   ├── chat.html         # Web Chat UI
│   └── index.html        # Web Simulation UI
├── ca_root.json          # Auto-generated CA root key state
└── messages_log.json     # Persistent log of all messages and their ciphertexts
```

---

## 📜 Message Logging

Every time a message is encrypted and sent (either via the web interfaces or the TCP client-server), a full record is automatically saved to `messages_log.json`. This log includes:
- The original plaintext message.
- The state **before decryption** (raw ciphertext, integrity tag).
- The state **after decryption** (recovered message).
- Whether an integrity/tamper attack was detected.
