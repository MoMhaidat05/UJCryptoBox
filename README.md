# UJ CryptoBox - RSA CTF Toolkit

A practical RSA exploitation sandbox for CTF players who want a clean workflow for key recovery, weak-key attacks, and fast decryption checks.

## Why This Toolkit

`uj_rsa_toolkit.py` provides a focused, interactive CLI for common RSA CTF scenarios without forcing you to switch between multiple scripts.

## Features

- Interactive menu-driven operator console built with Rich.
- In-memory RSA workspace for `N, e, c, p, q, r, totient, d`.
- FactorDB integration with selective import of discovered factors.
- Automatic `N` synchronization when working from stored prime factors.
- Totient calculation for:
  - One-prime mode
  - Two-prime RSA
  - Multi-prime RSA (`p, q, r`)
- Private key derivation with modular inverse (`d = e^-1 mod phi`).
- Standard RSA decryption from `c, d, N`.
- Low exponent / dropped-modulo support via exact integer root extraction.
- Wiener attack module for weak private exponent recovery.

## Typical CTF Use Cases

- Low exponent attack cases where ciphertext is an exact power.
- Multi-prime RSA challenges where `N = p * q * r`.
- Scenarios requiring quick FactorDB-assisted factor intake.
- Wiener-vulnerable keys with small private exponent `d`.

## Installation

### 1) Clone the repository

```bash
git clone https://github.com/MoMhaidat05/UJCryptoBox.git
cd UJ-CryptoBox
```

### 2) Create and activate a virtual environment

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux / macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3) Install dependencies

```bash
pip install -r requirements.txt
```

### 4) Run the toolkit

```bash
python uj_rsa_toolkit.py
```

## Dependency Notes

The toolkit currently depends on:

- `gmpy2`
- `pycryptodome`
- `requests`
- `rich`

All are listed in `requirements.txt` with minimum versions.

## Security and Ethics Disclaimer

This project is provided strictly for educational use, CTF practice, and authorized security research. Do not use it against systems, keys, or services without explicit permission.

