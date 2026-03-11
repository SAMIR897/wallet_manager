# 🔐 Wallet Manager

A Rust CLI tool for generating HD (Hierarchical Deterministic) Ethereum wallets with AES-256-GCM encrypted mnemonic storage.

## Features

- Generates **BIP-39** 12-word mnemonic phrases
- Derives Ethereum addresses from mnemonic
- Encrypts mnemonic with **AES-256-GCM** using a user-provided password
- Key derivation via Keccak-256 with random salt
- Saves/loads encrypted wallet from a local JSON file

## Usage

```bash
cargo run
```

### Create a New Wallet

```
Wallet Manager
1. Create new wallet
2. Load existing wallet
Choose an option: 1

Generating new wallet...
Mnemonic phrase: abandon badge camera ... zone zoo
Please store this phrase securely!

Wallet successfully generated!
Derived Address: 0xAbCd...1234
Enter a strong password to encrypt the keystore: ****
Wallet encrypted and saved to "encrypted_wallet.json"
```

### Load Existing Wallet

```
Choose an option: 2
Enter password to decrypt wallet: ****
Successfully decrypted wallet!
Address: 0xAbCd...1234
Mnemonic: abandon badge camera ... zone zoo
```

## Security

- Mnemonic is encrypted at rest using AES-256-GCM
- Password never stored — only used to derive the encryption key
- Random salt and nonce generated per encryption

## Tech Stack

- `ethers` — Wallet derivation, Keccak-256 hashing
- `aes-gcm` / `aead` — AES-256-GCM encryption
- `bip39` — Mnemonic generation
- `rpassword` — Secure password input (hidden from terminal)
- `serde` / `serde_json` — JSON serialization
