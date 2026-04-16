# 🔐 CryptoStudio: The Ultimate Crypto & Encoding Toolkit

CryptoStudio is a premium, privacy-first web application designed for seamless string conversion, encoding, and industrial-grade encryption—all handled entirely within your browser. 

![CryptoStudio Banner](https://img.shields.io/badge/Privacy-100%25-emerald) ![Tech](https://img.shields.io/badge/Tech-HTML%20%7C%20TailwindCSS%20%7C%20JS-blue) ![License](https://img.shields.io/badge/License-Apache%202.0-orange)

## ✨ Key Features

### 🛠️ Encoding & Decoding
Quickly transform data between popular formats:
- **Binary & Hexadecimal**: Standard low-level data representations.
- **Base64, Base32, Base58**: Industry-standard text encodings (including Bitcoin-style Base58).
- **URI Component**: Web-safe URL encoding.

### 🛡️ Symmetric Encryption
Secure your sensitive information with multiple algorithms:
- **AES (Advanced Encryption Standard)**: The gold standard for modern encryption.
- **Rabbit**: Specialized cipher for stream encryption.
- **⚠️ Legacy/Insecure Ciphers** (NOT recommended for sensitive data): TripleDES, RC4, XOR.
- **🚀 Enhanced Protection (Vault Mode)**: Up to 7 levels of PBKDF2 key derivation iterations. Level 7 ("Vault Mode") provides extreme resistance against brute-force attacks by introducing significant computational work.

> **⚠️ Security Notice**: Iteration levels 1-3 provide insufficient protection and should not be used for sensitive data. Always use level 4 or higher for production use.

### 🔑 PGP (Pretty Good Privacy)
Full suite of OpenPGP tools powered by `openpgp.js`:
- **Encrypt & Decrypt**: Secure message exchange using public/private key pairs.
- **Sign & Verify**: Ensure message integrity and sender authenticity.
- **Key Generation**: Dedicated generator for **RSA (2048/4096)** and **ECC (Curve25519)** keys.

### 💎 Premium User Experience
- **Responsive Interface**: High-iteration cryptographic tasks are offloaded to **Web Workers**, keeping the UI responsive.
- **Security First**: All operations are performed locally. No data ever leaves your machine or is sent to a server.
- **Modern Aesthetics**: A sleek, dark-themed UI built with **TailwindCSS** and refined with **Inter** and **JetBrains Mono** typography.
- **Secure Key Bundling**: Download your generated PGP keys in a password-protected (ZipCrypto) ZIP archive.

## 🚀 Getting Started

Simply open `index.html` in any modern web browser to begin. No installation or account is required.

1. **Select Category**: Choose between Encoding, Encryption, or PGP.
2. **Configure**: Select your algorithm and enter your keys or passphrases.
3. **Process**: Enter your input text; the transformation happens in real-time or via the "Process" trigger.
4. **Copy & Save**: Use the one-click copy button to retrieve your result.

## 🛠️ Technology Stack

- **Frontend**: HTML5, Vanilla JavaScript.
- **Styling**: TailwindCSS (CDN-based for portability).
- **Cryptography**: 
  - [CryptoJS](https://github.com/brix/crypto-js) for symmetric ciphers and base encodings.
  - [OpenPGP.js](https://openpgpjs.org/) for PGP operations and key generation.
  - [Zip.js](https://gildas-lormeau.github.io/zip.js/) for secure key packaging.

## 📜 License

Distributed under the **Apache 2.0 License**. See `LICENSE` for more information.

---

*Handcrafted for privacy and performance.* 🌑✨
