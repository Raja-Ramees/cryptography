# 🔐 Cryptography Algorithms Implementation

## 📌 Project Overview
This project demonstrates **advanced cryptography techniques** using Python:
- AES Encryption/Decryption (Symmetric)
- RSA Encryption/Decryption (Asymmetric)
- SHA-256 Hashing with Salt (Password Security)

The project simulates **real-world secure communication** and **password storage** mechanisms.

---

## 🚀 Features
1. **AES (Advanced Encryption Standard)**
   - Encrypts and decrypts text using a secret key.
   - Uses 256-bit key derived via SHA-256.
   - Random IV ensures unique encryption each time.

2. **RSA (Rivest–Shamir–Adleman)**
   - Public/Private key generation (2048 bits).
   - Secure message exchange.
   - Demonstrates asymmetric encryption.

3. **SHA-256 with Salt**
   - Password hashing for secure storage.
   - Salt ensures protection against rainbow table attacks.

---

## ⚙️ Requirements
- Python 3.10+
- Libraries:
  ```bash
  pip install pycryptodome

