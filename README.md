# Advanced Encryption Tool

## About
A Python-based tool for encrypting and decrypting files using AES encryption.

## Features
- File encryption
- File decryption
- Password-based key derivation using PBKDF2
- Random salt and initialization vector

## Requirements
- Python 3
- Cryptography library

## Installation

Install the required library:

```bash
pip install cryptography
```

## Usage

Import the functions:

```python
from ADVANCED_ENCRYPTION_TOOL import encrypt_file, decrypt_file
```

Encrypt a file:

```python
encrypt_file("sample.txt", "mypassword")
```

Decrypt the encrypted file:

```python
decrypt_file("sample.txt.enc", "mypassword")
```

## Output
- Encrypted file: sample.txt.enc
- Decrypted file: sample.txt.dec

## License
Refer to the repository license before using or distributing this project.