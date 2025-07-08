# ADVANCED_ENCRYPTION_TOOL.py
import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashlib.sha256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=backend
    )
    return kdf.derive(password.encode())

def encrypt_file(filepath: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)

    with open(filepath, 'rb') as f:
        data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    # PKCS7 padding
    pad_len = 16 - len(data) % 16
    data += bytes([pad_len] * pad_len)

    encrypted = encryptor.update(data) + encryptor.finalize()

    out_path = filepath + '.enc'
    with open(out_path, 'wb') as f:
        f.write(salt + iv + encrypted)

    print(f'Encrypted file saved to {out_path}')

def decrypt_file(enc_path: str, password: str):
    with open(enc_path, 'rb') as f:
        raw = f.read()

    salt = raw[:16]
    iv = raw[16:32]
    encrypted = raw[32:]
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()

    # Remove PKCS7 padding
    pad_len = decrypted[-1]
    decrypted = decrypted[:-pad_len]

    out_path = enc_path.replace('.enc', '.dec')
    with open(out_path, 'wb') as f:
        f.write(decrypted)

    print(f'Decrypted file saved to {out_path}')
