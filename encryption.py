"""
encryption.py — AES-256 encryption for sensitive user data.

Uses AES-256-CBC with a random IV per encryption operation.
Keys are derived from a master password via PBKDF2-HMAC-SHA256.

Stored format (base64):  SALT(16) + IV(16) + CIPHERTEXT
"""

import os
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Master key — in production load from environment variable / AWS Secrets Manager
MASTER_PASSWORD = os.environ.get("MASTER_PASSWORD", "CodeAlpha@SecretKey#2024!")
ITERATIONS = 200_000  # PBKDF2 rounds


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password + salt using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS,
        dklen=32,
    )


def encrypt(plaintext: str) -> str:
    """
    Encrypt plaintext with AES-256-CBC.
    Returns a base64-encoded string: SALT + IV + CIPHERTEXT.
    """
    salt = os.urandom(16)
    iv   = os.urandom(16)
    key  = _derive_key(MASTER_PASSWORD, salt)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher     = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor  = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    blob = salt + iv + ciphertext
    return base64.b64encode(blob).decode("utf-8")


def decrypt(token: str) -> str:
    """Decrypt a token produced by encrypt()."""
    blob = base64.b64decode(token.encode("utf-8"))
    salt       = blob[:16]
    iv         = blob[16:32]
    ciphertext = blob[32:]
    key        = _derive_key(MASTER_PASSWORD, salt)

    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded    = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder  = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-8")


def hash_password(password: str) -> str:
    """One-way PBKDF2 hash for passwords (for login verification)."""
    salt = os.urandom(16)
    dk   = _derive_key(password, salt)
    return base64.b64encode(salt + dk).decode("utf-8")


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash (constant-time compare)."""
    blob = base64.b64decode(stored_hash.encode("utf-8"))
    salt = blob[:16]
    stored_dk = blob[16:]
    derived   = _derive_key(password, salt)
    return hmac.compare_digest(derived, stored_dk)
