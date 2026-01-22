"""Cryptographic security utilities with Argon2id, PBKDF2, and RSA."""

import base64
import hashlib
import os

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

argon2_ph = PasswordHasher()

# EXPLANATION:
# We're using Argon2id for password hashing
# RSA keypair for asymmetric encryption
# PBKDF2 + AES-GCM for private key encryption
# We store encrypted private key in database so you can log in from anywhere and decrypt messages.
# Encrypted private key is transmitted during login/signup (frontend decrypts it with password).
# Only plaintext private key stays on frontend (never sent back to backend after decryption).
# This enables E2EE: frontend encrypts with recipient's public key, only recipient can decrypt with their private key.


def get_password_hash(password: str) -> str:
    return argon2_ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        argon2_ph.verify(hashed_password, plain_password)
        return True
    except VerifyMismatchError:
        return False


def generate_rsa_keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(
        public_exponent=settings.RSA_PUBLIC_EXPONENT,
        key_size=settings.RSA_KEY_SIZE,
        backend=default_backend(),
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return (
        base64.b64encode(private_pem).decode(),
        base64.b64encode(public_pem).decode(),
    )


# Private key encryption (PBKDF2 + AES-GCM)
def encrypt_private_key(private_key_pem: str, password: str) -> tuple[str, str]:
    salt = os.urandom(settings.PBKDF2_SALT_SIZE)
    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, settings.PBKDF2_ITERATIONS
    )

    cipher = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, private_key_pem.encode(), None)

    encrypted_data = nonce + ciphertext
    return base64.b64encode(encrypted_data).decode(), base64.b64encode(salt).decode()


def decrypt_private_key(
    encrypted_private_key_b64: str, salt_b64: str, password: str
) -> str:
    encrypted_data = base64.b64decode(encrypted_private_key_b64)
    salt = base64.b64decode(salt_b64)

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, settings.PBKDF2_ITERATIONS
    )
    cipher = AESGCM(key)

    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except InvalidTag:
        raise ValueError("Invalid password or corrupted data")
