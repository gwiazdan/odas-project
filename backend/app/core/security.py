"""Cryptographic security utilities with Argon2id, PBKDF2, and RSA."""

import base64
import hashlib
import os

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

argon2_ph = PasswordHasher()
RSA_KEY_SIZE = 4096
RSA_PUBLIC_EXPONENT = 65537
PBKDF2_ITERATIONS = 480000
PBKDF2_SALT_SIZE = 32


# Password hashing
def get_password_hash(password: str) -> str:
    return argon2_ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        argon2_ph.verify(hashed_password, plain_password)
        return True
    except VerifyMismatchError:
        return False


# RSA keypair
def generate_rsa_keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
        backend=default_backend(),
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    return private_pem, public_pem


# Private key encryption (PBKDF2 + AES-GCM)
def encrypt_private_key(private_key_pem: str, password: str) -> tuple[str, str]:
    salt = os.urandom(PBKDF2_SALT_SIZE)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)

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

    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    cipher = AESGCM(key)

    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except InvalidTag:
        raise ValueError("Invalid password or corrupted data")


# Message encryption/decryption (RSA-OAEP)
def encrypt_message(message_bytes: bytes, recipient_public_key_pem: str) -> str:
    public_key = serialization.load_pem_public_key(
        recipient_public_key_pem.encode(),
        backend=default_backend(),
    )

    ciphertext = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return base64.b64encode(ciphertext).decode()


def decrypt_message(encrypted_message_b64: str, private_key_pem: str) -> bytes:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend(),
    )

    ciphertext = base64.b64decode(encrypted_message_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return plaintext


# Message signing/verification (RSA-PSS)
def sign_message(message_bytes: bytes, private_key_pem: str) -> str:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend(),
    )

    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return base64.b64encode(signature).decode()


def verify_message_signature(
    message_bytes: bytes, signature_b64: str, sender_public_key_pem: str
) -> bool:
    public_key = serialization.load_pem_public_key(
        sender_public_key_pem.encode(),
        backend=default_backend(),
    )

    signature = base64.b64decode(signature_b64)

    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
