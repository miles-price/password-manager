from __future__ import annotations

import base64
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 390_000
SALT_SIZE = 16


def generate_salt() -> str:
    return base64.b64encode(os.urandom(SALT_SIZE)).decode("utf-8")


def derive_key(master_password: str, salt_b64: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.b64decode(salt_b64.encode("utf-8")),
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


def encrypt_text(plaintext: str, key: bytes) -> str:
    return Fernet(key).encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_text(ciphertext: str, key: bytes) -> str:
    try:
        return Fernet(key).decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Failed to decrypt data. Master password may be incorrect.") from exc
