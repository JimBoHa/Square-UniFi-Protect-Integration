"""Credential encryption, password hashing, and session token helpers."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

ENCRYPTION_KEY_ENV = "SPI_ENCRYPTION_KEY"
KEY_FILENAME = "secret.key"

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16


class CredentialCipher:
    """Encrypts secrets at rest with a Fernet key.

    The key comes from the SPI_ENCRYPTION_KEY environment variable if set,
    otherwise from a key file in the data directory (created on first use
    with 0600 permissions).
    """

    def __init__(self, data_dir: Path):
        self._fernet = Fernet(self._load_or_create_key(data_dir))

    @staticmethod
    def _load_or_create_key(data_dir: Path) -> bytes:
        env_key = os.environ.get(ENCRYPTION_KEY_ENV)
        if env_key:
            return env_key.encode()
        key_path = data_dir / KEY_FILENAME
        if key_path.exists():
            return key_path.read_bytes().strip()
        key = Fernet.generate_key()
        data_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        return key

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        try:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        except InvalidToken as exc:
            raise ValueError("Could not decrypt stored credential") from exc


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P
    )
    return f"scrypt${salt.hex()}${digest.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_hex, digest_hex = stored.split("$")
        if algo != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    digest = hashlib.scrypt(
        password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P
    )
    return hmac.compare_digest(digest, expected)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)

def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
