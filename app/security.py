"""Credential encryption, password hashing, and session token helpers."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

ENCRYPTION_KEY_ENV = "SPI_ENCRYPTION_KEY"
KEY_FILENAME = "secret.key"
_fchmod = getattr(os, "fchmod", None)

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
        try:
            return key_path.read_bytes().strip()
        except FileNotFoundError:
            pass

        key = Fernet.generate_key()
        data_dir.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{KEY_FILENAME}.", suffix=".tmp", dir=data_dir
        )
        temp_path = Path(temp_name)
        try:
            try:
                if _fchmod is not None:
                    _fchmod(fd, 0o600)
                else:
                    # Windows has no fchmod. mkstemp creates a private file;
                    # chmod keeps the path writable while preserving that ACL.
                    os.chmod(temp_path, 0o600)
                offset = 0
                while offset < len(key):
                    written = os.write(fd, key[offset:])
                    if written <= 0:
                        raise OSError("Could not write encryption key")
                    offset += written
                os.fsync(fd)
            finally:
                os.close(fd)

            try:
                # A hard link publishes the fully written inode only if the
                # destination does not yet exist. Concurrent losers read the
                # winner instead of overwriting it with a different key.
                os.link(temp_path, key_path)
            except FileExistsError:
                return key_path.read_bytes().strip()
            return key
        finally:
            temp_path.unlink(missing_ok=True)

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
