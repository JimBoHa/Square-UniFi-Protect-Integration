"""Credential encryption, password hashing, and session token helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

ENCRYPTION_KEY_ENV = "SPI_ENCRYPTION_KEY"
KEY_FILENAME = "secret.key"

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_KEYED_HMAC_DERIVATION_DOMAIN = (
    b"square-unifi-protect:credential-cipher:keyed-hmac:v1"
)


class CredentialCipher:
    """Encrypts secrets at rest with a Fernet key.

    The key comes from the SPI_ENCRYPTION_KEY environment variable if set,
    otherwise from a key file in the data directory (created on first use
    with 0600 permissions).
    """

    def __init__(self, data_dir: Path):
        key = self._load_or_create_key(data_dir)
        self._fernet = Fernet(key)
        raw_key = base64.urlsafe_b64decode(key)
        # Derive a distinct MAC key instead of reusing Fernet's key material
        # directly in another protocol. Derive from the decoded key so every
        # equivalent Fernet encoding produces the same durable MAC key.
        self._keyed_hmac_key = hmac.new(
            raw_key,
            _KEYED_HMAC_DERIVATION_DOMAIN,
            hashlib.sha256,
        ).digest()

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
                os.fchmod(fd, 0o600)
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

    def keyed_hmac_hex(self, domain: bytes, payload: bytes) -> str:
        """Return a domain-separated installation-specific HMAC digest."""
        if not domain or b"\0" in domain:
            raise ValueError("HMAC domain must be non-empty and contain no NUL bytes")
        return hmac.new(
            self._keyed_hmac_key,
            domain + b"\0" + payload,
            hashlib.sha256,
        ).hexdigest()


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
