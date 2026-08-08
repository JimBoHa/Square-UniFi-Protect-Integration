"""Self-signed TLS for LAN deployments.

Generates a long-lived self-signed certificate on first use so the app can
serve HTTPS without any external tooling. Browsers will warn once (the
certificate is self-signed); accepting it still upgrades every later session
to an encrypted connection, which matters once the dashboard is opened from
other devices on the LAN.
"""

from __future__ import annotations

import datetime
import errno
import ipaddress
import os
import re
import secrets
import shutil
import socket
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CERT_FILENAME = "tls-cert.pem"
KEY_FILENAME = "tls-key.pem"
_VALIDITY = datetime.timedelta(days=3650)
_RENEWAL_MARGIN = datetime.timedelta(days=30)
_GENERATIONS_DIRNAME = ".tls-material"
_CURRENT_GENERATION_FILENAME = ".tls-current"
_GENERATION_LOCK_FILENAME = ".tls-generation.lock"
_GENERATION_RE = re.compile(r"^[0-9a-f]{32}$")
_THREAD_LOCKS: dict[str, threading.Lock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


def _thread_lock_for(data_dir: Path) -> threading.Lock:
    key = os.path.normcase(str(data_dir.resolve()))
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(key, threading.Lock())


def _lock_file(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        # Windows permits byte-range locks past EOF, so the persistent lock
        # file can stay empty and fresh workers never race to initialize it.
        while True:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                return
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EDEADLK):
                    raise
                time.sleep(0.05)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX)


def _unlock_file(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def _generation_lock(data_dir: Path):
    """Serialize certificate selection and generation across workers."""
    with _thread_lock_for(data_dir):
        lock_path = data_dir / _GENERATION_LOCK_FILENAME
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        locked = False
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            _lock_file(fd)
            locked = True
            yield
        finally:
            if locked:
                _unlock_file(fd)
            os.close(fd)


def _write_all(fd: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(fd, content[offset:])
        if written <= 0:
            raise OSError("Could not write TLS material")
        offset += written
    os.fsync(fd)


def _write_new_file(path: Path, content: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        _write_all(fd, content)
    finally:
        os.close(fd)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove_incomplete_publications(data_dir: Path) -> None:
    generations_dir = data_dir / _GENERATIONS_DIRNAME
    if generations_dir.is_dir():
        for path in generations_dir.iterdir():
            if not path.name.startswith(".tmp-"):
                continue
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
    pointer_prefix = f"{_CURRENT_GENERATION_FILENAME}."
    for path in data_dir.iterdir():
        if path.name.startswith(pointer_prefix) and path.name.endswith(".tmp"):
            path.unlink(missing_ok=True)


def _current_pair(data_dir: Path) -> tuple[Path, Path]:
    pointer_path = data_dir / _CURRENT_GENERATION_FILENAME
    try:
        generation = pointer_path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        generation = ""
    if _GENERATION_RE.fullmatch(generation):
        generation_dir = data_dir / _GENERATIONS_DIRNAME / generation
        cert_path = generation_dir / CERT_FILENAME
        key_path = generation_dir / KEY_FILENAME
        if cert_path.is_file() and key_path.is_file():
            return cert_path, key_path
    return data_dir / CERT_FILENAME, data_dir / KEY_FILENAME


def _publish_pair(
    data_dir: Path, cert_bytes: bytes, key_bytes: bytes
) -> tuple[Path, Path]:
    """Publish both files by one atomic current-generation pointer swap."""
    generations_dir = data_dir / _GENERATIONS_DIRNAME
    generations_dir.mkdir(mode=0o700, exist_ok=True)
    if hasattr(os, "chmod"):
        os.chmod(generations_dir, 0o700)

    generation = secrets.token_hex(16)
    temp_dir = generations_dir / f".tmp-{generation}"
    final_dir = generations_dir / generation
    temp_pointer: Path | None = None
    os.mkdir(temp_dir, 0o700)
    try:
        _write_new_file(temp_dir / KEY_FILENAME, key_bytes, 0o600)
        _write_new_file(temp_dir / CERT_FILENAME, cert_bytes, 0o600)
        _fsync_directory(temp_dir)

        os.replace(temp_dir, final_dir)
        try:
            _fsync_directory(generations_dir)

            fd, temp_name = tempfile.mkstemp(
                prefix=f"{_CURRENT_GENERATION_FILENAME}.",
                suffix=".tmp",
                dir=data_dir,
            )
            temp_pointer = Path(temp_name)
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
                _write_all(fd, f"{generation}\n".encode("ascii"))
            finally:
                os.close(fd)
        except BaseException:
            # Nothing refers to this complete generation yet.
            shutil.rmtree(final_dir)
            raise
        try:
            os.replace(temp_pointer, data_dir / _CURRENT_GENERATION_FILENAME)
        except OSError:
            # The complete generation is not visible until this pointer moves.
            # A failed pointer publication can therefore discard it safely.
            shutil.rmtree(final_dir)
            raise
        _fsync_directory(data_dir)
        return final_dir / CERT_FILENAME, final_dir / KEY_FILENAME
    finally:
        if temp_pointer is not None:
            temp_pointer.unlink(missing_ok=True)
        if temp_dir.exists():
            shutil.rmtree(temp_dir)


def _local_ip() -> str | None:
    # A host with multiple interfaces (or a VPN) can route the UDP probe over
    # a different address than the one Uvicorn is configured to serve.  Prefer
    # an explicit IP bind so the generated certificate always covers the URL
    # clients actually use.  Wildcard and hostname binds still need discovery.
    configured_host = os.environ.get("SPI_HOST", "").strip().strip("[]")
    try:
        configured_ip = ipaddress.ip_address(configured_host)
    except ValueError:
        configured_ip = None
    if configured_ip is not None and not configured_ip.is_unspecified:
        return str(configured_ip)

    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("198.51.100.1", 9))  # no packets are sent
        return probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()


def _existing_pair_is_reusable(
    cert_path: Path, key_path: Path, local_ip: str | None
) -> bool:
    """Return whether existing material is safe to reuse for this startup."""
    try:
        # Invalid generations remain on disk because another process may still
        # be serving them. Restrict their private key before any early return.
        os.chmod(key_path, 0o600)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        now = datetime.datetime.now(datetime.timezone.utc)
        if cert.not_valid_before_utc > now:
            return False
        if cert.not_valid_after_utc <= now + _RENEWAL_MARGIN:
            return False
        if local_ip is not None:
            sans = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            addresses = sans.get_values_for_type(x509.IPAddress)
            if ipaddress.ip_address(local_ip) not in addresses:
                return False
        public_format = serialization.PublicFormat.SubjectPublicKeyInfo
        cert_public_key = cert.public_key().public_bytes(
            serialization.Encoding.DER, public_format
        )
        key_public_key = key.public_key().public_bytes(
            serialization.Encoding.DER, public_format
        )
        if cert_public_key != key_public_key:
            return False
    except (
        OSError,
        TypeError,
        UnsupportedAlgorithm,
        ValueError,
        x509.ExtensionNotFound,
    ):
        return False
    return True


def ensure_self_signed_cert(data_dir: Path) -> tuple[Path, Path]:
    """Return (cert_path, key_path), generating them on first use.

    Regenerates the pair when the machine's LAN IP is no longer covered by
    the certificate's subject alternative names (e.g. after a DHCP change),
    so LAN browsers keep seeing a name-matching certificate.

    Callers must use the returned paths; a regenerated pair is published in a
    new immutable generation so two files never change underneath a reader.
    """
    data_dir = Path(data_dir)
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with _generation_lock(data_dir):
        _remove_incomplete_publications(data_dir)
        cert_path, key_path = _current_pair(data_dir)
        local_ip = _local_ip()
        if (
            cert_path.is_file()
            and key_path.is_file()
            and _existing_pair_is_reusable(cert_path, key_path, local_ip)
        ):
            return cert_path, key_path

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "square-unifi-protect.local")]
        )
        alt_names: list[x509.GeneralName] = [
            x509.DNSName("localhost"),
            x509.DNSName("square-unifi-protect.local"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]
        if local_ip:
            alt_names.append(x509.IPAddress(ipaddress.ip_address(local_ip)))
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + _VALIDITY)
            .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(key, hashes.SHA256())
        )

        key_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
        return _publish_pair(data_dir, cert_bytes, key_bytes)


def uvicorn_tls_kwargs(data_dir: Path, enabled: bool) -> dict:
    """Uvicorn ssl kwargs for the runner; empty when TLS is disabled."""
    if not enabled:
        return {}
    cert_path, key_path = ensure_self_signed_cert(data_dir)
    return {"ssl_certfile": str(cert_path), "ssl_keyfile": str(key_path)}
