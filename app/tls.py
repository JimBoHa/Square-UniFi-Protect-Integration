"""Self-signed TLS for LAN deployments.

Generates a long-lived self-signed certificate on first use so the app can
serve HTTPS without any external tooling. Browsers will warn once (the
certificate is self-signed); accepting it still upgrades every later session
to an encrypted connection, which matters once the dashboard is opened from
other devices on the LAN.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import socket
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CERT_FILENAME = "tls-cert.pem"
KEY_FILENAME = "tls-key.pem"
_VALIDITY = datetime.timedelta(days=3650)


def _local_ip() -> str | None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("198.51.100.1", 9))  # no packets are sent
        return probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()


def ensure_self_signed_cert(data_dir: Path) -> tuple[Path, Path]:
    """Return (cert_path, key_path), generating them on first use."""
    data_dir = Path(data_dir)
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    cert_path = data_dir / CERT_FILENAME
    key_path = data_dir / KEY_FILENAME
    if cert_path.is_file() and key_path.is_file():
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
    local_ip = _local_ip()
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
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key_bytes)
    finally:
        os.close(fd)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def uvicorn_tls_kwargs(data_dir: Path, enabled: bool) -> dict:
    """Uvicorn ssl kwargs for the runner; empty when TLS is disabled."""
    if not enabled:
        return {}
    cert_path, key_path = ensure_self_signed_cert(data_dir)
    return {"ssl_certfile": str(cert_path), "ssl_keyfile": str(key_path)}
