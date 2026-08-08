"""Run the integration: ``python -m app``.

Environment:
  SPI_PORT       listen port (default 8000)
  SPI_HOST       bind address (default 127.0.0.1)
  SPI_DATA_DIR   data directory (default ./data)
  SPI_BOOTSTRAP_SECRET
                 optional random secret (32+ characters) for first setup;
                 otherwise one is generated and printed once at startup
  SPI_TLS        "1" serves HTTPS with an auto-generated self-signed
                 certificate and enables Secure session cookies
  SPI_TLS_CERTFILE / SPI_TLS_KEYFILE
                 optional absolute paths to an administrator-managed PEM
                 certificate chain and unencrypted private key
"""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn

from .tls import uvicorn_tls_kwargs

PORT_ERROR = "SPI_PORT must be a whole number from 1 to 65535"


def _parse_listen_port(value: str) -> int:
    if not value or not value.isascii() or not value.isdigit():
        raise ValueError(PORT_ERROR)
    port = int(value, 10)
    if not 1 <= port <= 65535:
        raise ValueError(PORT_ERROR)
    return port


def main() -> None:
    try:
        port = _parse_listen_port(os.environ.get("SPI_PORT", "8000"))
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    data_dir = Path(os.environ.get("SPI_DATA_DIR", "./data"))
    host = os.environ.get("SPI_HOST", "127.0.0.1")
    tls_enabled = os.environ.get("SPI_TLS", "0") == "1"
    if tls_enabled:
        # HTTPS makes Secure session cookies safe to require.
        # Do not let a stale launcher/service environment explicitly override
        # the transport guarantee selected by SPI_TLS.
        os.environ["SPI_COOKIE_SECURE"] = "1"
    tls_kwargs = uvicorn_tls_kwargs(data_dir, tls_enabled)
    from .main import create_app  # after env adjustments

    uvicorn.run(
        create_app(data_dir=data_dir, bind_host=host, tls_enabled=tls_enabled),
        host=host,
        port=port,
        log_level="info",
        **tls_kwargs,
    )


if __name__ == "__main__":
    main()
