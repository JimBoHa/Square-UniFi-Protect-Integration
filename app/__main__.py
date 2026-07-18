"""Run the integration: ``python -m app``.

Environment:
  SPI_PORT       listen port (default 8000)
  SPI_HOST       bind address (default 0.0.0.0)
  SPI_DATA_DIR   data directory (default ./data)
  SPI_TLS        "1" serves HTTPS with an auto-generated self-signed
                 certificate and enables Secure session cookies
"""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn

from .tls import uvicorn_tls_kwargs


def main() -> None:
    data_dir = Path(os.environ.get("SPI_DATA_DIR", "./data"))
    tls_enabled = os.environ.get("SPI_TLS", "0") == "1"
    if tls_enabled:
        # HTTPS makes Secure session cookies safe to require.
        # Do not let a stale launcher/service environment explicitly override
        # the transport guarantee selected by SPI_TLS.
        os.environ["SPI_COOKIE_SECURE"] = "1"
    from .main import create_app  # after env adjustments

    uvicorn.run(
        create_app(data_dir=data_dir),
        host=os.environ.get("SPI_HOST", "0.0.0.0"),
        port=int(os.environ.get("SPI_PORT", "8000")),
        log_level="info",
        **uvicorn_tls_kwargs(data_dir, tls_enabled),
    )


if __name__ == "__main__":
    main()
