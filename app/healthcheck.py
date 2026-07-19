"""Container-local liveness probe for the HTTP or built-in TLS server."""

from __future__ import annotations

import os
import ssl
import urllib.request


HEALTHCHECK_TIMEOUT_SECONDS = 4


def _local_tls_context() -> ssl.SSLContext:
    """Trust the app's self-signed certificate only for this loopback probe."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def main() -> None:
    tls_enabled = os.environ.get("SPI_TLS", "0") == "1"
    scheme = "https" if tls_enabled else "http"
    port = os.environ.get("SPI_PORT", "8000")
    url = f"{scheme}://127.0.0.1:{port}/api/status"
    options: dict = {"timeout": HEALTHCHECK_TIMEOUT_SECONDS}
    if tls_enabled:
        options["context"] = _local_tls_context()
    with urllib.request.urlopen(url, **options) as response:
        if response.status != 200:
            raise SystemExit(f"Health endpoint returned HTTP {response.status}")


if __name__ == "__main__":
    main()
