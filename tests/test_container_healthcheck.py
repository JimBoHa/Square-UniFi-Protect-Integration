"""Docker liveness probe protocol tests."""

import ssl
from pathlib import Path

import pytest

from app import healthcheck


REPO_ROOT = Path(__file__).resolve().parents[1]


class _Response:
    def __init__(self, status: int = 200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


def test_docker_uses_protocol_aware_healthcheck_module():
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert 'CMD ["python", "-m", "app.healthcheck"]' in dockerfile
    assert "urlopen(f'http://" not in dockerfile


def test_container_healthcheck_uses_plain_http_by_default(monkeypatch):
    captured = {}
    monkeypatch.delenv("SPI_TLS", raising=False)
    monkeypatch.setenv("SPI_PORT", "8123")
    monkeypatch.setattr(
        healthcheck.urllib.request,
        "urlopen",
        lambda url, **options: captured.update(url=url, options=options) or _Response(),
    )

    healthcheck.main()

    assert captured == {
        "url": "http://127.0.0.1:8123/api/status",
        "options": {"timeout": healthcheck.HEALTHCHECK_TIMEOUT_SECONDS},
    }


def test_container_healthcheck_supports_self_signed_tls(monkeypatch):
    captured = {}
    monkeypatch.setenv("SPI_TLS", "1")
    monkeypatch.setenv("SPI_PORT", "8443")
    monkeypatch.setattr(
        healthcheck.urllib.request,
        "urlopen",
        lambda url, **options: captured.update(url=url, options=options) or _Response(),
    )

    healthcheck.main()

    context = captured["options"]["context"]
    assert captured["url"] == "https://127.0.0.1:8443/api/status"
    assert captured["options"]["timeout"] == healthcheck.HEALTHCHECK_TIMEOUT_SECONDS
    assert isinstance(context, ssl.SSLContext)
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


def test_container_healthcheck_rejects_unhealthy_response(monkeypatch):
    monkeypatch.setattr(
        healthcheck.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(503),
    )

    with pytest.raises(SystemExit, match="HTTP 503"):
        healthcheck.main()
