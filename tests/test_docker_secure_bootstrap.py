"""Regression tests for secure first-run Docker defaults."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_container_enables_builtin_tls_for_wildcard_bind():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert "SPI_HOST=0.0.0.0" in dockerfile
    assert "SPI_TLS=1" in dockerfile
    assert 'SPI_TLS: "1"' in compose
    assert "SPI_BOOTSTRAP_SECRET" not in compose
    assert (
        'CMD ["gosu", "square-protect", "square-unifi-protect", "--healthcheck"]'
        in dockerfile
    )


def test_docker_smoke_probe_uses_the_tls_endpoint():
    workflow = (ROOT / ".github" / "workflows" / "docker.yml").read_text(
        encoding="utf-8"
    )

    assert "curl -kfs https://127.0.0.1:8000/api/status" in workflow
    assert "curl -fs http://127.0.0.1:8000/api/status" not in workflow


def test_docker_instructions_use_https_without_persisting_a_secret():
    instructions = (ROOT / "PACKAGING.md").read_text(encoding="utf-8")

    assert "https://<host>:8000" in instructions
    assert "docker compose logs square-protect" in instructions
    assert "plaintext setup secret in Compose or container metadata" in instructions
