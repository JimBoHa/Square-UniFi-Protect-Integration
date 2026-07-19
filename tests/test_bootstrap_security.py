"""First-run admin bootstrap security tests."""

from __future__ import annotations

import concurrent.futures
from contextlib import contextmanager
import importlib
import logging

from fastapi.testclient import TestClient
import pytest

from app.main import create_app

from .conftest import ADMIN_PASSWORD, BOOTSTRAP_SECRET


REMOTE_PEER = "198.51.100.23"
GENERATED_SECRET = "ephemeral-generated-bootstrap-secret-0123456789"


@contextmanager
def _bootstrap_client(
    tmp_path,
    peer: str,
    *,
    bind_host: str | None = "127.0.0.1",
    base_url: str = "http://localhost",
    tls_enabled: bool = False,
):
    app = create_app(
        data_dir=tmp_path / "data",
        enable_poller=False,
        bind_host=bind_host,
        tls_enabled=tls_enabled,
    )
    try:
        with TestClient(app, base_url=base_url, client=(peer, 50000)) as client:
            yield client, app.state.store
    finally:
        app.state.store.close()


def _setup_payload(secret: str = BOOTSTRAP_SECRET) -> dict[str, str]:
    return {"password": ADMIN_PASSWORD, "bootstrap_secret": secret}


def test_direct_local_http_requires_and_accepts_correct_secret(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
    with _bootstrap_client(tmp_path, "127.0.0.1") as (client, _store):
        missing = client.post(
            "/api/setup", json={"password": ADMIN_PASSWORD}
        )
        assert missing.status_code == 403
        assert missing.json()["detail"]["code"] == "invalid_bootstrap_secret"

        accepted = client.post("/api/setup", json=_setup_payload())
        assert accepted.status_code == 200


def test_generated_secret_is_printed_once_never_returned_and_works(
    tmp_path,
    monkeypatch,
    caplog,
):
    main_module = importlib.import_module("app.main")
    generated_calls = []

    def generated_secret(nbytes: int) -> str:
        generated_calls.append(nbytes)
        return GENERATED_SECRET

    monkeypatch.delenv("SPI_BOOTSTRAP_SECRET", raising=False)
    monkeypatch.setattr(main_module.secrets, "token_urlsafe", generated_secret)
    with caplog.at_level(logging.WARNING, logger="spi"):
        with _bootstrap_client(tmp_path, "127.0.0.1") as (client, _store):
            assert "SPI_BOOTSTRAP_SECRET" not in main_module.os.environ
            status = client.get("/api/status")
            assert GENERATED_SECRET not in status.text
            response = client.post(
                "/api/setup", json=_setup_payload(GENERATED_SECRET)
            )

    generated_records = [
        record
        for record in caplog.records
        if "Generated one-time first-run bootstrap secret" in record.getMessage()
    ]
    assert response.status_code == 200
    assert generated_calls == [32]
    assert len(generated_records) == 1
    assert GENERATED_SECRET in generated_records[0].getMessage()


def test_invalid_environment_secret_is_replaced_by_generated_secret(
    tmp_path,
    monkeypatch,
    caplog,
):
    main_module = importlib.import_module("app.main")
    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", "too-short")
    monkeypatch.setattr(
        main_module.secrets,
        "token_urlsafe",
        lambda _nbytes: GENERATED_SECRET,
    )
    with caplog.at_level(logging.WARNING, logger="spi"):
        with _bootstrap_client(tmp_path, "127.0.0.1") as (client, _store):
            rejected = client.post(
                "/api/setup", json=_setup_payload("too-short")
            )
            accepted = client.post(
                "/api/setup", json=_setup_payload(GENERATED_SECRET)
            )

    assert rejected.status_code == 403
    assert accepted.status_code == 200
    assert caplog.text.count("Generated one-time first-run bootstrap secret") == 1
    assert "too-short" not in caplog.text


def test_nginx_style_loopback_proxy_rewrite_cannot_omit_secret(
    tmp_path,
    monkeypatch,
):
    """A proxy can rewrite peer and Host to loopback and strip all proxy headers."""
    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
    with _bootstrap_client(tmp_path, "127.0.0.1") as (client, _store):
        response = client.post(
            "/api/setup",
            json={"password": ADMIN_PASSWORD},
            headers={"Host": "localhost"},
        )

        assert response.status_code == 403
        assert response.json()["detail"]["code"] == "invalid_bootstrap_secret"


@pytest.mark.parametrize(
    "headers",
    (
        {"Host": "pos.example.test"},
        {"Origin": "https://pos.example.test"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"Forwarded": 'for="[::1]"'},
        {"X-Real-IP": "::1"},
        {"Via": "1.1 local-proxy"},
    ),
    ids=("host", "origin", "xff", "forwarded", "real-ip", "via"),
)
def test_non_direct_http_rejects_correct_secret_without_builtin_tls(
    tmp_path,
    monkeypatch,
    headers,
):
    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
    with _bootstrap_client(tmp_path, "127.0.0.1") as (client, _store):
        response = client.post(
            "/api/setup",
            json=_setup_payload(),
            headers=headers,
        )

        assert response.status_code == 403
        assert response.json()["detail"]["code"] == (
            "bootstrap_tls_not_configured"
        )


def test_xfp_rewritten_https_scope_cannot_authorize_plain_http_proxy_path(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
    # HTTPS base_url models the scope after Uvicorn trusts X-Forwarded-Proto.
    # The app must use only its startup TLS configuration, never this scope.
    with _bootstrap_client(
        tmp_path,
        "127.0.0.1",
        base_url="https://localhost",
        tls_enabled=False,
    ) as (client, _store):
        response = client.post(
            "/api/setup",
            json=_setup_payload(),
            headers={"X-Forwarded-Proto": "https"},
        )

        assert response.status_code == 403
        assert response.json()["detail"]["code"] == (
            "bootstrap_tls_not_configured"
        )


def test_request_https_scope_alone_cannot_authorize_remote_setup(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
    with _bootstrap_client(
        tmp_path,
        REMOTE_PEER,
        bind_host="0.0.0.0",
        base_url="https://pos.example.test",
        tls_enabled=False,
    ) as (client, _store):
        response = client.post("/api/setup", json=_setup_payload())

        assert response.status_code == 403
        assert response.json()["detail"]["code"] == (
            "bootstrap_tls_not_configured"
        )


def test_builtin_tls_configured_remote_path_accepts_correct_secret(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
    with _bootstrap_client(
        tmp_path,
        REMOTE_PEER,
        bind_host="0.0.0.0",
        base_url="https://pos.example.test",
        tls_enabled=True,
    ) as (client, _store):
        response = client.post("/api/setup", json=_setup_payload())

        assert response.status_code == 200


def test_raw_factory_does_not_trust_spi_tls_environment(
    tmp_path,
    monkeypatch,
):
    main_module = importlib.import_module("app.main")
    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
    monkeypatch.setenv("SPI_TLS", "1")
    monkeypatch.setenv("SPI_HOST", "0.0.0.0")
    monkeypatch.setenv("SPI_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SPI_DISABLE_POLLER", "1")
    application = main_module.app()
    try:
        with TestClient(
            application,
            base_url="http://pos.example.test",
            client=(REMOTE_PEER, 50000),
        ) as client:
            response = client.post("/api/setup", json=_setup_payload())
    finally:
        application.state.store.close()

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "bootstrap_tls_not_configured"


@pytest.mark.parametrize(
    ("host", "expected_status"),
    (
        ("localhost:65535", 200),
        ("localhost:65536", 403),
        ("localhost:" + "9" * 5000, 403),
        ("[::1]:" + "9" * 5000, 403),
    ),
    ids=("max-port", "over-max-port", "huge-port", "huge-ipv6-port"),
)
def test_host_port_boundaries_fail_closed_without_integer_conversion_error(
    tmp_path,
    monkeypatch,
    host,
    expected_status,
):
    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
    with _bootstrap_client(tmp_path, "127.0.0.1") as (client, _store):
        response = client.post(
            "/api/setup",
            json=_setup_payload(),
            headers={"Host": host},
        )

        assert response.status_code == expected_status
        if expected_status == 403:
            assert response.json()["detail"]["code"] == (
                "bootstrap_tls_not_configured"
            )


def test_secret_digest_is_compared_in_constant_time(tmp_path, monkeypatch):
    main_module = importlib.import_module("app.main")
    compared = []
    original_compare = main_module.secrets.compare_digest

    def record_compare(left, right):
        compared.append((bytes(left), bytes(right)))
        return original_compare(left, right)

    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
    monkeypatch.setattr(main_module.secrets, "compare_digest", record_compare)
    with _bootstrap_client(tmp_path, "127.0.0.1") as (client, _store):
        response = client.post(
            "/api/setup", json=_setup_payload("x" * 32)
        )

        assert response.status_code == 403
        assert response.json()["detail"]["code"] == "invalid_bootstrap_secret"
        assert len(compared) == 1
        left, right = compared[0]
        assert len(left) == len(right) == 32
        assert BOOTSTRAP_SECRET.encode() not in (left, right)


def test_plaintext_env_secret_is_popped_and_digest_cleared_after_winner(
    tmp_path,
    monkeypatch,
):
    main_module = importlib.import_module("app.main")
    clear_states = []
    original_clear = main_module._BootstrapSecretVerifier.clear

    def record_clear(verifier):
        before = verifier.configured
        original_clear(verifier)
        clear_states.append((before, verifier.configured))

    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
    monkeypatch.setattr(
        main_module._BootstrapSecretVerifier,
        "clear",
        record_clear,
    )
    with _bootstrap_client(tmp_path, "127.0.0.1") as (client, _store):
        assert "SPI_BOOTSTRAP_SECRET" not in main_module.os.environ
        response = client.post("/api/setup", json=_setup_payload())

        assert response.status_code == 200
        assert (True, False) in clear_states


def test_configured_secret_is_not_persisted_or_logged(
    tmp_path,
    monkeypatch,
    caplog,
):
    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
    with caplog.at_level(logging.WARNING, logger="spi"):
        with _bootstrap_client(tmp_path, "127.0.0.1") as (client, store):
            response = client.post("/api/setup", json=_setup_payload())

            assert response.status_code == 200
            settings = store._db.execute(
                "SELECT key, value FROM settings"
            ).fetchall()
            assert all(BOOTSTRAP_SECRET not in row["value"] for row in settings)
            for database_file in store.data_dir.glob("spi.db*"):
                assert BOOTSTRAP_SECRET.encode() not in database_file.read_bytes()
    assert BOOTSTRAP_SECRET not in caplog.text


def test_completed_setup_does_not_generate_or_print_another_secret(
    tmp_path,
    monkeypatch,
    caplog,
):
    main_module = importlib.import_module("app.main")
    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
    with _bootstrap_client(tmp_path, "127.0.0.1") as (client, _store):
        assert client.post("/api/setup", json=_setup_payload()).status_code == 200

    monkeypatch.delenv("SPI_BOOTSTRAP_SECRET", raising=False)

    def unexpected_generation(_nbytes):
        raise AssertionError("completed setup generated another secret")

    monkeypatch.setattr(
        main_module.secrets,
        "token_urlsafe",
        unexpected_generation,
    )
    with caplog.at_level(logging.WARNING, logger="spi"):
        app = create_app(
            data_dir=tmp_path / "data",
            enable_poller=False,
            bind_host="127.0.0.1",
            tls_enabled=False,
        )
        app.state.store.close()

    assert "Generated one-time first-run bootstrap secret" not in caplog.text


def test_two_process_like_apps_keep_atomic_single_setup_winner(
    tmp_path,
    monkeypatch,
):
    data_dir = tmp_path / "shared-data"
    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
    first_app = create_app(
        data_dir=data_dir,
        enable_poller=False,
        bind_host="127.0.0.1",
        tls_enabled=False,
    )
    # Separate OS workers inherit independent copies of the launch environment.
    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
    second_app = create_app(
        data_dir=data_dir,
        enable_poller=False,
        bind_host="127.0.0.1",
        tls_enabled=False,
    )
    try:
        with (
            TestClient(
                first_app,
                base_url="http://localhost",
                client=("127.0.0.1", 50001),
            ) as first_client,
            TestClient(
                second_app,
                base_url="http://localhost",
                client=("127.0.0.1", 50002),
            ) as second_client,
        ):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                responses = list(
                    executor.map(
                        lambda client: client.post(
                            "/api/setup", json=_setup_payload()
                        ),
                        (first_client, second_client),
                    )
                )

        assert sorted(response.status_code for response in responses) == [200, 409]
    finally:
        first_app.state.store.close()
        second_app.state.store.close()


@pytest.mark.parametrize(
    ("configured_host", "configured_tls"),
    ((None, False), ("192.0.2.44", True)),
)
def test_bundled_runner_couples_tls_authorization_to_uvicorn_tls_kwargs(
    tmp_path,
    monkeypatch,
    configured_host,
    configured_tls,
):
    runner = importlib.import_module("app.__main__")
    main_module = importlib.import_module("app.main")
    sentinel_app = object()
    captured = {}

    monkeypatch.setenv("SPI_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SPI_TLS", "1" if configured_tls else "0")
    if configured_host is None:
        monkeypatch.delenv("SPI_HOST", raising=False)
    else:
        monkeypatch.setenv("SPI_HOST", configured_host)

    def capture_create_app(*, data_dir, bind_host, tls_enabled):
        captured["create_bind_host"] = bind_host
        captured["create_tls_enabled"] = tls_enabled
        return sentinel_app

    def capture_run(application, **kwargs):
        captured["application"] = application
        captured.update(kwargs)

    monkeypatch.setattr(main_module, "create_app", capture_create_app)
    monkeypatch.setattr(runner.uvicorn, "run", capture_run)
    monkeypatch.setattr(
        runner,
        "uvicorn_tls_kwargs",
        lambda _data_dir, enabled: {"test_tls": enabled},
    )

    runner.main()

    expected_host = configured_host or "127.0.0.1"
    assert captured["application"] is sentinel_app
    assert captured["host"] == expected_host
    assert captured["create_bind_host"] == expected_host
    assert captured["create_tls_enabled"] is configured_tls
    assert captured["test_tls"] is configured_tls
    assert "proxy_headers" not in captured
