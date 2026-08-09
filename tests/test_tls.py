"""Self-signed TLS helper tests."""

import datetime
import multiprocessing
import os
import ssl
import stat
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.tls import ensure_self_signed_cert, uvicorn_tls_kwargs


def _generate_tls_in_process(data_dir, lock_attempted, lock_acquired, result) -> None:
    import app.tls as tls

    original_lock = tls._lock_file

    def observed_lock(fd):
        lock_attempted.set()
        original_lock(fd)
        lock_acquired.set()

    tls._lock_file = observed_lock
    try:
        paths = tls.ensure_self_signed_cert(Path(data_dir))
        result.put(("ok", tuple(str(path) for path in paths)))
    except BaseException as exc:  # pragma: no cover - reported in parent process
        result.put(("error", repr(exc)))


def _replace_certificate(
    cert_path, key_path, *, not_valid_before, not_valid_after
) -> bytes:
    original = x509.load_pem_x509_certificate(cert_path.read_bytes())
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    builder = (
        x509.CertificateBuilder()
        .subject_name(original.subject)
        .issuer_name(original.issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
    )
    for extension in original.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    content = builder.sign(key, hashes.SHA256()).public_bytes(
        serialization.Encoding.PEM
    )
    cert_path.write_bytes(content)
    return content


def _assert_pair_loads(cert_path, key_path) -> None:
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert_path, key_path)


def test_cert_generated_once_with_private_key_permissions(tmp_path):
    cert_path, key_path = ensure_self_signed_cert(tmp_path)
    assert cert_path.is_file() and key_path.is_file()
    if os.name == "posix":
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert "localhost" in san.value.get_values_for_type(x509.DNSName)

    # Second call must reuse, not regenerate.
    again_cert, again_key = ensure_self_signed_cert(tmp_path)
    assert again_cert.read_bytes() == cert_path.read_bytes()


def test_cert_covers_explicit_bind_ip_instead_of_default_route(
    tmp_path, monkeypatch
):
    import app.tls as tls
    import ipaddress

    monkeypatch.setenv("SPI_HOST", "192.0.2.44")
    monkeypatch.setattr(
        tls.socket,
        "socket",
        lambda *_args, **_kwargs: pytest.fail("default route must not be probed"),
    )

    cert_path, _ = tls.ensure_self_signed_cert(tmp_path)
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    sans = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value

    assert ipaddress.ip_address("192.0.2.44") in sans.get_values_for_type(
        x509.IPAddress
    )


def test_wildcard_bind_certificate_tracks_resolved_lan_addresses(
    tmp_path, monkeypatch
):
    import app.tls as tls
    import ipaddress

    monkeypatch.setenv("SPI_HOST", "0.0.0.0")
    monkeypatch.setattr(tls.socket, "gethostname", lambda: "register-host")
    monkeypatch.setattr(
        tls.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (tls.socket.AF_INET, tls.socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
            (tls.socket.AF_INET, tls.socket.SOCK_STREAM, 6, "", ("192.0.2.11", 0)),
            (tls.socket.AF_INET, tls.socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ],
    )
    monkeypatch.setattr(
        tls.socket,
        "socket",
        lambda *_args, **_kwargs: pytest.fail("route fallback must not be probed"),
    )

    cert_path, _ = tls.ensure_self_signed_cert(tmp_path)
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    sans = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.IPAddress)

    assert ipaddress.ip_address("192.0.2.10") in sans
    assert ipaddress.ip_address("192.0.2.11") in sans
    assert ipaddress.ip_address("0.0.0.0") not in sans


def test_wildcard_bind_certificate_rotates_after_dhcp_change(tmp_path, monkeypatch):
    import app.tls as tls
    import ipaddress

    monkeypatch.setenv("SPI_HOST", "0.0.0.0")
    current_address = ["192.0.2.10"]
    monkeypatch.setattr(tls.socket, "gethostname", lambda: "register-host")
    monkeypatch.setattr(
        tls.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (
                tls.socket.AF_INET,
                tls.socket.SOCK_STREAM,
                6,
                "",
                (current_address[0], 0),
            )
        ],
    )

    original, _ = tls.ensure_self_signed_cert(tmp_path)
    current_address[0] = "192.0.2.99"
    regenerated, _ = tls.ensure_self_signed_cert(tmp_path)

    assert regenerated != original
    cert = x509.load_pem_x509_certificate(regenerated.read_bytes())
    sans = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.IPAddress)
    assert ipaddress.ip_address("192.0.2.99") in sans
    assert ipaddress.ip_address("192.0.2.10") not in sans


def test_uvicorn_kwargs_disabled_and_enabled(tmp_path):
    assert uvicorn_tls_kwargs(tmp_path, False) == {}
    kwargs = uvicorn_tls_kwargs(tmp_path, True)
    assert set(kwargs) == {"ssl_certfile", "ssl_keyfile"}


def test_uvicorn_uses_valid_administrator_tls_pair(tmp_path, monkeypatch):
    import app.tls as tls

    generated_dir = tmp_path / "generated"
    cert_path, key_path = tls.ensure_self_signed_cert(generated_dir)
    monkeypatch.setenv(tls.CUSTOM_CERT_ENV, str(cert_path))
    monkeypatch.setenv(tls.CUSTOM_KEY_ENV, str(key_path))

    kwargs = tls.uvicorn_tls_kwargs(tmp_path / "unused", True)

    assert kwargs == {
        "ssl_certfile": str(cert_path),
        "ssl_keyfile": str(key_path),
    }
    assert not (tmp_path / "unused").exists()


@pytest.mark.parametrize(
    ("cert_value", "key_value"),
    (("/tmp/cert.pem", ""), ("", "/tmp/key.pem")),
)
def test_custom_tls_requires_certificate_and_key_together(
    tmp_path, monkeypatch, cert_value, key_value
):
    import app.tls as tls

    monkeypatch.setenv(tls.CUSTOM_CERT_ENV, cert_value)
    monkeypatch.setenv(tls.CUSTOM_KEY_ENV, key_value)

    with pytest.raises(ValueError, match="must be configured together"):
        tls.uvicorn_tls_kwargs(tmp_path, True)


def test_custom_tls_paths_must_be_absolute(tmp_path, monkeypatch):
    import app.tls as tls

    monkeypatch.setenv(tls.CUSTOM_CERT_ENV, "cert.pem")
    monkeypatch.setenv(tls.CUSTOM_KEY_ENV, "key.pem")

    with pytest.raises(ValueError, match="paths must be absolute"):
        tls.uvicorn_tls_kwargs(tmp_path, True)


@pytest.mark.parametrize(
    ("missing_name", "message"),
    (("cert.pem", "certificate is not a file"), ("key.pem", "key is not a file")),
)
def test_custom_tls_files_must_exist(tmp_path, monkeypatch, missing_name, message):
    import app.tls as tls

    cert_path, key_path = tls.ensure_self_signed_cert(tmp_path / "generated")
    missing_path = tmp_path / missing_name
    if missing_name == "cert.pem":
        cert_path = missing_path
    else:
        key_path = missing_path
    monkeypatch.setenv(tls.CUSTOM_CERT_ENV, str(cert_path))
    monkeypatch.setenv(tls.CUSTOM_KEY_ENV, str(key_path))

    with pytest.raises(ValueError, match=message):
        tls.uvicorn_tls_kwargs(tmp_path / "unused", True)


def test_custom_tls_rejects_mismatched_pair(tmp_path, monkeypatch):
    import app.tls as tls

    cert_path, _ = tls.ensure_self_signed_cert(tmp_path / "first")
    _, key_path = tls.ensure_self_signed_cert(tmp_path / "second")
    monkeypatch.setenv(tls.CUSTOM_CERT_ENV, str(cert_path))
    monkeypatch.setenv(tls.CUSTOM_KEY_ENV, str(key_path))

    with pytest.raises(ValueError, match="could not be loaded as a pair"):
        tls.uvicorn_tls_kwargs(tmp_path / "unused", True)


@pytest.mark.parametrize(
    ("not_before", "not_after", "message"),
    ((-2, -1, "has expired"), (1, 2, "is not valid yet")),
)
def test_custom_tls_rejects_invalid_certificate_dates(
    tmp_path, monkeypatch, not_before, not_after, message
):
    import app.tls as tls

    cert_path, key_path = tls.ensure_self_signed_cert(tmp_path / "generated")
    now = datetime.datetime.now(datetime.timezone.utc)
    _replace_certificate(
        cert_path,
        key_path,
        not_valid_before=now + datetime.timedelta(days=not_before),
        not_valid_after=now + datetime.timedelta(days=not_after),
    )
    monkeypatch.setenv(tls.CUSTOM_CERT_ENV, str(cert_path))
    monkeypatch.setenv(tls.CUSTOM_KEY_ENV, str(key_path))

    with pytest.raises(ValueError, match=message):
        tls.uvicorn_tls_kwargs(tmp_path / "unused", True)


def test_custom_tls_rejects_insecure_private_key_permissions(tmp_path, monkeypatch):
    import app.tls as tls

    if os.name != "posix":
        pytest.skip("POSIX permission bits required")
    cert_path, key_path = tls.ensure_self_signed_cert(tmp_path / "generated")
    key_path.chmod(0o644)
    monkeypatch.setenv(tls.CUSTOM_CERT_ENV, str(cert_path))
    monkeypatch.setenv(tls.CUSTOM_KEY_ENV, str(key_path))

    with pytest.raises(ValueError, match="group or other users"):
        tls.uvicorn_tls_kwargs(tmp_path / "unused", True)


def test_custom_tls_configuration_requires_tls_enabled(tmp_path, monkeypatch):
    import app.tls as tls

    monkeypatch.setenv(tls.CUSTOM_CERT_ENV, "/tmp/cert.pem")
    monkeypatch.setenv(tls.CUSTOM_KEY_ENV, "/tmp/key.pem")

    with pytest.raises(ValueError, match="SPI_TLS must be 1"):
        tls.uvicorn_tls_kwargs(tmp_path, False)


def test_cert_regenerated_when_lan_ip_leaves_sans(tmp_path, monkeypatch):
    import app.tls as tls

    monkeypatch.setattr(tls, "_local_ip", lambda: "192.0.2.10")
    cert_path, _ = tls.ensure_self_signed_cert(tmp_path)
    first = cert_path.read_bytes()

    # Same IP: reused untouched.
    tls.ensure_self_signed_cert(tmp_path)
    assert cert_path.read_bytes() == first

    # New DHCP lease: certificate is regenerated to cover the new address.
    monkeypatch.setattr(tls, "_local_ip", lambda: "192.0.2.99")
    regenerated_path, _ = tls.ensure_self_signed_cert(tmp_path)
    regenerated = regenerated_path.read_bytes()
    assert regenerated != first

    from cryptography import x509
    import ipaddress

    cert = x509.load_pem_x509_certificate(regenerated)
    sans = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    assert ipaddress.ip_address("192.0.2.99") in sans.get_values_for_type(
        x509.IPAddress
    )


def test_concurrent_threads_generate_one_matched_pair(tmp_path, monkeypatch):
    import app.tls as tls

    monkeypatch.setattr(tls, "_local_ip", lambda: "192.0.2.10")
    original_generate = tls.ec.generate_private_key
    first_entered = threading.Event()
    allow_first = threading.Event()
    second_entered = threading.Event()
    generation_count = 0
    count_lock = threading.Lock()

    def controlled_generate(*args, **kwargs):
        nonlocal generation_count
        with count_lock:
            generation_count += 1
            current = generation_count
        if current == 1:
            first_entered.set()
            assert allow_first.wait(5)
        else:
            second_entered.set()
        return original_generate(*args, **kwargs)

    monkeypatch.setattr(tls.ec, "generate_private_key", controlled_generate)
    results = []
    errors = []

    def generate() -> None:
        try:
            results.append(tls.ensure_self_signed_cert(tmp_path))
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    first = threading.Thread(target=generate)
    second = threading.Thread(target=generate)
    first.start()
    assert first_entered.wait(5)
    second.start()
    assert not second_entered.wait(0.25)
    allow_first.set()
    first.join(5)
    second.join(5)

    assert not first.is_alive() and not second.is_alive()
    assert errors == []
    assert generation_count == 1
    assert results[0] == results[1]
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(*results[0])


def test_generation_waits_for_cross_process_lock(tmp_path):
    import app.tls as tls

    context = multiprocessing.get_context("spawn")
    lock_attempted = context.Event()
    lock_acquired = context.Event()
    result = context.Queue()
    process = context.Process(
        target=_generate_tls_in_process,
        args=(str(tmp_path), lock_attempted, lock_acquired, result),
    )

    try:
        with tls._generation_lock(tmp_path):
            process.start()
            assert lock_attempted.wait(5)
            assert not lock_acquired.wait(0.25)
        assert lock_acquired.wait(10)
        process.join(10)
        assert process.exitcode == 0
        status, payload = result.get(timeout=2)
        assert status == "ok", payload
        cert_path, key_path = (Path(value) for value in payload)
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
            cert_path, key_path
        )
    finally:
        if process.is_alive():
            process.terminate()
            process.join(5)
        result.close()
        result.join_thread()


def test_failed_material_write_leaves_no_partial_generation(tmp_path, monkeypatch):
    import app.tls as tls

    monkeypatch.setattr(tls, "_local_ip", lambda: "192.0.2.10")
    original_write = tls._write_new_file

    def fail_cert_write(path, content, mode):
        if path.name == tls.CERT_FILENAME:
            raise OSError("injected certificate write failure")
        return original_write(path, content, mode)

    monkeypatch.setattr(tls, "_write_new_file", fail_cert_write)
    with pytest.raises(OSError, match="injected certificate write failure"):
        tls.ensure_self_signed_cert(tmp_path)

    generations_dir = tmp_path / tls._GENERATIONS_DIRNAME
    assert list(generations_dir.iterdir()) == []
    assert not (tmp_path / tls._CURRENT_GENERATION_FILENAME).exists()
    assert not list(tmp_path.glob(f"{tls._CURRENT_GENERATION_FILENAME}.*.tmp"))


def test_failed_generation_sync_removes_unpublished_pair(tmp_path, monkeypatch):
    import app.tls as tls

    monkeypatch.setattr(tls, "_local_ip", lambda: "192.0.2.10")
    original_fsync = tls._fsync_directory
    generations_dir = tmp_path / tls._GENERATIONS_DIRNAME

    def fail_generation_sync(path):
        if path == generations_dir:
            raise OSError("injected generation sync failure")
        return original_fsync(path)

    monkeypatch.setattr(tls, "_fsync_directory", fail_generation_sync)
    with pytest.raises(OSError, match="injected generation sync failure"):
        tls.ensure_self_signed_cert(tmp_path)

    assert list(generations_dir.iterdir()) == []
    assert not (tmp_path / tls._CURRENT_GENERATION_FILENAME).exists()


def test_failed_pointer_swap_preserves_previous_pair(tmp_path, monkeypatch):
    import app.tls as tls

    monkeypatch.setattr(tls, "_local_ip", lambda: "192.0.2.10")
    original_pair = tls.ensure_self_signed_cert(tmp_path)
    original_cert = original_pair[0].read_bytes()
    pointer_path = tmp_path / tls._CURRENT_GENERATION_FILENAME
    original_pointer = pointer_path.read_bytes()
    original_replace = tls.os.replace

    monkeypatch.setattr(tls, "_local_ip", lambda: "192.0.2.99")

    def fail_pointer_swap(source, destination):
        if Path(destination) == pointer_path:
            raise OSError("injected pointer swap failure")
        return original_replace(source, destination)

    monkeypatch.setattr(tls.os, "replace", fail_pointer_swap)
    with pytest.raises(OSError, match="injected pointer swap failure"):
        tls.ensure_self_signed_cert(tmp_path)

    assert pointer_path.read_bytes() == original_pointer
    assert original_pair[0].read_bytes() == original_cert
    generations = [
        path
        for path in (tmp_path / tls._GENERATIONS_DIRNAME).iterdir()
        if not path.name.startswith(".tmp-")
    ]
    assert generations == [original_pair[0].parent]
    assert not list(tmp_path.glob(f"{tls._CURRENT_GENERATION_FILENAME}.*.tmp"))
    monkeypatch.setattr(tls, "_local_ip", lambda: "192.0.2.10")
    assert tls.ensure_self_signed_cert(tmp_path) == original_pair
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(*original_pair)


def test_mismatched_private_key_regenerates_pair(tmp_path, monkeypatch):
    import app.tls as tls

    monkeypatch.setattr(tls, "_local_ip", lambda: "192.0.2.10")
    original_pair = tls.ensure_self_signed_cert(tmp_path)
    original_cert = original_pair[0].read_bytes()
    unrelated_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    original_pair[1].write_bytes(unrelated_key)
    original_pair[1].chmod(0o644)

    regenerated = tls.ensure_self_signed_cert(tmp_path)

    assert regenerated != original_pair
    assert original_pair[0].read_bytes() == original_cert
    assert original_pair[1].read_bytes() == unrelated_key
    if os.name == "posix":
        assert stat.S_IMODE(original_pair[1].stat().st_mode) == 0o600
        assert stat.S_IMODE(regenerated[1].stat().st_mode) == 0o600
    _assert_pair_loads(*regenerated)
    assert tls.ensure_self_signed_cert(tmp_path) == regenerated


@pytest.mark.parametrize("corrupt_name", ["tls-cert.pem", "tls-key.pem"])
def test_corrupt_tls_material_regenerates_pair(tmp_path, monkeypatch, corrupt_name):
    import app.tls as tls

    monkeypatch.setattr(tls, "_local_ip", lambda: "192.0.2.10")
    original_pair = tls.ensure_self_signed_cert(tmp_path)
    corrupt_path = (
        original_pair[0] if corrupt_name == tls.CERT_FILENAME else original_pair[1]
    )
    if corrupt_name == tls.CERT_FILENAME:
        original_pair[1].chmod(0o644)
    corrupt_content = b"not PEM material"
    corrupt_path.write_bytes(corrupt_content)

    regenerated = tls.ensure_self_signed_cert(tmp_path)

    assert regenerated != original_pair
    assert corrupt_path.read_bytes() == corrupt_content
    if os.name == "posix":
        assert stat.S_IMODE(original_pair[1].stat().st_mode) == 0o600
    x509.load_pem_x509_certificate(regenerated[0].read_bytes())
    serialization.load_pem_private_key(regenerated[1].read_bytes(), password=None)
    _assert_pair_loads(*regenerated)


@pytest.mark.parametrize(
    ("not_before_delta", "not_after_delta"),
    [
        (
            -datetime.timedelta(days=2),
            -datetime.timedelta(seconds=1),
        ),
        (
            datetime.timedelta(days=1),
            datetime.timedelta(days=365),
        ),
        (
            -datetime.timedelta(days=1),
            datetime.timedelta(days=29),
        ),
    ],
    ids=("expired", "not-yet-valid", "inside-renewal-margin"),
)
def test_invalid_certificate_dates_regenerate_pair(
    tmp_path,
    monkeypatch,
    not_before_delta,
    not_after_delta,
):
    import app.tls as tls

    monkeypatch.setattr(tls, "_local_ip", lambda: "192.0.2.10")
    original_pair = tls.ensure_self_signed_cert(tmp_path)
    now = datetime.datetime.now(datetime.timezone.utc)
    invalid_cert = _replace_certificate(
        *original_pair,
        not_valid_before=now + not_before_delta,
        not_valid_after=now + not_after_delta,
    )

    regenerated = tls.ensure_self_signed_cert(tmp_path)

    assert regenerated != original_pair
    assert original_pair[0].read_bytes() == invalid_cert
    assert regenerated[0].read_bytes() != invalid_cert
    _assert_pair_loads(*regenerated)


def test_reuse_repairs_private_key_permissions(tmp_path, monkeypatch):
    import app.tls as tls

    monkeypatch.setattr(tls, "_local_ip", lambda: "192.0.2.10")
    pair = tls.ensure_self_signed_cert(tmp_path)
    original_cert = pair[0].read_bytes()
    pair[1].chmod(0o644)

    assert tls.ensure_self_signed_cert(tmp_path) == pair
    assert pair[0].read_bytes() == original_cert
    if os.name == "posix":
        assert stat.S_IMODE(pair[1].stat().st_mode) == 0o600


def test_concurrent_corruption_repair_publishes_one_replacement(tmp_path, monkeypatch):
    import app.tls as tls

    monkeypatch.setattr(tls, "_local_ip", lambda: "192.0.2.10")
    original_pair = tls.ensure_self_signed_cert(tmp_path)
    original_pair[1].write_bytes(b"corrupt private key")
    original_generate = tls.ec.generate_private_key
    first_entered = threading.Event()
    allow_first = threading.Event()
    generation_count = 0
    count_lock = threading.Lock()

    def controlled_generate(*args, **kwargs):
        nonlocal generation_count
        with count_lock:
            generation_count += 1
        first_entered.set()
        assert allow_first.wait(5)
        return original_generate(*args, **kwargs)

    monkeypatch.setattr(tls.ec, "generate_private_key", controlled_generate)
    results = []
    errors = []

    def repair() -> None:
        try:
            results.append(tls.ensure_self_signed_cert(tmp_path))
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    first = threading.Thread(target=repair)
    second = threading.Thread(target=repair)
    first.start()
    assert first_entered.wait(5)
    second.start()
    allow_first.set()
    first.join(5)
    second.join(5)

    assert not first.is_alive() and not second.is_alive()
    assert errors == []
    assert generation_count == 1
    assert len(results) == 2
    assert results[0] == results[1]
    assert results[0] != original_pair
    _assert_pair_loads(*results[0])
