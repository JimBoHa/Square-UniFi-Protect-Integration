"""Self-signed TLS helper tests."""

import multiprocessing
import ssl
import stat
import threading
from pathlib import Path

import pytest
from cryptography import x509

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


def test_cert_generated_once_with_private_key_permissions(tmp_path):
    cert_path, key_path = ensure_self_signed_cert(tmp_path)
    assert cert_path.is_file() and key_path.is_file()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert "localhost" in san.value.get_values_for_type(x509.DNSName)

    # Second call must reuse, not regenerate.
    again_cert, again_key = ensure_self_signed_cert(tmp_path)
    assert again_cert.read_bytes() == cert_path.read_bytes()


def test_uvicorn_kwargs_disabled_and_enabled(tmp_path):
    assert uvicorn_tls_kwargs(tmp_path, False) == {}
    kwargs = uvicorn_tls_kwargs(tmp_path, True)
    assert set(kwargs) == {"ssl_certfile", "ssl_keyfile"}


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
