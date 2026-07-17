"""Self-signed TLS helper tests."""

import stat

from cryptography import x509

from app.tls import ensure_self_signed_cert, uvicorn_tls_kwargs


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
