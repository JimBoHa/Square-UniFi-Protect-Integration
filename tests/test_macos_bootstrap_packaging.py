"""Static security regressions for the native Rust macOS app."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "bin" / "square-protect-menubar.rs"


def _source():
    return SOURCE.read_text(encoding="utf-8")


def test_setup_probe_scrubs_the_secret_and_uses_the_native_probe():
    source = _source()

    assert '.arg("--setup-complete")' in source
    assert '.env("SPI_DATA_DIR", data_dir)' in source
    assert '.env_remove("SPI_BOOTSTRAP_SECRET")' in source


def test_setup_secret_is_zeroized_and_never_printed():
    source = _source()

    assert "Option<Zeroizing<String>>" in source
    assert "self.bootstrap_secret.take();" in source
    assert "println!(secret" not in source
    assert "eprintln!(secret" not in source


def test_secret_dialog_receives_the_secret_over_stdin_not_process_arguments():
    source = _source()
    function = source[source.index("fn run_applescript"):]

    assert 'Command::new("/usr/bin/osascript")' in function
    assert ".stdin(Stdio::piped())" in function
    assert ".write_all(script)" in function
    assert ".arg(script)" not in function


def test_wrapper_supervises_and_terminates_its_owned_server():
    source = _source()

    assert "impl Drop for ServerProcess" in source
    assert "libc::SIGTERM" in source
    assert "SHUTDOWN_GRACE" in source
