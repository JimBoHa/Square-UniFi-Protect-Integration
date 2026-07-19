"""Regression tests for first-run setup through the Windows scheduled task."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "windows" / "install-service.ps1"
RUNNER = ROOT / "scripts" / "windows" / "run-service.ps1"


def test_installer_activates_only_when_secure_bootstrap_is_available():
    installer = INSTALLER.read_text(encoding="utf-8")

    assert "inspect.signature(main.create_app).parameters" in installer
    assert '{"bind_host", "tls_enabled"} <= set(p)' in installer
    assert "$SecureBootstrap = $LASTEXITCODE -eq 0" in installer
    assert "if ($SecureBootstrap)" in installer


def test_task_persists_only_a_dpapi_protected_secret():
    installer = INSTALLER.read_text(encoding="utf-8")
    action = installer[installer.index("$Action = New-ScheduledTaskAction") :]

    assert "RandomNumberGenerator" in installer
    assert "ProtectedData]::Protect" in installer
    assert "DataProtectionScope]::CurrentUser" in installer
    assert "bootstrap-secret.dpapi" in installer
    assert '-Execute "powershell.exe"' in action
    assert "run-service.ps1" in installer
    assert '-File `"$Runner`"' in action
    assert "SPI_BOOTSTRAP_SECRET" not in action


def test_runner_clears_plaintext_and_deletes_handoff_after_setup():
    runner = RUNNER.read_text(encoding="utf-8")

    decrypt = runner.index("ProtectedData]::Unprotect")
    child_start = runner.index("[System.Diagnostics.Process]::Start")
    clear_environment = runner.index("Remove-Item Env:SPI_BOOTSTRAP_SECRET")
    setup_complete = runner.index("setup_complete.py")
    delete_handoff = runner.index("Remove-Item $BootstrapSecretFile", setup_complete)

    assert decrypt < child_start < clear_environment < setup_complete < delete_handoff
    assert "CreateNoWindow = $true" in runner
    assert "Invoke-RestMethod" not in runner
    assert "http://" not in runner
    assert "https://" not in runner


def test_reinstall_and_uninstall_stop_only_the_recorded_python_child():
    installer = INSTALLER.read_text(encoding="utf-8")

    stop_function = installer[
        installer.index("function Stop-SquareProtectService") : installer.index(
            "if ($Uninstall)"
        )
    ]
    assert "service-process.pid" in installer
    assert "Get-CimInstance Win32_Process" in stop_function
    assert "[IO.Path]::GetFullPath($Python)" in stop_function
    assert "[StringComparison]::OrdinalIgnoreCase" in stop_function
    assert "$ServiceProcess.CommandLine -match" in stop_function
    assert "Stop-Process -Id $ServicePid" in stop_function
    assert installer.count("Stop-SquareProtectService") >= 3
    assert "if ($Process.HasExited)" in RUNNER.read_text(encoding="utf-8")
    uninstall_exit = installer.index("exit 0", installer.index("if ($Uninstall)"))
    reinstall_stop = installer.index("Stop-SquareProtectService", uninstall_exit)
    dependency_setup = installer.index("ensure_dependencies.py")
    assert reinstall_stop < dependency_setup


def test_uninstall_removes_encrypted_handoff_before_exiting():
    installer = INSTALLER.read_text(encoding="utf-8")

    uninstall = installer.index("if ($Uninstall)")
    remove_handoff = installer.index("Remove-Item $BootstrapSecretFile", uninstall)
    uninstall_exit = installer.index("exit 0", uninstall)

    assert uninstall < remove_handoff < uninstall_exit


def test_windows_packaging_documents_the_protected_handoff():
    instructions = (ROOT / "PACKAGING.md").read_text(encoding="utf-8")

    assert "DPAPI-protected" in instructions
    assert "encrypted\nhandoff automatically" in instructions
    assert "never stores\nthe plaintext secret" in instructions
