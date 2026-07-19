# Install the integration to start automatically at logon (Windows).
# Run from PowerShell in the repository folder:
#   powershell -ExecutionPolicy Bypass -File scripts\windows\install-service.ps1 [-Uninstall]
param([switch]$Uninstall)
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$TaskName = "SquareProtect"
$DataDir = Join-Path $Repo "data"
$Python = "$Repo\.venv\Scripts\python.exe"
$BootstrapSecretFile = Join-Path $DataDir "bootstrap-secret.dpapi"
$ServicePidFile = Join-Path $DataDir "service-process.pid"

function Stop-SquareProtectService {
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if (Test-Path $ServicePidFile) {
    $ServicePid = 0
    $PidText = Get-Content $ServicePidFile -Raw -ErrorAction SilentlyContinue
    if ([int]::TryParse($PidText, [ref]$ServicePid)) {
      $ServiceProcess = Get-CimInstance Win32_Process `
        -Filter "ProcessId = $ServicePid" -ErrorAction SilentlyContinue
      if ($null -ne $ServiceProcess -and $ServiceProcess.ExecutablePath) {
        $ExpectedPython = [IO.Path]::GetFullPath($Python)
        $ObservedExecutable = [IO.Path]::GetFullPath($ServiceProcess.ExecutablePath)
        $RunsSquareProtect = $ServiceProcess.CommandLine -match '(?:^|\s)-m\s+app(?:\s|$)'
        if (
          [string]::Equals(
            $ExpectedPython,
            $ObservedExecutable,
            [StringComparison]::OrdinalIgnoreCase
          ) -and $RunsSquareProtect
        ) {
          Stop-Process -Id $ServicePid -Force -ErrorAction SilentlyContinue
        }
      }
    }
    Remove-Item $ServicePidFile -Force -ErrorAction SilentlyContinue
  }
}

if ($Uninstall) {
  Stop-SquareProtectService
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Remove-Item $BootstrapSecretFile -Force -ErrorAction SilentlyContinue
  Write-Host "Uninstalled scheduled task."
  exit 0
}

Stop-SquareProtectService

if (-not (Test-Path "$Repo\.venv\Scripts\python.exe")) {
  Write-Host "Setting up the Python environment..."
  python -m venv "$Repo\.venv"
}
& "$Repo\.venv\Scripts\python.exe" "$Repo\scripts\ensure_dependencies.py" `
  "$Repo" "$Repo\.venv"

& $Python -c 'import inspect; from app import main; p = inspect.signature(main.create_app).parameters; raise SystemExit(0 if {"bind_host", "tls_enabled"} <= set(p) and hasattr(main, "BOOTSTRAP_SECRET_MIN_LENGTH") else 1)'
$SecureBootstrap = $LASTEXITCODE -eq 0
$SetupSecret = $null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

if ($SecureBootstrap) {
  Add-Type -AssemblyName System.Security
  $RandomBytes = New-Object byte[] 32
  $Generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $Generator.GetBytes($RandomBytes)
    $SetupSecret = [Convert]::ToBase64String($RandomBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
  } finally {
    $Generator.Dispose()
    [Array]::Clear($RandomBytes, 0, $RandomBytes.Length)
  }
  $PlainBytes = [Text.Encoding]::UTF8.GetBytes($SetupSecret)
  try {
    $ProtectedBytes = [Security.Cryptography.ProtectedData]::Protect(
      $PlainBytes,
      $null,
      [Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    [IO.File]::WriteAllBytes($BootstrapSecretFile, $ProtectedBytes)
    [Array]::Clear($ProtectedBytes, 0, $ProtectedBytes.Length)
  } finally {
    [Array]::Clear($PlainBytes, 0, $PlainBytes.Length)
  }
} else {
  # The packaging PR can merge before secure bootstrap without changing the
  # legacy app's setup behavior.
  Remove-Item $BootstrapSecretFile -Force -ErrorAction SilentlyContinue
}

$Runner = "$Repo\scripts\windows\run-service.ps1"
$Action = New-ScheduledTaskAction `
  -Execute "powershell.exe" `
  -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Runner`"" `
  -WorkingDirectory $Repo
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet `
  -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
  -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
  -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "Installed. Dashboard: http://localhost:8000"
if ($SecureBootstrap) {
  Write-Host "One-time setup secret: $SetupSecret"
  Write-Host "The encrypted handoff is deleted automatically after setup succeeds."
  $SetupSecret = $null
}
