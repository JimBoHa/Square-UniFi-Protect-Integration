# Install the integration to start automatically at logon (Windows).
# Run from PowerShell in the repository folder:
#   powershell -ExecutionPolicy Bypass -File scripts\windows\install-service.ps1 [-Uninstall]
param([switch]$Uninstall)
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$TaskName = "SquareProtect"
$DataDir = Join-Path $Repo "data"
$Binary = "$Repo\target\release\square-unifi-protect.exe"
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
        $ExpectedBinary = [IO.Path]::GetFullPath($Binary)
        $ObservedExecutable = [IO.Path]::GetFullPath($ServiceProcess.ExecutablePath)
        if (
          [string]::Equals(
            $ExpectedBinary,
            $ObservedExecutable,
            [StringComparison]::OrdinalIgnoreCase
          )
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

if ($null -eq (Get-Command cargo -ErrorAction SilentlyContinue)) {
  throw "Rust/Cargo is required. Install it from https://rustup.rs and run this installer again."
}
Write-Host "Building the Rust service..."
& cargo build --manifest-path "$Repo\Cargo.toml" --locked --release
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Binary)) {
  throw "The Rust service build failed."
}

$SetupSecret = $null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
$env:SPI_DATA_DIR = $DataDir
& $Binary --setup-complete 2>$null
$SetupAlreadyComplete = $LASTEXITCODE -eq 0

if (-not $SetupAlreadyComplete) {
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
if ($null -ne $SetupSecret) {
  Write-Host "One-time setup secret: $SetupSecret"
  Write-Host "The encrypted handoff is deleted automatically after setup succeeds."
  $SetupSecret = $null
}
