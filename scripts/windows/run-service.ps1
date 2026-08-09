# Start the scheduled Windows service and retire its DPAPI-protected setup secret.
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Binary = "$Repo\target\release\square-unifi-protect.exe"
$BootstrapSecretFile = Join-Path $Repo "data\bootstrap-secret.dpapi"
$ServicePidFile = Join-Path $Repo "data\service-process.pid"
$env:SPI_DATA_DIR = "$Repo\data"
if ([string]::IsNullOrWhiteSpace($env:SPI_PORT)) {
  $env:SPI_PORT = "3546"
}
$HasBootstrapSecret = Test-Path $BootstrapSecretFile
$BootstrapSecret = $null

if ($HasBootstrapSecret) {
  Add-Type -AssemblyName System.Security
  $ProtectedBytes = [IO.File]::ReadAllBytes($BootstrapSecretFile)
  $PlainBytes = $null
  try {
    $PlainBytes = [Security.Cryptography.ProtectedData]::Unprotect(
      $ProtectedBytes,
      $null,
      [Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $BootstrapSecret = [Text.Encoding]::UTF8.GetString($PlainBytes)
    $env:SPI_BOOTSTRAP_SECRET = $BootstrapSecret
  } finally {
    [Array]::Clear($ProtectedBytes, 0, $ProtectedBytes.Length)
    if ($null -ne $PlainBytes) {
      [Array]::Clear($PlainBytes, 0, $PlainBytes.Length)
    }
  }
}

$StartInfo = New-Object System.Diagnostics.ProcessStartInfo
$StartInfo.FileName = $Binary
$StartInfo.Arguments = ""
$StartInfo.WorkingDirectory = $Repo
$StartInfo.UseShellExecute = $false
$StartInfo.CreateNoWindow = $true
try {
  $Process = [System.Diagnostics.Process]::Start($StartInfo)
} finally {
  Remove-Item Env:SPI_BOOTSTRAP_SECRET -ErrorAction SilentlyContinue
  $BootstrapSecret = $null
}
$TemporaryPidFile = "$ServicePidFile.$PID.tmp"
[IO.File]::WriteAllText($TemporaryPidFile, "$($Process.Id)`n")
Move-Item $TemporaryPidFile $ServicePidFile -Force

try {
  if ($HasBootstrapSecret) {
    while (-not $Process.HasExited) {
      Start-Sleep -Seconds 2
      $env:SPI_DATA_DIR = "$Repo\data"
      & $Binary --setup-complete
      if ($LASTEXITCODE -eq 0) {
        Remove-Item $BootstrapSecretFile -Force -ErrorAction SilentlyContinue
        break
      }
    }
  }
  $Process.WaitForExit()
  $ServiceExitCode = $Process.ExitCode
} finally {
  Remove-Item $TemporaryPidFile -Force -ErrorAction SilentlyContinue
  # Keep the PID handoff if Task Scheduler stops this wrapper while its child
  # remains alive; the installer verifies and terminates that exact process.
  if ($Process.HasExited) {
    Remove-Item $ServicePidFile -Force -ErrorAction SilentlyContinue
  }
}

exit $ServiceExitCode
