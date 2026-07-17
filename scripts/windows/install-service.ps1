# Install the integration to start automatically at logon (Windows).
# Run from PowerShell in the repository folder:
#   powershell -ExecutionPolicy Bypass -File scripts\windows\install-service.ps1 [-Uninstall]
param([switch]$Uninstall)
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$TaskName = "SquareProtect"

if ($Uninstall) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "Uninstalled scheduled task."
  exit 0
}

if (-not (Test-Path "$Repo\.venv\Scripts\python.exe")) {
  Write-Host "Setting up the Python environment..."
  python -m venv "$Repo\.venv"
  & "$Repo\.venv\Scripts\pip.exe" install --quiet --upgrade pip
  & "$Repo\.venv\Scripts\pip.exe" install --quiet -e $Repo
}

$Action = New-ScheduledTaskAction `
  -Execute "$Repo\.venv\Scripts\pythonw.exe" `
  -Argument "-m app" -WorkingDirectory $Repo
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
  -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "Installed. Dashboard: http://localhost:8000"
