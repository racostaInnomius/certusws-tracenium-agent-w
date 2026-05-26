# Registers the TraceniumWatchdog scheduled task.
# Idempotent — re-running replaces the existing task.
# Called from the MSI as a deferred CustomAction (runs as SYSTEM).

$ErrorActionPreference = "Stop"

$dataDir = "C:\ProgramData\Tracenium\Agent"
$wdScript = Join-Path $dataDir "watchdog.ps1"

# Ensure ProgramData directory exists (the agent will use it for logs)
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

# Watchdog script content written to a stable path so the scheduled task
# always has a resolvable file reference.
@'
$ErrorActionPreference = "SilentlyContinue"
$logPath = "C:\ProgramData\Tracenium\Agent\watchdog.log"
$svc = Get-Service -Name "TraceniumAgentCore"
if ($null -eq $svc) {
    Add-Content -Path $logPath -Value "$(Get-Date -Format 'o') | service_missing"
    return
}
if ($svc.Status -ne 'Running') {
    Add-Content -Path $logPath -Value "$(Get-Date -Format 'o') | restart (was=$($svc.Status))"
    try {
        Start-Service -Name "TraceniumAgentCore" -ErrorAction Stop
        Add-Content -Path $logPath -Value "$(Get-Date -Format 'o') | started"
    } catch {
        Add-Content -Path $logPath -Value "$(Get-Date -Format 'o') | start_failed: $($_.Exception.Message)"
    }
}
'@ | Set-Content -Path $wdScript -Encoding UTF8 -Force

# Register the scheduled task (overwrites existing)
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$wdScript`""

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5)

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

Register-ScheduledTask -TaskName "TraceniumWatchdog" `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "Restart TraceniumAgentCore if it ends up in Stopped state — last-resort safety net" `
    -Force | Out-Null
