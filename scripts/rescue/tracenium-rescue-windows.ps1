# scripts/rescue/tracenium-rescue-windows.ps1
#
# One-shot rescue for Windows devices stuck on an old agent (typically
# 1.1.14 with the broken update path) that won't self-update. Forces a
# hard-clean uninstall + reinstall from a locally-supplied .msi.
#
# Usage (open PowerShell as ADMIN):
#   .\tracenium-rescue-windows.ps1 -MsiPath C:\path\to\Tracenium-Agent-1.1.17-x64.msi
#
# What it does:
#   1. Stops Tracenium services + kills any lingering node.exe under
#      our install dir
#   2. Runs `msiexec /x` on any existing Tracenium MSI registered in
#      the uninstall registry
#   3. HARD DELETES the install directory (WiX's uninstall is known to
#      leave residuals — confirmed with node 24.14.1 stale binaries)
#   4. Adds Microsoft Defender exclusions so the new MSI's signed
#      binaries don't get quarantined while their Trusted Signing cert
#      is still building reputation
#   5. Installs the new .msi with verbose log to %TEMP%\tracenium-install.log
#   6. Sanity-checks: node.exe version, service state, file presence
#
# Tolerates a clean device too — uninstall step is a no-op if nothing
# was registered.

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$MsiPath
)

$ErrorActionPreference = 'Stop'

# Must be admin (uninstall + write to Program Files)
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$amAdmin = ([System.Security.Principal.WindowsPrincipal]$me).IsInRole(
  [System.Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $amAdmin) {
  throw "This script must be run as Administrator."
}
if (-not (Test-Path $MsiPath)) {
  throw "MSI not found at: $MsiPath"
}

$MsiAbs = (Resolve-Path $MsiPath).Path
Write-Host "==== Tracenium Windows rescue ===="
Write-Host "  msi:    $MsiAbs"
Write-Host "  size:   $((Get-Item $MsiAbs).Length) bytes"
Write-Host "  sha256: $((Get-FileHash $MsiAbs -Algorithm SHA256).Hash.ToLower())"
Write-Host ""

# ── 1. Stop services + kill stragglers ────────────────────────────
Write-Host "→ stopping Tracenium services (if any)" -ForegroundColor Yellow
Get-Service -Name "Tracenium*" -ErrorAction SilentlyContinue | ForEach-Object {
  try {
    Stop-Service $_.Name -Force -ErrorAction Stop
    Write-Host "  stopped: $($_.Name)"
  } catch {
    Write-Host "  (already stopped or not present: $($_.Name))" -ForegroundColor DarkGray
  }
}

# Kill any leftover node.exe running from our install path
Get-Process -Name node -ErrorAction SilentlyContinue | Where-Object {
  $_.Path -like "C:\Program Files\Tracenium\*"
} | ForEach-Object {
  Write-Host "  killing leftover node.exe pid=$($_.Id)"
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}

Start-Sleep -Seconds 2

# ── 2. Uninstall existing Tracenium MSI from registry ─────────────
Write-Host ""
Write-Host "→ uninstalling existing Tracenium installation (if any)" -ForegroundColor Yellow
$installed = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* `
                              -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -like "*Tracenium*" }

foreach ($entry in $installed) {
  Write-Host "  uninstalling: $($entry.DisplayName) $($entry.DisplayVersion)"
  $code = $entry.PSChildName   # ProductCode GUID
  $logTmp = "$env:TEMP\tracenium-uninstall-$($code).log"
  Start-Process "msiexec.exe" `
    -ArgumentList "/x $code /qn /norestart /l*v `"$logTmp`"" `
    -Wait `
    -NoNewWindow
  Write-Host "    log: $logTmp"
}

Start-Sleep -Seconds 3

# ── 3. HARD DELETE residual install dir ───────────────────────────
# WiX uninstall is conservative — it skips files modified post-install
# (touched by AV scans, by the agent writing config, etc). We saw this
# leave node v24.14.1 in place when the new MSI shipped 24.10.0. So we
# nuke the directory before reinstalling.
Write-Host ""
Write-Host "→ removing residual install directories" -ForegroundColor Yellow
foreach ($p in @(
    "C:\Program Files\Tracenium",
    "C:\ProgramData\Tracenium"
  )) {
  if (Test-Path $p) {
    Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $p) {
      Write-Host "  ⚠ could not fully remove: $p (a file may be locked)" -ForegroundColor Yellow
    } else {
      Write-Host "  removed: $p"
    }
  }
}

# ── 4. Microsoft Defender exclusions ──────────────────────────────
# Trusted Signing certs build reputation with each downloaded copy.
# Until the cert's accumulated enough trust, Defender's "Block at first
# sight" / SmartScreen can quarantine node.exe specifically (a heavy
# bundled JS runtime with a brand-new cert = classic suspect pattern).
# Excluding our install path is the safest workaround until reputation
# builds.
Write-Host ""
Write-Host "→ adding Microsoft Defender exclusions for Tracenium" -ForegroundColor Yellow
try {
  Add-MpPreference -ExclusionPath    "C:\Program Files\Tracenium" -ErrorAction SilentlyContinue
  Add-MpPreference -ExclusionProcess "node.exe"                   -ErrorAction SilentlyContinue
  Add-MpPreference -ExclusionProcess "TraceniumAgentCore.exe"     -ErrorAction SilentlyContinue
  Add-MpPreference -ExclusionProcess "Tracenium.PrivSvc.Windows.exe" -ErrorAction SilentlyContinue
  Add-MpPreference -ExclusionProcess "Tracenium.AgentTray.exe"    -ErrorAction SilentlyContinue
  Write-Host "  exclusions added"
} catch {
  Write-Host "  (exclusions failed — likely no Defender on this host)" -ForegroundColor DarkGray
}

# ── 5. Install the new MSI ────────────────────────────────────────
Write-Host ""
Write-Host "→ installing $MsiAbs" -ForegroundColor Yellow
$installLog = "$env:TEMP\tracenium-install.log"
$proc = Start-Process "msiexec.exe" `
  -ArgumentList "/i `"$MsiAbs`" /qn /norestart /l*v `"$installLog`"" `
  -Wait `
  -NoNewWindow `
  -PassThru
Write-Host "  exit code: $($proc.ExitCode)"
Write-Host "  log:       $installLog"

if ($proc.ExitCode -ne 0) {
  Write-Host ""
  Write-Host "❌ MSI install failed. Last 20 'error' lines from log:" -ForegroundColor Red
  Select-String -Path $installLog -Pattern "error|fail" -CaseSensitive:$false |
    Select-Object -Last 20 | ForEach-Object { Write-Host "  $($_.Line)" }
  exit $proc.ExitCode
}

# ── 6. Sanity check ───────────────────────────────────────────────
Start-Sleep -Seconds 5
Write-Host ""
Write-Host "==== POST-INSTALL STATE ===="

# node.exe present + correct version
$nodeBin = "C:\Program Files\Tracenium\AgentCore\node\node.exe"
if (Test-Path $nodeBin) {
  $nodeVer = & $nodeBin --version 2>&1
  Write-Host "  node.exe: $nodeVer (path: $nodeBin)"
} else {
  Write-Host "  ⚠ node.exe MISSING at $nodeBin" -ForegroundColor Red
}

# Service state
Get-Service -Name "Tracenium*" -ErrorAction SilentlyContinue | ForEach-Object {
  Write-Host "  service: $($_.Name) → $($_.Status)"
}

# Running processes
$running = Get-Process -Name node, "Tracenium*" -ErrorAction SilentlyContinue |
  Where-Object { $_.Path -like "C:\Program Files\Tracenium\*" }
if ($running) {
  $running | ForEach-Object {
    Write-Host "  pid=$($_.Id) $($_.Name) $($_.Path)"
  }
} else {
  Write-Host "  ⚠ no Tracenium processes running" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "✓ Rescue complete. Device should report 1.1.17 to backend within 1-2 min." -ForegroundColor Green
Write-Host "  Verify in the portal that this device now shows agent_version 1.1.17."
