# scripts/build-windows-msi.ps1
#
# Assemble the per-arch MSI for the Tracenium Agent.
#
# Prerequisites (run earlier in the pipeline):
#   1. scripts/build-windows-binaries.sh   →  produces PrivSvc + AgentTray EXEs
#                                              under build/win-binaries/<arch>/
#   2. scripts/build-agentcore-windows.ps1 →  produces AgentCore/ tree
#                                              under build/win-binaries/<arch>/
#
# This script then:
#   1. Stages all inputs into windows/installer/binaries/ (the bindpath
#      WiX expects — see Files.wxs `<Files Include="binaries\...">`).
#   2. Runs `wix build` with -arch parameter matching the target arch.
#   3. Moves the resulting MSI to build/win-msi/<arch>/Tracenium-Agent-<v>-<arch>.msi.
#
# After the consolidation, the WiX project lives at
# $RepoRoot/windows/installer/. There's ONE wix/ source tree shared
# across both archs (Phase A merged what used to be two copies). The
# only arch-specific input is the `binaries/` content, which we stage
# fresh per build.
#
# Code signing is NOT done here — it happens in a separate step (the
# GHA workflow uses Azure Trusted Signing; local builds can `signtool`
# manually after the MSI is produced).

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet("x64", "arm64")]
  [string]$Arch
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ── Resolve paths ────────────────────────────────────────────────────
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Split-Path -Parent $ScriptDir

if (-not (Test-Path "$RepoRoot/package.json")) {
  throw "Could not find agent repo root at $RepoRoot (package.json missing)"
}

$InstallerDir = Join-Path $RepoRoot "windows/installer"
if (-not (Test-Path $InstallerDir)) {
  throw "WiX installer dir missing at $InstallerDir (Phase A consolidation incomplete?)"
}

$BinSrcDir = Join-Path $RepoRoot "build/win-binaries/$Arch"
foreach ($needed in @(
    "AgentCore/TraceniumAgentCore.exe",
    "AgentCore/TraceniumAgentCore.xml",
    "AgentCore/node/node.exe",
    "AgentCore/app/dist/index.js",
    "AgentTray/Tracenium.AgentTray.exe",
    "PrivSvc/Tracenium.PrivSvc.Windows.exe"
  )) {
  $p = Join-Path $BinSrcDir $needed
  if (-not (Test-Path $p)) {
    throw @"
Missing MSI input: $p
Run the producer first:
  scripts/build-windows-binaries.sh         (PrivSvc + AgentTray)
  scripts/build-agentcore-windows.ps1 -Arch $Arch   (AgentCore)
"@
  }
}

# ── Resolve version ──────────────────────────────────────────────────
$Version = if ($env:TRACENIUM_AGENT_VERSION) {
  $env:TRACENIUM_AGENT_VERSION
} else {
  $pkg = Get-Content (Join-Path $RepoRoot "package.json") -Raw | ConvertFrom-Json
  $pkg.version
}
if (-not $Version) { throw "Could not resolve agent version" }

Write-Host "==== build-windows-msi ====" -ForegroundColor Cyan
Write-Host "  Repo:       $RepoRoot"
Write-Host "  Arch:       $Arch"
Write-Host "  Version:    $Version"
Write-Host "  Installer:  $InstallerDir"
Write-Host "  Inputs:     $BinSrcDir"
Write-Host ""

# ── Preflight: WiX 6 ─────────────────────────────────────────────────
# WiX 6 is a dotnet global tool. The CI workflow installs it; locally
# the operator runs `dotnet tool install --global wix --version 6.*`.
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
  throw "WiX 6 not in PATH. Install with: dotnet tool install --global wix --version 6.*"
}

# ── Stage binaries under installer/binaries/ ─────────────────────────
# WiX 6's <Files Include="binaries\..."> resolves relative to the
# -bindpath. We pass -bindpath = $InstallerDir, so binaries/ must live
# under $InstallerDir at build time.
#
# We WIPE binaries/ before each build so a previous arch's leftovers
# don't accidentally end up in the new MSI (caught a real bug pre-
# consolidation where a stale node.exe from a wrong arch was packaged).
$StagedBin = Join-Path $InstallerDir "binaries"
if (Test-Path $StagedBin) { Remove-Item $StagedBin -Recurse -Force }
New-Item -ItemType Directory -Force -Path $StagedBin | Out-Null

Write-Host "→ staging inputs into $StagedBin" -ForegroundColor Yellow
Copy-Item (Join-Path $BinSrcDir "AgentCore") $StagedBin -Recurse -Force
Copy-Item (Join-Path $BinSrcDir "AgentTray") $StagedBin -Recurse -Force
Copy-Item (Join-Path $BinSrcDir "PrivSvc")   $StagedBin -Recurse -Force

# Stage static installer scripts (not produced by the AgentCore build).
# register-watchdog.ps1 is a repo source file consumed by WiX via
#   <File Source="binaries\AgentCore\scripts\register-watchdog.ps1">
$scriptsStageDir = Join-Path $StagedBin "AgentCore\scripts"
New-Item -ItemType Directory -Force -Path $scriptsStageDir | Out-Null
Copy-Item (Join-Path $InstallerDir "scripts\register-watchdog.ps1") $scriptsStageDir -Force

# ── Run wix build ────────────────────────────────────────────────────
# Output goes to a temp filename inside the installer dir, then we move
# it to its final per-arch home under build/win-msi/.
$TmpMsi = Join-Path $InstallerDir "Tracenium-Agent.msi"
if (Test-Path $TmpMsi) { Remove-Item $TmpMsi -Force }

Push-Location $InstallerDir
try {
  Write-Host "→ wix build -arch $Arch" -ForegroundColor Yellow
  wix build `
    wix/Product.wxs `
    wix/Files.wxs `
    wix/AgentCoreFiles.wxs `
    wix/PrivSvc.wxs `
    wix/UI.wxs `
    -ext WixToolset.Util.wixext `
    -ext WixToolset.UI.wixext `
    -culture en-US `
    -arch $Arch `
    -bindpath (Get-Location).Path `
    -o $TmpMsi
  if ($LASTEXITCODE -ne 0) { throw "wix build failed (exit $LASTEXITCODE)" }
} finally {
  Pop-Location
}

if (-not (Test-Path $TmpMsi)) {
  throw "wix build reported success but $TmpMsi was not created"
}

# ── Move to final location ───────────────────────────────────────────
$OutDir = Join-Path $RepoRoot "build/win-msi/$Arch"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$FinalMsi = Join-Path $OutDir "Tracenium-Agent-$Version-$Arch.msi"
if (Test-Path $FinalMsi) { Remove-Item $FinalMsi -Force }
Move-Item $TmpMsi $FinalMsi

# Clean staged binaries to keep the working tree tidy. Build outputs
# live under build/, not under the WiX source dir.
Remove-Item $StagedBin -Recurse -Force

# Clean WiX intermediates that landed beside the MSI.
Get-ChildItem $InstallerDir -Filter "*.wixpdb" | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem $InstallerDir -Filter "*.wixobj" | Remove-Item -Force -ErrorAction SilentlyContinue

# ── Summary ──────────────────────────────────────────────────────────
$msiSize = (Get-Item $FinalMsi).Length
$msiSha  = (Get-FileHash $FinalMsi -Algorithm SHA256).Hash.ToLower()

Write-Host ""
Write-Host "==== MSI BUILD DONE ====" -ForegroundColor Green
Write-Host "  msi    : $FinalMsi"
Write-Host "  size   : $msiSize bytes"
Write-Host "  sha256 : $msiSha"
Write-Host "  arch   : $Arch"
Write-Host "  version: $Version"
Write-Host ""
Write-Host "Next: sign the MSI (Azure Trusted Signing in CI; manual signtool locally)"
