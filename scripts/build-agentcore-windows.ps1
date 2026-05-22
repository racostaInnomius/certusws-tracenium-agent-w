# scripts/build-agentcore-windows.ps1
#
# Build the AgentCore tree (the node bundle that the MSI installs as a
# Windows service via WinSW). Runs ONLY on a Windows host — the better-
# sqlite3 native binding must be rebuilt against the host's ABI, and
# WinSW is a Windows-only program.
#
# What it produces:
#
#   build\win-binaries\<arch>\AgentCore\
#     ├── TraceniumAgentCore.exe       # WinSW wrapper (per-arch download)
#     ├── TraceniumAgentCore.xml       # WinSW service config (from repo)
#     ├── node\node.exe                # Node 24 runtime (per-arch download)
#     ├── logs\                        # empty dir for runtime logs
#     └── app\
#         ├── dist\index.js            # esbuild bundle (arch-agnostic JS)
#         └── node_modules\            # ONLY native deps (better-sqlite3
#                                        + bindings + file-uri-to-path),
#                                        rebuilt for host arch.
#
# The arch comes from the host (the runner you executed this on). To
# match your current 2-machine workflow:
#   * On an ARM64 W11 (your VM)    → pass -Arch arm64 (or let auto-detect)
#   * On an x64 W11   (your physical) → pass -Arch x64
# In CI both archs run in parallel on matrix runners
# (windows-latest = x64, windows-11-arm = arm64).
#
# Why ONLY native deps in node_modules instead of full npm install:
# the agent bundle is produced by esbuild with --bundle, which inlines
# ALL pure-JS deps into dist/index.js. Native modules can't be bundled
# (they're .node files loaded by dlopen), so they MUST be shipped as
# separate node_modules entries that better-sqlite3 / bindings reach via
# require() at runtime. Shipping the full node_modules would bloat the
# MSI by ~200 MB of unused JS. This staging mirrors what
# build-linux-binaries.sh does on the Linux side.

[CmdletBinding()]
param(
  [ValidateSet("x64", "arm64", "auto")]
  [string]$Arch = "auto",

  [string]$NodeVersion = ""  # Optional override; default reads .nodeversion
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # silence Invoke-WebRequest progress bar (huge in CI logs)

# ── Resolve paths ────────────────────────────────────────────────────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir

if (-not (Test-Path "$RepoRoot/package.json")) {
  throw "Could not find agent repo root at $RepoRoot (package.json missing)"
}

# ── Resolve arch ─────────────────────────────────────────────────────
if ($Arch -eq "auto") {
  # PROCESSOR_ARCHITECTURE values on Windows:
  #   AMD64 → x64
  #   ARM64 → arm64
  $hostArch = $env:PROCESSOR_ARCHITECTURE
  switch ($hostArch) {
    "AMD64" { $Arch = "x64" }
    "ARM64" { $Arch = "arm64" }
    default { throw "Unsupported host arch: $hostArch (PROCESSOR_ARCHITECTURE)" }
  }
}

# ── Resolve NodeVersion ──────────────────────────────────────────────
if (-not $NodeVersion) {
  $nodeversionFile = Join-Path $RepoRoot ".nodeversion"
  if (Test-Path $nodeversionFile) {
    $NodeVersion = (Get-Content $nodeversionFile -Raw).Trim()
  } else {
    throw "No .nodeversion file at $nodeversionFile and -NodeVersion not passed"
  }
}

# ── Tooling preflight ────────────────────────────────────────────────
# node + npm must be installed on the host. In CI we use actions/setup-node@v4;
# locally the operator installs Node directly. We DON'T require the host's
# node to match $NodeVersion — host node only runs npm for the rebuild step;
# the BUNDLED node we package is downloaded fresh.
foreach ($cmd in @("node", "npm", "npx")) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
    throw "Required command '$cmd' not found in PATH. Install Node.js or use actions/setup-node."
  }
}

Write-Host "==== build-agentcore-windows ====" -ForegroundColor Cyan
Write-Host "  Repo:        $RepoRoot"
Write-Host "  Arch:        $Arch"
Write-Host "  NodeVersion: $NodeVersion"
Write-Host "  Host node:   $(node --version)"
Write-Host ""

# ── Output layout ────────────────────────────────────────────────────
$OutBase = Join-Path $RepoRoot "build/win-binaries/$Arch/AgentCore"
$OutApp  = Join-Path $OutBase  "app"
$OutDist = Join-Path $OutApp   "dist"
$OutNm   = Join-Path $OutApp   "node_modules"
$OutNode = Join-Path $OutBase  "node"
$OutLogs = Join-Path $OutBase  "logs"

# Clean re-stage — pkg-root style. Avoids accidental cross-arch
# contamination if the same checkout is used for both archs sequentially.
if (Test-Path $OutBase) { Remove-Item $OutBase -Recurse -Force }
New-Item -ItemType Directory -Force -Path $OutBase, $OutApp, $OutDist, $OutNm, $OutNode, $OutLogs | Out-Null

# ── 1. esbuild the agent bundle ──────────────────────────────────────
# Output is a single JS file. Arch-agnostic — esbuild produces the same
# bytes on x64 and arm64 hosts given the same source + lockfile.
# Reuse host node_modules for esbuild itself (we expect `npm ci` has
# already run at the repo root in the workflow).
Write-Host "→ esbuild agent core" -ForegroundColor Yellow
Push-Location $RepoRoot
try {
  # Invoke esbuild via its JS entry, NOT via node_modules/.bin/esbuild.
  #
  # The .bin/esbuild file is npm's POSIX shell shim — running `node`
  # against it on Windows fails with:
  #     node_modules\.bin\esbuild:2
  #     basedir=$(dirname "$(echo "$0" | sed -e 's,\\,/,g')")
  #               ^^^^^^^
  #     SyntaxError: missing ) after argument list
  # (because node tried to parse the bash script as JavaScript).
  #
  # Calling `node node_modules/esbuild/bin/esbuild` works the SAME way
  # on every platform — it's a tiny JS launcher that knows how to find
  # esbuild's native binary inside its own package.
  $esbuildJs = Join-Path $RepoRoot "node_modules/esbuild/bin/esbuild"
  if (-not (Test-Path $esbuildJs)) {
    # Fallback for local invocations without a prior `npm ci`. CI
    # workflows always run npm ci first, so this is just for the
    # "I cloned the repo and ran the script" case.
    Write-Host "  (host node_modules missing — running npm ci)" -ForegroundColor DarkGray
    npm ci --no-audit --no-fund
  }
  if (-not (Test-Path $esbuildJs)) {
    throw "esbuild JS entry not found at $esbuildJs even after npm ci. Check package.json devDependencies."
  }
  & node $esbuildJs `
    "src/index.ts" `
    --bundle `
    --platform=node `
    --format=cjs `
    --target=node24 `
    --external:better-sqlite3 `
    --outfile="$OutDist/index.js"
  if ($LASTEXITCODE -ne 0) { throw "esbuild failed" }
} finally {
  Pop-Location
}

# ── 2. Stage native deps + rebuild better-sqlite3 ────────────────────
# Strategy: create a minimal package.json under $OutApp that only
# declares the three native runtime deps (better-sqlite3 + its peers).
# Then `npm install --omit=dev` there → host node-gyp compiles
# better-sqlite3 for the host's ABI automatically. Same pattern used
# by build-linux-binaries.sh on Linux.
Write-Host "→ staging native deps + rebuilding better-sqlite3 for $Arch" -ForegroundColor Yellow
$repoPkg = Get-Content (Join-Path $RepoRoot "package.json") -Raw | ConvertFrom-Json
$nativeDeps = @{
  # Pin to the SAME versions as the host package.json. better-sqlite3
  # is the only one whose native binding actually gets compiled; the
  # other two are pure-JS but ship as transitive deps of better-sqlite3
  # and Node's require resolver expects them at sibling paths.
  "better-sqlite3"     = $repoPkg.dependencies."better-sqlite3"
  "bindings"           = "*"
  "file-uri-to-path"   = "*"
}
$nativePkg = @{
  name = "tracenium-agentcore-native"
  version = "0.0.0"
  private = $true
  dependencies = $nativeDeps
}
$nativePkg | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $OutApp "package.json") -Encoding UTF8

Push-Location $OutApp
try {
  # Two modes depending on host vs. target arch:
  #
  # Native arch (host == target):
  #   `--build-from-source` forces node-gyp to compile the binding
  #   fresh. Guarantees ABI match and avoids any "wrong-arch prebuild
  #   slipped in" surprise. This is the path build-linux-binaries.sh
  #   takes on Linux.
  #
  # Cross arch (host != target, e.g. x64 host building arm64 MSI):
  #   We can't compile a foreign-arch binary from this host's gcc
  #   without setting up cross-compilers. Instead, we install in
  #   PREBUILD mode: npm_config_arch + target_platform tell npm to
  #   download the precompiled .node binding for the requested arch
  #   from better-sqlite3's GitHub release. We trust the prebuild
  #   because better-sqlite3 publishes them per release with checksums.
  #
  #   The win-arm64 prebuild has been shipped by better-sqlite3 since
  #   v11.x. If a future version drops it, this script will fail at
  #   npm install with a clear "no prebuild found" error — at which
  #   point the right answer is to either pin to a version that has
  #   the prebuild or revert this job to a native arm64 runner.
  $hostArch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
  $env:npm_config_arch = $Arch
  $env:npm_config_target_platform = "win32"

  if ($hostArch -eq $Arch) {
    Write-Host "  (native build: host=$hostArch == target=$Arch)" -ForegroundColor DarkGray
    npm install --omit=dev --build-from-source --no-audit --no-fund
  } else {
    Write-Host "  (cross-compile: host=$hostArch -> target=$Arch — using prebuilds)" -ForegroundColor DarkGray
    npm install --omit=dev --no-audit --no-fund
  }
  if ($LASTEXITCODE -ne 0) { throw "npm install (native deps) failed" }
} finally {
  Pop-Location
  Remove-Item env:npm_config_arch -ErrorAction SilentlyContinue
  Remove-Item env:npm_config_target_platform -ErrorAction SilentlyContinue
}

# Sanity check: did better-sqlite3 actually produce the .node binding?
$nativeBinding = Join-Path $OutNm "better-sqlite3/build/Release/better_sqlite3.node"
if (-not (Test-Path $nativeBinding)) {
  throw "better-sqlite3 native binding missing at $nativeBinding — rebuild failed silently"
}
Write-Host "  ✓ better-sqlite3 binding present: $(((Get-Item $nativeBinding).Length / 1KB)) KB"

# ── Drop test_extension.node ─────────────────────────────────────────
# better-sqlite3's own binding.gyp compiles a sibling target
# `test_extension` alongside the real `better_sqlite3` binding when we
# run `npm install --build-from-source` (x64 native path on CI). It's a
# tiny C++ fixture (~50 KB) used by better-sqlite3's test suite only —
# the agent never loads it. The cross-compile path (arm64, uses
# better-sqlite3's prebuilt tarball) never ships it because prebuilds
# only contain the production binding.
#
# Leaving test_extension.node in the MSI: harmless (we sign it in CI,
# so it'd carry our cert), but it inflates the install footprint and
# tells anyone inspecting the binaries that we're shipping a test
# fixture by mistake — looks sloppy. Drop it here, before WiX picks
# the tree up.
$testExtension = Join-Path $OutNm "better-sqlite3/build/Release/test_extension.node"
if (Test-Path $testExtension) {
  Remove-Item $testExtension -Force
  Write-Host "  → removed test_extension.node (test fixture, never loaded at runtime)"
}

# ── 3. Download bundled node.exe for target arch ─────────────────────
$nodeFilename = "node.exe"
$nodeUrl = "https://nodejs.org/dist/v$NodeVersion/win-$Arch/$nodeFilename"
$cacheDir = Join-Path $RepoRoot "build/.node-cache"
$cachedNode = Join-Path $cacheDir "node-v$NodeVersion-win-$Arch.exe"
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null

if (-not (Test-Path $cachedNode)) {
  Write-Host "→ downloading node.exe ($NodeVersion / win-$Arch)" -ForegroundColor Yellow
  Invoke-WebRequest -Uri $nodeUrl -OutFile $cachedNode -UseBasicParsing

  # SHA256 verification against nodejs.org's official SHASUMS256.txt.
  $sumsUrl = "https://nodejs.org/dist/v$NodeVersion/SHASUMS256.txt"
  $sums = (Invoke-WebRequest -Uri $sumsUrl -UseBasicParsing).Content
  # nodejs.org's SHASUMS256.txt lists files relative to the dist root,
  # so a Windows node.exe shows up as "win-x64/node.exe" not bare
  # "node.exe". Match accordingly.
  $expectedLine = $sums -split "`n" | Where-Object { $_ -match "  win-$Arch/node\.exe$" }
  if (-not $expectedLine) {
    Remove-Item $cachedNode -Force
    throw "Could not find SHA256 entry for win-$Arch/node.exe in $sumsUrl"
  }
  $expectedSha = ($expectedLine -split "\s+")[0]
  $actualSha = (Get-FileHash $cachedNode -Algorithm SHA256).Hash.ToLower()
  if ($expectedSha.ToLower() -ne $actualSha) {
    Remove-Item $cachedNode -Force
    throw "node.exe SHA256 mismatch (expected $expectedSha, got $actualSha)"
  }
  Write-Host "  ✓ node.exe SHA256 verified"
} else {
  Write-Host "→ reusing cached node.exe" -ForegroundColor DarkGray
}

Copy-Item $cachedNode (Join-Path $OutNode "node.exe") -Force

# ── 4. Copy WinSW wrapper for target arch from the repo ─────────────
# WinSW is the service wrapper that launches `node app\dist\index.js`
# as a Windows service. We ship per-arch binaries committed at
# packaging/windows/core-service/TraceniumAgentCore-<arch>.exe.
#
# Why committed instead of downloaded: WinSW v3 hasn't had a stable
# final release yet, and the URLs across their alpha drops have moved
# (some releases have `WinSW-x64.exe`, others have `WinSW-net4.exe`,
# others nothing for that arch). Pinning the binary in the repo
# trades ~17 MB × 2 of repo size for reproducible CI builds that
# don't break when an upstream tag moves.
#
# NOTE on arm64: today we ship the SAME binary as x64 in the arm64
# slot (Windows ARM64 runs x64 EXEs via emulation). Replace
# TraceniumAgentCore-arm64.exe with a native arm64 build whenever
# WinSW publishes a stable v3 with arm64 support.
$winswSrc = Join-Path $RepoRoot "packaging/windows/core-service/TraceniumAgentCore-$Arch.exe"
if (-not (Test-Path $winswSrc)) {
  throw @"
WinSW binary missing: $winswSrc
Commit a Windows service wrapper EXE at that path before re-running.
The arm64 file can be a copy of the x64 file (runs via Windows emulation).
"@
}
$wrapperExe = Join-Path $OutBase "TraceniumAgentCore.exe"
Copy-Item $winswSrc $wrapperExe -Force
Write-Host "→ copied WinSW wrapper from repo ($Arch)" -ForegroundColor Yellow

# ── DO NOT rewrite WinSW's VersionInfo with rcedit ───────────────────
#
# This used to invoke `rcedit-x64.exe TraceniumAgentCore.exe
# --set-version-string CompanyName "CERTUS ITM LLC" ...` so the
# wrapper's embedded VersionInfo would match the signature subject in
# Task Manager. It DID NOT WORK with WinSW v3:
#
#   1. rcedit v2.0.0 exits 0 but produces a PE that the subsequent
#      Trusted Signing step rejects with 0x800700C1
#      (ERROR_BAD_EXE_FORMAT).
#   2. Failures observed on BOTH x64 and arm64 builds in CI runs
#      26041422393 (1.1.17 first attempt) and again after the 1.1.19
#      bump — same exit code, same binary corruption pattern.
#   3. Root cause appears to be WinSW v3's .NET single-file packed
#      layout: rcedit's resource-section rewriter assumes a flatter
#      PE structure than what WinSW ships, so it relocates the
#      optional header in a way SignTool's parser rejects.
#
# Net effect of skipping: TraceniumAgentCore.exe ships with the
# upstream WinSW VersionInfo (CompanyName="CloudBees, Inc.", Product=
# "Windows Service Wrapper"). It's cosmetic — the Authenticode
# signature is still CERTUS ITM LLC, which is what Task Manager's
# "Verified Signer" column and the SmartScreen install dialog show.
# The mismatch only appears in Explorer's Properties → Details tab,
# which is rarely looked at outside of triage.
#
# Cleaner alternatives for the future (each its own follow-up):
#
#   (a) Rebuild WinSW from source with our own AssemblyInfo and skip
#       the binary rewrite entirely. Most idiomatic; requires
#       importing the WinSW source tree and a separate dotnet build.
#   (b) Try `verpatch` (https://github.com/pavel-a/ddverpatch) or
#       ResourceHacker CLI as drop-in replacements. They handle some
#       PE layouts that rcedit doesn't.
#   (c) Migrate off WinSW to a native .NET 8 Worker Service like the
#       one we already use for PrivSvc, which we DO control end-to-
#       end. Pro: kills the WinSW dependency entirely. Con: bigger
#       refactor of how AgentCore is launched as a Windows service.
#
# **Critical**: if you ever try rcedit again, ALWAYS verify the
# emitted binary is still a valid PE by signing it locally with
# signtool before pushing. Don't push to CI on a hunch — every retry
# loop here costs ~10 minutes of Trusted Signing API time.

# ── 5. Copy WinSW XML config from repo ───────────────────────────────
# Single source of truth — same XML on both archs. The %BASE% env var
# WinSW resolves at runtime points to the install dir, so the XML
# doesn't need per-arch paths.
$xmlSrc = Join-Path $RepoRoot "packaging/windows/core-service/TraceniumAgentCore.xml"
if (-not (Test-Path $xmlSrc)) {
  throw "WinSW config missing at $xmlSrc"
}
Copy-Item $xmlSrc (Join-Path $OutBase "TraceniumAgentCore.xml") -Force

# ── Done ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "==== AgentCore staged for $Arch ====" -ForegroundColor Green
Write-Host "  Output: $OutBase"
Get-ChildItem $OutBase -Recurse -File | ForEach-Object {
  $rel = $_.FullName.Substring($OutBase.Length + 1)
  $sz  = [math]::Round($_.Length / 1KB, 1)
  Write-Host ("    {0,12} KB  {1}" -f $sz, $rel)
}
