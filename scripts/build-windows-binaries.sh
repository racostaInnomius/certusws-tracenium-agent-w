#!/bin/sh
# build-windows-binaries.sh
#
# Cross-compile (macOS/Linux → Windows) the two .NET binaries that go
# inside the Windows MSI: PrivSvc (Worker Service) and AgentTray
# (WinForms tray app). Two publishes per run, one per architecture:
#
#   win-x64    → tracenium-agent-installer-x64/binaries/{PrivSvc,AgentTray}/
#   win-arm64  → tracenium-agent-installer/binaries/{PrivSvc,AgentTray}/
#
# Why both arches and not just x64-via-emulation:
#   * arm64 Windows runs x64 EXEs via emulation, BUT x64 Windows does
#     NOT run arm64 EXEs at all. A single x64 publish would still
#     "work" everywhere via emulation, but every arm64 device pays the
#     emulation overhead — measurable for PrivSvc which does crypto
#     and gRPC streaming. Native binaries on each side is the right
#     long-term answer.
#   * Per-arch binaries also let us notarize/sign per-arch later if we
#     ever introduce code signing on the Windows side.
#
# The actual MSI build (`wix build`) still runs on a Windows host —
# see each installer's build.ps1. This script only produces the .exe
# inputs from macOS/Linux. Once it finishes, transfer each installer
# dir to a Windows host and run `pwsh ./build.ps1` to emit the MSI.
#
# Only AgentCore (the Node bundle in <installer>/binaries/AgentCore/)
# is NOT touched by this script — that's a separate flow involving
# esbuild + a bundled Node runtime + better-sqlite3 native rebuild.
#
# Requirements:
#   * .NET 8 SDK installed and `dotnet` in PATH.
#   * Both installer dirs present at <workspace>/tracenium-agent-installer{,-x64}.
#   * Both csproj have <EnableWindowsTargeting>true</EnableWindowsTargeting>
#     (the script verifies this; without it dotnet returns NETSDK1100
#     when crossing from macOS to net8.0-windows).
#
# Usage (callable from anywhere — paths are resolved from this file):
#   /abs/path/to/scripts/build-windows-binaries.sh
#   ./scripts/build-windows-binaries.sh
#   DRY_RUN=1 ./scripts/build-windows-binaries.sh
#   ONLY_X64=1 ./scripts/build-windows-binaries.sh       # skip arm64 build
#   ONLY_ARM64=1 ./scripts/build-windows-binaries.sh     # skip x64 build

set -eu

# -----------------------------------------------------------------------------
# Path resolution — never rely on $PWD
# -----------------------------------------------------------------------------

SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
AGENT_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -f "$AGENT_REPO_DIR/package.json" ]; then
  echo "ERROR: Could not find agent repo root at: $AGENT_REPO_DIR" >&2
  echo "       (package.json missing — is scripts/ still in the right place?)" >&2
  exit 1
fi

PRIVSVC_PROJECT="$AGENT_REPO_DIR/privsvc/windows/Tracenium.PrivSvc.Windows/Tracenium.PrivSvc.Windows.csproj"
AGENTTRAY_PROJECT="$AGENT_REPO_DIR/windows/Tracenium.AgentTray/Tracenium.AgentTray.csproj"

# ── Version resolution ───────────────────────────────────────────────
# Pulled from package.json (single source of truth across all five
# packagers — same pattern as build-linux-binaries.sh + build-macos-pkg.sh).
# Passed into `dotnet publish` as Version + AssemblyVersion + FileVersion
# so the emitted PE binaries' VersionInfo block carries the actual
# release version (1.1.18 etc.) instead of the SDK's default 1.0.0.0.
#
# This shows up in Explorer Properties → Details and in `signtool verify`
# output. Previously this was missing — the .exes shipped with
# FileVersion=1.0.0.0 while the surrounding MSI said 1.1.18, which
# looks sloppy and complicates triage when someone reports "my agent
# is on version X but the .exe says Y".
#
# AssemblyVersion / FileVersion require a 4-part numeric (a.b.c.d), so
# we strip any semver pre-release suffix (e.g. "1.1.18-rc1" → "1.1.18")
# before adding the trailing ".0". The full semver-friendly string still
# rides on `-p:Version=` which accepts any SemVer 2.0 value.
if [ -n "${TRACENIUM_AGENT_VERSION:-}" ]; then
  VERSION="$TRACENIUM_AGENT_VERSION"
else
  VERSION="$(/usr/bin/sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$AGENT_REPO_DIR/package.json" | head -n 1)"
fi
if [ -z "$VERSION" ]; then
  echo "ERROR: Could not resolve version from package.json (or TRACENIUM_AGENT_VERSION env)." >&2
  exit 1
fi
NUMERIC_VERSION="$(printf '%s' "$VERSION" | sed 's/-.*//').0"

# Stage outputs sit inside the agent repo's build/ tree, one subdir
# per (project × arch) combo. From here, build-windows-msi.ps1 (run on
# a Windows host) consumes these EXEs together with the AgentCore
# produced by build-agentcore-windows.ps1 and runs `wix build`.
#
# Pre-consolidation we also COPIED the EXEs into two separate installer
# repos (`tracenium-agent-installer` / `-x64`) — that step is gone now
# that the WiX project lives at $AGENT_REPO_DIR/windows/installer/ and
# the MSI builder reads directly from build/win-binaries/.
STAGE_BASE="$AGENT_REPO_DIR/build/win-binaries"

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

is_truthy() {
  case "$(printf "%s" "$1" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

# -----------------------------------------------------------------------------
# Pre-flight
# -----------------------------------------------------------------------------

if ! command -v dotnet >/dev/null 2>&1; then
  echo "ERROR: dotnet SDK not installed. Install .NET 8 SDK first." >&2
  echo "  macOS: brew install --cask dotnet-sdk" >&2
  exit 1
fi

if [ ! -f "$PRIVSVC_PROJECT" ]; then
  echo "ERROR: PrivSvc csproj not found at: $PRIVSVC_PROJECT" >&2
  exit 1
fi
if [ ! -f "$AGENTTRAY_PROJECT" ]; then
  echo "ERROR: AgentTray csproj not found at: $AGENTTRAY_PROJECT" >&2
  exit 1
fi
if [ ! -d "$AGENT_REPO_DIR/windows/installer" ]; then
  echo "ERROR: WiX installer dir not found at: $AGENT_REPO_DIR/windows/installer" >&2
  echo "       (Phase A consolidation may not have completed — check the repo layout)" >&2
  exit 1
fi

# Sanity-check that EnableWindowsTargeting is set in both csproj.
# Without it, cross-compile from macOS dies with NETSDK1100. We grep
# rather than parse XML to keep the script POSIX-portable.
for proj in "$PRIVSVC_PROJECT" "$AGENTTRAY_PROJECT"; do
  if ! grep -q "<EnableWindowsTargeting>true</EnableWindowsTargeting>" "$proj"; then
    echo "ERROR: $proj is missing <EnableWindowsTargeting>true</EnableWindowsTargeting>." >&2
    echo "       Add it inside <PropertyGroup> or this script will fail with NETSDK1100." >&2
    exit 1
  fi
done

# -----------------------------------------------------------------------------
# Skip flags — let operators run a single arch when iterating fast
# -----------------------------------------------------------------------------

DO_X64=1
DO_ARM64=1
if is_truthy "${ONLY_X64:-}";   then DO_ARM64=0; fi
if is_truthy "${ONLY_ARM64:-}"; then DO_X64=0;   fi
if [ "$DO_X64" = "0" ] && [ "$DO_ARM64" = "0" ]; then
  echo "ERROR: ONLY_X64 and ONLY_ARM64 both set — nothing to build." >&2
  exit 1
fi

# -----------------------------------------------------------------------------
# Publish helper — purges bin/obj before each invocation to prevent
# RID cross-contamination between successive runs. This is a known
# .NET trap when alternating x64/arm64 from the same project.
# -----------------------------------------------------------------------------

clean_and_publish() {
  proj="$1"
  rid="$2"
  outdir="$3"
  selfcontained="$4"

  proj_dir="$(dirname "$proj")"
  rm -rf "$proj_dir/bin" "$proj_dir/obj"
  rm -rf "$outdir"
  mkdir -p "$outdir"

  # Cross-compile detection. The AgentTray csproj has a post-build
  # VerifyTrayIconEmbedded target that calls [Assembly]::LoadFile on
  # the produced DLL — that fails with BadImageFormatException when
  # host arch != target arch (e.g. x64 host publishing win-arm64 DLL).
  # We pass -p:SkipVerifyTrayIcon=true to opt out of the check in
  # those cases. The csproj also auto-detects via
  # NETCoreSdkRuntimeIdentifier as a fallback, but this explicit flag
  # is the primary mechanism (more obvious + safer if MSBuild's
  # RuntimeIdentifier handling changes in future SDK versions).
  #
  # Host arch (running this script):
  #   Linux / macOS                                    → not Windows; csproj target self-skips on OS
  #   Windows x64                                       → host=x64
  #   Windows arm64 (rare for our CI, but valid)        → host=arm64
  host_arch=""
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      # Windows via Git Bash. PROCESSOR_ARCHITECTURE in env distinguishes.
      case "${PROCESSOR_ARCHITECTURE:-}" in
        AMD64) host_arch="x64" ;;
        ARM64) host_arch="arm64" ;;
      esac
      ;;
  esac

  # Map our RID to a comparable arch token.
  target_arch=""
  case "$rid" in
    win-x64)   target_arch="x64" ;;
    win-arm64) target_arch="arm64" ;;
  esac

  skip_verify_args=""
  if [ -n "$host_arch" ] && [ -n "$target_arch" ] && [ "$host_arch" != "$target_arch" ]; then
    # Cross-arch on a Windows host. Skip the post-build verifier.
    skip_verify_args="-p:SkipVerifyTrayIcon=true"
    echo "  (cross-compile $host_arch -> $target_arch on Windows host — skipping VerifyTrayIconEmbedded)"
  fi

  # -p:Version / -p:AssemblyVersion / -p:FileVersion: stamp release
  # version into the emitted PE's VersionInfo block. See VERSION /
  # NUMERIC_VERSION resolution near the top of the script.
  version_args="-p:Version=$VERSION -p:AssemblyVersion=$NUMERIC_VERSION -p:FileVersion=$NUMERIC_VERSION"

  if [ "$selfcontained" = "true" ]; then
    # PrivSvc: explicit self-contained on the CLI overrides the
    # csproj's <SelfContained>false</SelfContained>. We keep that
    # csproj setting for dev-time `dotnet build` (faster, no runtime
    # baked in) but force self-contained for ship binaries so endpoints
    # don't need .NET 8 Desktop Runtime preinstalled.
    dotnet publish "$proj" \
      -c Release \
      -r "$rid" \
      --self-contained true \
      -p:PublishSingleFile=true \
      -p:DebugType=none \
      -p:DebugSymbols=false \
      $version_args \
      $skip_verify_args \
      -o "$outdir"
  else
    # AgentTray: csproj already has SingleFile + SelfContained=true +
    # EnableCompressionInSingleFile. CLI just sets RID + output dir.
    dotnet publish "$proj" \
      -c Release \
      -r "$rid" \
      $version_args \
      $skip_verify_args \
      -o "$outdir"
  fi
}

distribute_exe() {
  src_path="$1"      # absolute path to staged EXE
  arch="$2"          # x64 or arm64
  subdir="$3"        # PrivSvc or AgentTray

  # Output layout (post-consolidation):
  #   build/win-binaries/<arch>/<subdir>/<exe>
  # Consumed downstream by build-windows-msi.ps1, which stages these
  # together with AgentCore/ under the WiX bindpath and runs `wix build`.
  target="$STAGE_BASE/$arch/$subdir"
  mkdir -p "$target"
  filename="$(basename "$src_path")"
  cp -f "$src_path" "$target/$filename"
  size="$(stat -f%z "$target/$filename" 2>/dev/null || wc -c < "$target/$filename" | tr -d ' ')"
  echo "  -> $target/$filename ($size bytes)"

  # Sanity: AgentTray con compresión debe quedar en ~25 MB. Si supera
  # 50 MB, es síntoma de que EnableCompressionInSingleFile fue ignorado
  # (típicamente por IncludeAllContentForSelfExtract=true en el csproj
  # pisándolo). PrivSvc es legítimamente ~70 MB porque empaqueta
  # Microsoft.AspNetCore.App + WindowsServices hosting; no chequeamos
  # tamaño ahí.
  if [ "$subdir" = "AgentTray" ]; then
    size_mb="$((size / 1048576))"
    if [ "$size_mb" -gt 50 ]; then
      echo "" >&2
      echo "  WARNING: AgentTray.exe came out at ${size_mb} MB — expected ~25 MB." >&2
      echo "           EnableCompressionInSingleFile likely ignored. Check the csproj for" >&2
      echo "           <IncludeAllContentForSelfExtract>true</> which silently disables" >&2
      echo "           compression. Build will proceed but the MSI will be 50+ MB larger." >&2
      echo "" >&2
    fi
  fi
}

# -----------------------------------------------------------------------------
# Plan / Dry-run
# -----------------------------------------------------------------------------

echo ""
echo "================================================================"
echo " Build Windows binaries (Mac/Linux → Windows cross-compile)"
echo "================================================================"
echo "  Agent repo          : $AGENT_REPO_DIR"
echo "  PrivSvc project     : $PRIVSVC_PROJECT"
echo "  AgentTray project   : $AGENTTRAY_PROJECT"
echo "  Output (per arch)   : $STAGE_BASE/<arch>/{PrivSvc,AgentTray}/"
echo "----------------------------------------------------------------"
[ "$DO_X64"   = "1" ] && echo "  Will build: win-x64    (native, no emulation overhead)"
[ "$DO_ARM64" = "1" ] && echo "  Will build: win-arm64  (native, no emulation overhead)"
echo "================================================================"

if is_truthy "${DRY_RUN:-}"; then
  echo ""
  echo "DRY_RUN=1 — no actions taken. The script would:"
  if [ "$DO_X64" = "1" ]; then
    echo "  [win-x64]"
    echo "    1. dotnet publish PrivSvc   → $STAGE_BASE/PrivSvc-win-x64/"
    echo "    2. dotnet publish AgentTray → $STAGE_BASE/AgentTray-win-x64/"
    echo "    3. cp .exe → $STAGE_BASE/x64/{PrivSvc,AgentTray}/"
  fi
  if [ "$DO_ARM64" = "1" ]; then
    echo "  [win-arm64]"
    echo "    4. dotnet publish PrivSvc   → $STAGE_BASE/PrivSvc-win-arm64/"
    echo "    5. dotnet publish AgentTray → $STAGE_BASE/AgentTray-win-arm64/"
    echo "    6. cp .exe → $STAGE_BASE/arm64/{PrivSvc,AgentTray}/"
  fi
  exit 0
fi

# -----------------------------------------------------------------------------
# Build · win-x64
# -----------------------------------------------------------------------------

if [ "$DO_X64" = "1" ]; then
  echo ""
  echo "================================================================"
  echo "  win-x64 build"
  echo "================================================================"

  X64_PRIVSVC_STAGE="$STAGE_BASE/PrivSvc-win-x64"
  X64_AGENTTRAY_STAGE="$STAGE_BASE/AgentTray-win-x64"

  echo ""
  echo "[x64 1/4] Publishing PrivSvc..."
  clean_and_publish "$PRIVSVC_PROJECT" "win-x64" "$X64_PRIVSVC_STAGE" "true"
  if [ ! -f "$X64_PRIVSVC_STAGE/Tracenium.PrivSvc.Windows.exe" ]; then
    echo "ERROR: PrivSvc x64 publish produced no EXE in $X64_PRIVSVC_STAGE" >&2
    exit 1
  fi

  echo ""
  echo "[x64 2/4] Publishing AgentTray..."
  clean_and_publish "$AGENTTRAY_PROJECT" "win-x64" "$X64_AGENTTRAY_STAGE" "false"
  if [ ! -f "$X64_AGENTTRAY_STAGE/Tracenium.AgentTray.exe" ]; then
    echo "ERROR: AgentTray x64 publish produced no EXE in $X64_AGENTTRAY_STAGE" >&2
    exit 1
  fi

  echo ""
  echo "[x64 3/4] Staging PrivSvc EXE → build/win-binaries/x64/..."
  distribute_exe "$X64_PRIVSVC_STAGE/Tracenium.PrivSvc.Windows.exe" "x64" "PrivSvc"

  echo ""
  echo "[x64 4/4] Staging AgentTray EXE → build/win-binaries/x64/..."
  distribute_exe "$X64_AGENTTRAY_STAGE/Tracenium.AgentTray.exe" "x64" "AgentTray"
fi

# -----------------------------------------------------------------------------
# Build · win-arm64
# -----------------------------------------------------------------------------

if [ "$DO_ARM64" = "1" ]; then
  echo ""
  echo "================================================================"
  echo "  win-arm64 build"
  echo "================================================================"

  ARM64_PRIVSVC_STAGE="$STAGE_BASE/PrivSvc-win-arm64"
  ARM64_AGENTTRAY_STAGE="$STAGE_BASE/AgentTray-win-arm64"

  echo ""
  echo "[arm64 1/4] Publishing PrivSvc..."
  clean_and_publish "$PRIVSVC_PROJECT" "win-arm64" "$ARM64_PRIVSVC_STAGE" "true"
  if [ ! -f "$ARM64_PRIVSVC_STAGE/Tracenium.PrivSvc.Windows.exe" ]; then
    echo "ERROR: PrivSvc arm64 publish produced no EXE in $ARM64_PRIVSVC_STAGE" >&2
    exit 1
  fi

  echo ""
  echo "[arm64 2/4] Publishing AgentTray..."
  clean_and_publish "$AGENTTRAY_PROJECT" "win-arm64" "$ARM64_AGENTTRAY_STAGE" "false"
  if [ ! -f "$ARM64_AGENTTRAY_STAGE/Tracenium.AgentTray.exe" ]; then
    echo "ERROR: AgentTray arm64 publish produced no EXE in $ARM64_AGENTTRAY_STAGE" >&2
    exit 1
  fi

  echo ""
  echo "[arm64 3/4] Staging PrivSvc EXE → build/win-binaries/arm64/..."
  distribute_exe "$ARM64_PRIVSVC_STAGE/Tracenium.PrivSvc.Windows.exe" "arm64" "PrivSvc"

  echo ""
  echo "[arm64 4/4] Staging AgentTray EXE → build/win-binaries/arm64/..."
  distribute_exe "$ARM64_AGENTTRAY_STAGE/Tracenium.AgentTray.exe" "arm64" "AgentTray"
fi

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------

echo ""
echo "================================================================"
echo " DONE."
echo ""
echo " EXEs staged at:"
[ "$DO_X64"   = "1" ] && echo "   $STAGE_BASE/x64/{PrivSvc,AgentTray}/"
[ "$DO_ARM64" = "1" ] && echo "   $STAGE_BASE/arm64/{PrivSvc,AgentTray}/"
echo ""
echo " Next (on a Windows host):"
echo "   1. pwsh scripts/build-agentcore-windows.ps1 -Arch <x64|arm64>"
echo "   2. pwsh scripts/build-windows-msi.ps1 -Arch <x64|arm64>"
echo " to produce the per-arch MSI under build/win-msi/<arch>/."
echo "================================================================"
