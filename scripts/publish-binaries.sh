#!/bin/sh
# publish-binaries.sh
#
# Upload all five agent binaries (macOS arm64 pkg, Windows arm64 MSI,
# Windows x64 MSI, Linux amd64 .deb, Linux amd64 .rpm) to Azure Blob
# Storage in a single run. Designed for the "I just finished
# rebuilding everything, publish it" flow — the per-platform scripts
# still exist for partial publishes, but this wrapper is the usual
# path when releasing a version.
#
# Why a single script?
#   * Version drift is the #1 cause of failed auto-updates. Driving
#     the version from one place (this repo's package.json) and using
#     it for all three blob paths guarantees the triple stays in sync.
#   * The metadata endpoint reads `sha256` blob metadata per file;
#     each upload is independent but must finish successfully for the
#     release to be considered shipped. Running them together + a
#     final verification keeps the release atomic from the operator's
#     point of view.
#   * DRY_RUN=1 prints the plan for all three. Safe to inspect before
#     going live.
#
# Assumes all binaries are already built on disk:
#
#   macOS pkg            →  build/pkg-out/Tracenium-Agent-<version>-arm64.pkg
#   Windows arm64 MSI    →  build/win-msi/arm64/Tracenium-Agent-<version>-arm64.msi
#   Windows x64   MSI    →  build/win-msi/x64/Tracenium-Agent-<version>-x64.msi
#   Linux  amd64 .deb    →  build/linux/pkg-out/Tracenium-Agent-<version>-x64.deb
#   Linux  amd64 .rpm    →  build/linux/pkg-out/Tracenium-Agent-<version>-x64.rpm
#
# If any of the binaries is missing, the script aborts BEFORE
# uploading anything — we don't want a partial release where the
# backend metadata endpoint points at some-of-N versions.
#
# Usage:
#   ./scripts/publish-binaries.sh                    # version from package.json
#   TRACENIUM_AGENT_VERSION=1.1.2 ./scripts/publish-binaries.sh
#   DRY_RUN=1 ./scripts/publish-binaries.sh          # plan only, no upload
#   SKIP_MACOS=1 ./scripts/publish-binaries.sh       # skip macOS upload
#   SKIP_WIN_ARM64=1 ./scripts/publish-binaries.sh   # skip Windows arm64
#   SKIP_WIN_X64=1 ./scripts/publish-binaries.sh     # skip Windows x64
#   SKIP_LINUX_DEB=1 ./scripts/publish-binaries.sh   # skip Linux .deb
#   SKIP_LINUX_RPM=1 ./scripts/publish-binaries.sh   # skip Linux .rpm
#
# Overridable env vars (defaults for production):
#   TRACENIUM_AGENT_VERSION    (default: from package.json)
#   TRACENIUM_BLOB_ACCOUNT     (default: cwsinveid)
#   TRACENIUM_BLOB_CONTAINER   (default: tracenium)
#   TRACENIUM_AZ_AUTH_MODE     (default: key)

set -eu

# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------
# This script lives at <workspace>/scripts/. Its parent is the
# workspace root, and the agent repo + the two installer repos all
# live there as sibling directories. Resolved here from the script's
# own location so the script is safe to run from any cwd.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -f "$AGENT_REPO_DIR/package.json" ]; then
  echo "ERROR: Could not find agent repo root at: $AGENT_REPO_DIR" >&2
  echo "       (package.json missing — is scripts/ still in the right place?)" >&2
  exit 1
fi

# -----------------------------------------------------------------------------
# Version resolution
# -----------------------------------------------------------------------------
# Single source of truth: the agent repo's package.json. An explicit
# TRACENIUM_AGENT_VERSION env var overrides it (useful for testing a
# specific version string without editing package.json).

if [ -n "${TRACENIUM_AGENT_VERSION:-}" ]; then
  VERSION="$TRACENIUM_AGENT_VERSION"
else
  VERSION="$(/usr/bin/sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$AGENT_REPO_DIR/package.json" | head -n 1)"
fi

if [ -z "$VERSION" ]; then
  echo "Could not resolve version from package.json and TRACENIUM_AGENT_VERSION not set." >&2
  exit 1
fi

BLOB_ACCOUNT="${TRACENIUM_BLOB_ACCOUNT:-cwsinveid}"
BLOB_CONTAINER="${TRACENIUM_BLOB_CONTAINER:-tracenium}"
BLOB_AUTH_MODE="${TRACENIUM_AZ_AUTH_MODE:-key}"

# -----------------------------------------------------------------------------
# Binary locations
# -----------------------------------------------------------------------------

MACOS_PKG="$AGENT_REPO_DIR/build/pkg-out/Tracenium-Agent-$VERSION-arm64.pkg"
# After May 2026 consolidation, the MSI builders write to:
#   build/win-msi/<arch>/Tracenium-Agent-<version>-<arch>.msi
# (previously: $WORKSPACE_DIR/tracenium-agent-installer{,-x64}/Tracenium-Agent.msi).
# Filename now carries version + arch — matches macOS .pkg + Linux .deb/.rpm
# naming and removes the "which arch is this MSI?" ambiguity from before.
WIN_ARM64_MSI="$AGENT_REPO_DIR/build/win-msi/arm64/Tracenium-Agent-$VERSION-arm64.msi"
WIN_X64_MSI="$AGENT_REPO_DIR/build/win-msi/x64/Tracenium-Agent-$VERSION-x64.msi"
# Linux .deb and .rpm — produced by build-linux-binaries.sh inside the
# agent repo's build dir. Names follow the cross-platform convention
# `Tracenium-Agent-<version>-<arch>.<ext>` (Node-style arch token) —
# same shape as the macOS .pkg and Windows .msi. The build script
# renames nfpm's native output (`tracenium-agent_<v>_amd64.deb` etc.)
# to this convention at the end of the build, so the on-disk filename
# is identical to the blob path's filename component.
LINUX_DEB="$AGENT_REPO_DIR/build/linux/pkg-out/Tracenium-Agent-${VERSION}-x64.deb"
LINUX_RPM="$AGENT_REPO_DIR/build/linux/pkg-out/Tracenium-Agent-${VERSION}-x64.rpm"

# -----------------------------------------------------------------------------
# Skip flags (1/true/yes = skip)
# -----------------------------------------------------------------------------

is_truthy() {
  case "$(printf "%s" "$1" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

SKIP_MAC=0
SKIP_ARM64=0
SKIP_X64=0
SKIP_DEB=0
SKIP_RPM=0
if is_truthy "${SKIP_MACOS:-}";     then SKIP_MAC=1;   fi
if is_truthy "${SKIP_WIN_ARM64:-}"; then SKIP_ARM64=1; fi
if is_truthy "${SKIP_WIN_X64:-}";   then SKIP_X64=1;   fi
if is_truthy "${SKIP_LINUX_DEB:-}"; then SKIP_DEB=1;   fi
if is_truthy "${SKIP_LINUX_RPM:-}"; then SKIP_RPM=1;   fi

# -----------------------------------------------------------------------------
# Pre-flight checks (fail fast, before any upload)
# -----------------------------------------------------------------------------

ERRORS=0
check_file() {
  # $1 = label, $2 = path, $3 = skip flag (1 = skip the check)
  if [ "$3" = "1" ]; then
    return 0
  fi
  if [ ! -f "$2" ]; then
    echo "MISSING: $1 not found at $2" >&2
    ERRORS=$((ERRORS + 1))
  fi
}

check_file "macOS pkg"         "$MACOS_PKG"     "$SKIP_MAC"
check_file "Windows arm64 MSI" "$WIN_ARM64_MSI" "$SKIP_ARM64"
check_file "Windows x64 MSI"   "$WIN_X64_MSI"   "$SKIP_X64"
check_file "Linux amd64 deb"   "$LINUX_DEB"     "$SKIP_DEB"
check_file "Linux amd64 rpm"   "$LINUX_RPM"     "$SKIP_RPM"

if [ "$ERRORS" -gt 0 ]; then
  echo ""
  echo "Build the missing binaries first, or set the corresponding SKIP_* env var." >&2
  exit 1
fi

if ! command -v az >/dev/null 2>&1; then
  echo "'az' CLI is not installed. Install Azure CLI first." >&2
  exit 1
fi

# -----------------------------------------------------------------------------
# Compute sha256 + size for every binary we're going to touch.
# -----------------------------------------------------------------------------

sha_of() {
  shasum -a 256 "$1" | awk '{print $1}'
}

size_of() {
  stat -f%z "$1" 2>/dev/null || wc -c < "$1" | tr -d ' '
}

if [ "$SKIP_MAC" = "0" ]; then
  MAC_SHA="$(sha_of "$MACOS_PKG")"
  MAC_SIZE="$(size_of "$MACOS_PKG")"
  MAC_BLOB="agents/macos/arm64/$VERSION/Tracenium-Agent-$VERSION-arm64.pkg"
fi
if [ "$SKIP_ARM64" = "0" ]; then
  ARM_SHA="$(sha_of "$WIN_ARM64_MSI")"
  ARM_SIZE="$(size_of "$WIN_ARM64_MSI")"
  ARM_BLOB="agents/windows/arm64/$VERSION/Tracenium-Agent-$VERSION-arm64.msi"
fi
if [ "$SKIP_X64" = "0" ]; then
  X64_SHA="$(sha_of "$WIN_X64_MSI")"
  X64_SIZE="$(size_of "$WIN_X64_MSI")"
  X64_BLOB="agents/windows/x64/$VERSION/Tracenium-Agent-$VERSION-x64.msi"
fi
# Linux blob paths follow the same versioned + arch-specific naming
# convention as Windows MSIs and macOS PKGs:
#   agents/<platform>/<arch>/<version>/Tracenium-Agent-<version>-<arch>.<ext>
#
# build-linux-binaries.sh renames nfpm's native output to match this
# convention on disk, so the local filename and the blob filename are
# identical. Arch token is Node-style (x64/arm64) end-to-end, even
# though the .deb/.rpm internal metadata uses amd64/x86_64 — that's
# inside the control file and irrelevant to apt/dpkg/dnf install.
if [ "$SKIP_DEB" = "0" ]; then
  DEB_SHA="$(sha_of "$LINUX_DEB")"
  DEB_SIZE="$(size_of "$LINUX_DEB")"
  DEB_BLOB="agents/linux/x64/$VERSION/Tracenium-Agent-$VERSION-x64.deb"
fi
if [ "$SKIP_RPM" = "0" ]; then
  RPM_SHA="$(sha_of "$LINUX_RPM")"
  RPM_SIZE="$(size_of "$LINUX_RPM")"
  RPM_BLOB="agents/linux/x64/$VERSION/Tracenium-Agent-$VERSION-x64.rpm"
fi

# -----------------------------------------------------------------------------
# Plan summary
# -----------------------------------------------------------------------------

echo ""
echo "============================== PUBLISH PLAN ================================="
echo "  version   : $VERSION"
echo "  account   : $BLOB_ACCOUNT"
echo "  container : $BLOB_CONTAINER"
echo "  auth mode : $BLOB_AUTH_MODE"
echo "-----------------------------------------------------------------------------"
if [ "$SKIP_MAC" = "0" ]; then
  echo "  [macOS arm64]   $MAC_SIZE bytes  sha256=$MAC_SHA"
  echo "                  → $MAC_BLOB"
else
  echo "  [macOS arm64]   SKIPPED"
fi
if [ "$SKIP_ARM64" = "0" ]; then
  echo "  [Windows arm64] $ARM_SIZE bytes  sha256=$ARM_SHA"
  echo "                  → $ARM_BLOB"
else
  echo "  [Windows arm64] SKIPPED"
fi
if [ "$SKIP_X64" = "0" ]; then
  echo "  [Windows x64]   $X64_SIZE bytes  sha256=$X64_SHA"
  echo "                  → $X64_BLOB"
else
  echo "  [Windows x64]   SKIPPED"
fi
if [ "$SKIP_DEB" = "0" ]; then
  echo "  [Linux deb]     $DEB_SIZE bytes  sha256=$DEB_SHA"
  echo "                  → $DEB_BLOB"
else
  echo "  [Linux deb]     SKIPPED"
fi
if [ "$SKIP_RPM" = "0" ]; then
  echo "  [Linux rpm]     $RPM_SIZE bytes  sha256=$RPM_SHA"
  echo "                  → $RPM_BLOB"
else
  echo "  [Linux rpm]     SKIPPED"
fi
echo "============================================================================="

if is_truthy "${DRY_RUN:-}"; then
  echo ""
  echo "DRY_RUN=1 set — no uploads will run."
  exit 0
fi

# -----------------------------------------------------------------------------
# Uploads. Each is independent; a failure in one doesn't abort the
# others (we collect errors and exit non-zero at the end). Rationale:
# if macOS uploads cleanly but Windows x64 hits a transient 503, we'd
# rather have the 2 good ones visible to the metadata endpoint and
# retry the third, than roll back the whole release.
# -----------------------------------------------------------------------------

UPLOAD_ERRORS=0
upload_one() {
  # $1 = label, $2 = blob path, $3 = file, $4 = sha256, $5 = content-type
  #
  # Why we explicitly set --content-type:
  #   `az storage blob upload` defaults to a guess driven by the file
  #   extension via Python's mimetypes module. For `.msi`, that lookup
  #   used to resolve to `application/x-msdownload` — the historical
  #   MIME type for Windows EXE binaries. Chrome and Edge then MIME-
  #   sniffed the download as "executable", overrode the URL filename,
  #   and saved the artifact as `.exe`. The operator opening the
  #   "MSI" got an unrunnable file (preprod incident, May 2026).
  #
  #   The backend now also forces `rsct=` on the SAS URL it generates,
  #   so the browser path through the UI is fixed regardless of how
  #   blobs were uploaded. But anyone hitting the blob directly (curl
  #   probes, ad-hoc scripts, the agent's auto-update fetch) still
  #   sees the raw blob's Content-Type. Setting it correctly here
  #   keeps the two-layer story consistent and avoids future MIME-
  #   sniffing surprises if a different client comes along.
  #
  #   Map (kept in sync with backend `extToMime` in binaries.service.ts):
  #     .msi → application/x-msi
  #     .pkg → application/octet-stream  (macOS doesn't sniff anyway)
  #     .deb → application/vnd.debian.binary-package
  #     .rpm → application/x-rpm
  echo ""
  echo "--- Uploading $1 -----------------------------------------------------------"
  if az storage blob upload \
      --account-name "$BLOB_ACCOUNT" \
      --container-name "$BLOB_CONTAINER" \
      --name "$2" \
      --file "$3" \
      --metadata "sha256=$4" \
      --content-type "$5" \
      --auth-mode "$BLOB_AUTH_MODE" \
      --overwrite; then
    echo "    OK $1"
  else
    echo "    FAILED $1" >&2
    UPLOAD_ERRORS=$((UPLOAD_ERRORS + 1))
  fi
}

if [ "$SKIP_MAC" = "0" ]; then
  upload_one "macOS arm64 pkg" "$MAC_BLOB" "$MACOS_PKG" "$MAC_SHA" "application/octet-stream"
fi
if [ "$SKIP_ARM64" = "0" ]; then
  upload_one "Windows arm64 MSI" "$ARM_BLOB" "$WIN_ARM64_MSI" "$ARM_SHA" "application/x-msi"
fi
if [ "$SKIP_X64" = "0" ]; then
  upload_one "Windows x64 MSI" "$X64_BLOB" "$WIN_X64_MSI" "$X64_SHA" "application/x-msi"
fi
if [ "$SKIP_DEB" = "0" ]; then
  upload_one "Linux amd64 deb" "$DEB_BLOB" "$LINUX_DEB" "$DEB_SHA" "application/vnd.debian.binary-package"
fi
if [ "$SKIP_RPM" = "0" ]; then
  upload_one "Linux amd64 rpm" "$RPM_BLOB" "$LINUX_RPM" "$RPM_SHA" "application/x-rpm"
fi

echo ""
echo "============================== PUBLISH DONE ================================="
if [ "$UPLOAD_ERRORS" -gt 0 ]; then
  echo "  $UPLOAD_ERRORS upload(s) failed. See log above." >&2
  echo "============================================================================="
  exit 1
fi

echo "  Verify the backend picked up the release:"
echo "    curl -sS 'https://api.tracenium.com/api/v1/binaries/agent/metadata?platform=macos&arch=arm64'   | python3 -m json.tool"
echo "    curl -sS 'https://api.tracenium.com/api/v1/binaries/agent/metadata?platform=windows&arch=arm64' | python3 -m json.tool"
echo "    curl -sS 'https://api.tracenium.com/api/v1/binaries/agent/metadata?platform=windows&arch=x64'   | python3 -m json.tool"
echo "    curl -sS 'https://api.tracenium.com/api/v1/binaries/agent/metadata?platform=linux&arch=x64'     | python3 -m json.tool"
echo "============================================================================="
