#!/bin/sh
set -eu

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_DIR="$ROOT_DIR/build/macos"
PKG_ROOT="$ROOT_DIR/build/pkg-root"
COMPONENT_OUT="$ROOT_DIR/build/pkg-component"
PKG_OUT="$ROOT_DIR/build/pkg-out"
NPM_CACHE_DIR="$ROOT_DIR/build/.npm-cache"
NODE_GYP_CACHE_DIR="$ROOT_DIR/build/.node-gyp"
SCRIPTS_DIR="$ROOT_DIR/privsvc/macos/pkg-scripts"
DIST_TEMPLATE="$ROOT_DIR/privsvc/macos/distribution/Distribution.xml"
DIST_BUILD="$ROOT_DIR/build/pkg-distribution/Distribution.xml"
RESOURCES_DIR="$ROOT_DIR/privsvc/macos/distribution/resources"
ICON_PNG="$RESOURCES_DIR/tracenium.png"
ICON_ICNS="$RESOURCES_DIR/tracenium.icns"

VERSION="${TRACENIUM_AGENT_VERSION:-1.1.0}"
ARCH="${TRACENIUM_AGENT_ARCH:-arm64}"
IDENTIFIER="${TRACENIUM_PKG_IDENTIFIER:-com.certusws.tracenium.agent}"

build_agent_bundle() {
  mkdir -p "$BUILD_DIR/Agent"

  (
    cd "$ROOT_DIR"
    ./node_modules/.bin/esbuild src/index.ts \
      --bundle \
      --platform=node \
      --format=cjs \
      --target=node24 \
      --external:better-sqlite3 \
      --outfile="$BUILD_DIR/Agent/agent-core.js"
  )

  if ! grep -qF "env/file/registry" "$BUILD_DIR/Agent/agent-core.js"; then
    echo "Generated Agent Core bundle does not include the current enrollment token logic." >&2
    exit 1
  fi
}

build_privsvc_bundle() {
  mkdir -p "$BUILD_DIR/PrivSvc/macos"
  mkdir -p "$BUILD_DIR/PrivSvc/proto"
  mkdir -p "$BUILD_DIR/PrivSvc/assets"

  (
    cd "$ROOT_DIR"
    ./node_modules/.bin/esbuild privsvc/macos/src/index.ts \
      --bundle \
      --platform=node \
      --format=cjs \
      --target=node24 \
      --outfile="$BUILD_DIR/PrivSvc/macos/privsvc.js"
  )

  cp "$ROOT_DIR/proto/controlplane.proto" "$BUILD_DIR/PrivSvc/proto/controlplane.proto"
  cp "$ROOT_DIR/privsvc/windows/Tracenium.PrivSvc.Windows/assets/root-ca.crt" "$BUILD_DIR/PrivSvc/assets/root-ca.crt"

  if ! grep -qF "../proto/controlplane.proto" "$BUILD_DIR/PrivSvc/macos/privsvc.js"; then
    echo "Generated PrivSvc bundle does not include the installed proto path." >&2
    exit 1
  fi

  if [ ! -f "$BUILD_DIR/PrivSvc/assets/root-ca.crt" ]; then
    echo "Missing packaged root CA for PrivSvc." >&2
    exit 1
  fi

  if ! grep -qF "subjectAltName = @alt_names" "$BUILD_DIR/PrivSvc/macos/privsvc.js"; then
    echo "Generated PrivSvc bundle does not include the current CSR generation logic." >&2
    exit 1
  fi
}

rebuild_better_sqlite3() {
  local target_node_version
  target_node_version="$("$BUILD_DIR/Runtime/node" -p 'process.versions.node')"

  mkdir -p "$NPM_CACHE_DIR" "$NODE_GYP_CACHE_DIR"

  (
    cd "$BUILD_DIR/Agent/node_modules/better-sqlite3"
    HOME="$ROOT_DIR/build" \
    npm_config_cache="$NPM_CACHE_DIR" \
    npm_config_devdir="$NODE_GYP_CACHE_DIR" \
    npm_config_target="$target_node_version" \
    npm_config_runtime="node" \
    npm_config_arch="$ARCH" \
    npm_config_platform="darwin" \
    npm_config_build_from_source="true" \
    npm rebuild
  )

  if ! "$BUILD_DIR/Runtime/node" -e "require('$BUILD_DIR/Agent/node_modules/better-sqlite3');" >/dev/null 2>&1; then
    echo "better-sqlite3 rebuild completed but the bundled Node runtime still cannot load it." >&2
    exit 1
  fi
}

if [ ! -x "$BUILD_DIR/Runtime/node" ]; then
  echo "Missing bundled node runtime: $BUILD_DIR/Runtime/node" >&2
  exit 1
fi

build_agent_bundle
build_privsvc_bundle

if [ ! -f "$BUILD_DIR/PrivSvc/macos/privsvc.js" ]; then
  echo "Missing PrivSvc bundle: $BUILD_DIR/PrivSvc/macos/privsvc.js" >&2
  exit 1
fi

if [ ! -d "$BUILD_DIR/Agent/node_modules/better-sqlite3" ]; then
  echo "Missing better-sqlite3 module directory in Agent payload." >&2
  exit 1
fi

if [ ! -f "$BUILD_DIR/Agent/node_modules/better-sqlite3/build/Release/better_sqlite3.node" ]; then
  echo "better-sqlite3 native module missing. Rebuilding for bundled Node runtime..." >&2
  rebuild_better_sqlite3
fi

if ! "$BUILD_DIR/Runtime/node" -e "require('$BUILD_DIR/Agent/node_modules/better-sqlite3');" >/dev/null 2>&1; then
  echo "better-sqlite3 ABI mismatch detected. Rebuilding for bundled Node runtime..." >&2
  rebuild_better_sqlite3
fi

if [ ! -f "$RESOURCES_DIR/tracenium_pgk.png" ]; then
  echo "Missing installer background: $RESOURCES_DIR/tracenium_pgk.png" >&2
  exit 1
fi

if [ ! -f "$ICON_PNG" ]; then
  echo "Missing installer icon source: $ICON_PNG" >&2
  exit 1
fi

rm -rf "$PKG_ROOT" "$COMPONENT_OUT" "$PKG_OUT" "$ROOT_DIR/build/pkg-distribution"
mkdir -p "$PKG_ROOT/Library/Application Support/Tracenium"
mkdir -p "$PKG_ROOT/Library/LaunchDaemons"
mkdir -p "$COMPONENT_OUT"
mkdir -p "$PKG_OUT"
mkdir -p "$(dirname "$DIST_BUILD")"

rsync -a --exclude ".DS_Store" "$BUILD_DIR/Runtime/" "$PKG_ROOT/Library/Application Support/Tracenium/Runtime/"
rsync -a --exclude ".DS_Store" "$BUILD_DIR/PrivSvc/" "$PKG_ROOT/Library/Application Support/Tracenium/PrivSvc/"
rsync -a --exclude ".DS_Store" "$BUILD_DIR/Agent/" "$PKG_ROOT/Library/Application Support/Tracenium/Agent/"
rsync -a --exclude ".DS_Store" "$BUILD_DIR/LaunchDaemons/" "$PKG_ROOT/Library/LaunchDaemons/"

rm -f "$PKG_ROOT/Library/Application Support/Tracenium/Agent/.env"
find "$PKG_ROOT" -name ".DS_Store" -delete

chmod +x "$SCRIPTS_DIR/preinstall" "$SCRIPTS_DIR/postinstall"

ICONSET_DIR="$ROOT_DIR/build/pkg-icon.iconset"
rm -rf "$ICONSET_DIR"
mkdir -p "$ICONSET_DIR"
sips -z 16 16 "$ICON_PNG" --out "$ICONSET_DIR/icon_16x16.png" >/dev/null
sips -z 32 32 "$ICON_PNG" --out "$ICONSET_DIR/icon_16x16@2x.png" >/dev/null
sips -z 32 32 "$ICON_PNG" --out "$ICONSET_DIR/icon_32x32.png" >/dev/null
sips -z 64 64 "$ICON_PNG" --out "$ICONSET_DIR/icon_32x32@2x.png" >/dev/null
sips -z 128 128 "$ICON_PNG" --out "$ICONSET_DIR/icon_128x128.png" >/dev/null
sips -z 256 256 "$ICON_PNG" --out "$ICONSET_DIR/icon_128x128@2x.png" >/dev/null
sips -z 256 256 "$ICON_PNG" --out "$ICONSET_DIR/icon_256x256.png" >/dev/null
sips -z 512 512 "$ICON_PNG" --out "$ICONSET_DIR/icon_256x256@2x.png" >/dev/null
sips -z 512 512 "$ICON_PNG" --out "$ICONSET_DIR/icon_512x512.png" >/dev/null
sips -z 1024 1024 "$ICON_PNG" --out "$ICONSET_DIR/icon_512x512@2x.png" >/dev/null
if ! iconutil --convert icns "$ICONSET_DIR" --output "$ICON_ICNS" 2>/dev/null; then
  ICONSET_DIR="$ICONSET_DIR" ICON_ICNS="$ICON_ICNS" python3 - <<'PY'
from pathlib import Path
import os
import struct

iconset = Path(os.environ["ICONSET_DIR"])
out = Path(os.environ["ICON_ICNS"])
mapping = [
    ("icp4", "icon_16x16.png"),
    ("icp5", "icon_32x32.png"),
    ("icp6", "icon_32x32@2x.png"),
    ("ic07", "icon_128x128.png"),
    ("ic08", "icon_256x256.png"),
    ("ic09", "icon_512x512.png"),
    ("ic10", "icon_512x512@2x.png"),
]
chunks = []
for kind, name in mapping:
    data = (iconset / name).read_bytes()
    chunks.append(kind.encode("ascii") + struct.pack(">I", len(data) + 8) + data)
body = b"".join(chunks)
out.write_bytes(b"icns" + struct.pack(">I", len(body) + 8) + body)
PY
fi

sed \
  -e "s/@TRACENIUM_PKG_IDENTIFIER@/$IDENTIFIER/g" \
  -e "s/@TRACENIUM_AGENT_VERSION@/$VERSION/g" \
  "$DIST_TEMPLATE" > "$DIST_BUILD"

COMPONENT_PKG="$COMPONENT_OUT/TraceniumAgentComponent.pkg"
FINAL_PKG="$PKG_OUT/Tracenium-Agent-$VERSION-$ARCH.pkg"

pkgbuild \
  --root "$PKG_ROOT" \
  --scripts "$SCRIPTS_DIR" \
  --identifier "$IDENTIFIER" \
  --version "$VERSION" \
  --install-location "/" \
  "$COMPONENT_PKG"

productbuild \
  --distribution "$DIST_BUILD" \
  --resources "$RESOURCES_DIR" \
  --package-path "$COMPONENT_OUT" \
  "$FINAL_PKG"

ICON_RSRC="$ROOT_DIR/build/pkg-icon.rsrc"
ICON_REZ="$ROOT_DIR/build/pkg-icon.r"
printf "read 'icns' (-16455) \"%s\";\n" "$ICON_ICNS" > "$ICON_REZ"
if Rez -append "$ICON_REZ" -o "$FINAL_PKG" 2>/dev/null; then
  SetFile -a C "$FINAL_PKG" 2>/dev/null || true
fi

# -----------------------------------------------------------------------------
# Post-build: sha256 digest + optional upload to Azure Blob Storage
# -----------------------------------------------------------------------------
# The backend metadata endpoint (/api/v1/binaries/agent/metadata) reads the
# blob's `sha256` metadata. The macOS agent validates the downloaded pkg
# against that hash before running `installer`, so the metadata MUST match.
#
# Upload is opt-in to avoid accidental publishes from local dev runs. Enable
# with any of: TRACENIUM_UPLOAD=1 | true | yes
#
# Override-able env vars (defaults sensible for production):
#   TRACENIUM_BLOB_ACCOUNT      (default: cwsinveid)
#   TRACENIUM_BLOB_CONTAINER    (default: tracenium)
#   TRACENIUM_BLOB_PLATFORM     (default: macos)
#   TRACENIUM_BLOB_PATH         (default: agents/<platform>/<arch>/<version>/<file>)
#   TRACENIUM_AZ_AUTH_MODE      (default: key)  — passed to `az storage blob upload`
# -----------------------------------------------------------------------------

FINAL_PKG_SHA256="$(shasum -a 256 "$FINAL_PKG" | awk '{print $1}')"
FINAL_PKG_SIZE_BYTES="$(stat -f%z "$FINAL_PKG" 2>/dev/null || wc -c < "$FINAL_PKG" | tr -d ' ')"

echo ""
echo "================================ BUILD DONE ================================"
echo "  pkg    : $FINAL_PKG"
echo "  size   : $FINAL_PKG_SIZE_BYTES bytes"
echo "  sha256 : $FINAL_PKG_SHA256"
echo "  version: $VERSION"
echo "  arch   : $ARCH"
echo "============================================================================"

upload_flag="$(printf "%s" "${TRACENIUM_UPLOAD:-}" | tr '[:upper:]' '[:lower:]')"
if [ "$upload_flag" = "1" ] || [ "$upload_flag" = "true" ] || [ "$upload_flag" = "yes" ]; then
  BLOB_ACCOUNT="${TRACENIUM_BLOB_ACCOUNT:-cwsinveid}"
  BLOB_CONTAINER="${TRACENIUM_BLOB_CONTAINER:-tracenium}"
  BLOB_PLATFORM="${TRACENIUM_BLOB_PLATFORM:-macos}"
  BLOB_AUTH_MODE="${TRACENIUM_AZ_AUTH_MODE:-key}"
  BLOB_PATH="${TRACENIUM_BLOB_PATH:-agents/$BLOB_PLATFORM/$ARCH/$VERSION/$(basename "$FINAL_PKG")}"

  if ! command -v az >/dev/null 2>&1; then
    echo "TRACENIUM_UPLOAD is set but 'az' CLI is not installed. Install Azure CLI first." >&2
    exit 1
  fi

  echo ""
  echo "================================ UPLOADING ================================="
  echo "  account   : $BLOB_ACCOUNT"
  echo "  container : $BLOB_CONTAINER"
  echo "  blob path : $BLOB_PATH"
  echo "  auth mode : $BLOB_AUTH_MODE"
  echo "============================================================================"

  az storage blob upload \
    --account-name "$BLOB_ACCOUNT" \
    --container-name "$BLOB_CONTAINER" \
    --name "$BLOB_PATH" \
    --file "$FINAL_PKG" \
    --metadata "sha256=$FINAL_PKG_SHA256" \
    --auth-mode "$BLOB_AUTH_MODE" \
    --overwrite

  echo ""
  echo "================================ UPLOADED =================================="
  echo "Verify backend metadata picked up the new version:"
  echo "  curl -sS 'https://api.tracenium.com/api/v1/binaries/agent/metadata?platform=$BLOB_PLATFORM&arch=$ARCH' | python3 -m json.tool"
  echo "============================================================================"
else
  echo ""
  echo "Skipping blob upload (set TRACENIUM_UPLOAD=1 to enable)."
fi

echo "$FINAL_PKG"
