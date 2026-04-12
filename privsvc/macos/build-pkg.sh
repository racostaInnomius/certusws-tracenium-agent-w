#!/bin/sh
set -eu

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_DIR="$ROOT_DIR/build/macos"
PKG_ROOT="$ROOT_DIR/build/pkg-root"
COMPONENT_OUT="$ROOT_DIR/build/pkg-component"
PKG_OUT="$ROOT_DIR/build/pkg-out"
SCRIPTS_DIR="$ROOT_DIR/privsvc/macos/pkg-scripts"
DIST_TEMPLATE="$ROOT_DIR/privsvc/macos/distribution/Distribution.xml"
DIST_BUILD="$ROOT_DIR/build/pkg-distribution/Distribution.xml"
RESOURCES_DIR="$ROOT_DIR/privsvc/macos/distribution/resources"
ICON_PNG="$RESOURCES_DIR/tracenium.png"
ICON_ICNS="$RESOURCES_DIR/tracenium.icns"

VERSION="${TRACENIUM_AGENT_VERSION:-1.0.87}"
ARCH="${TRACENIUM_AGENT_ARCH:-arm64}"
IDENTIFIER="${TRACENIUM_PKG_IDENTIFIER:-com.certusws.tracenium.agent}"

if [ ! -x "$BUILD_DIR/Runtime/node" ]; then
  echo "Missing bundled node runtime: $BUILD_DIR/Runtime/node" >&2
  exit 1
fi

if [ ! -f "$BUILD_DIR/Agent/agent-core.js" ]; then
  echo "Missing Agent Core bundle: $BUILD_DIR/Agent/agent-core.js" >&2
  exit 1
fi

if [ ! -f "$BUILD_DIR/PrivSvc/macos/privsvc.js" ]; then
  echo "Missing PrivSvc bundle: $BUILD_DIR/PrivSvc/macos/privsvc.js" >&2
  exit 1
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

echo "$FINAL_PKG"
