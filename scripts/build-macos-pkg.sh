#!/bin/sh
# build-macos-pkg.sh
#
# Build the macOS .pkg installer for the Tracenium Agent.
#
# Lives in <workspace>/scripts/ alongside build-windows-binaries.sh
# and publish-binaries.sh so all release tooling sits in one place.
# The original location was <agent-repo>/privsvc/macos/build-pkg.sh.
#
# All internal paths are resolved relative to the agent repo (located
# via $WORKSPACE_DIR), so the script is safe to run from any cwd.
# Internally ROOT_DIR is set to the agent repo so every existing path
# expression below stays unchanged.
#
# Usage (callable from anywhere):
#   /abs/path/to/scripts/build-macos-pkg.sh
#   ./scripts/build-macos-pkg.sh
#   TRACENIUM_AGENT_VERSION=1.1.5 ./scripts/build-macos-pkg.sh
#   TRACENIUM_UPLOAD=1 TRACENIUM_AGENT_VERSION=1.1.5 ./scripts/build-macos-pkg.sh
#   TRACENIUM_CODESIGN_IDENTITY="Developer ID Application: …" ./scripts/build-macos-pkg.sh

set -eu

# Resolve the agent repo from this script's location. After the
# May 2026 consolidation, scripts/ lives INSIDE the agent repo.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -f "$ROOT_DIR/package.json" ]; then
  echo "ERROR: Could not find agent repo root at: $ROOT_DIR" >&2
  echo "       (package.json missing — is scripts/ still in the right place?)" >&2
  exit 1
fi

# NODE_VERSION resolution: env override → .nodeversion → fallback.
if [ -n "${TRACENIUM_NODE_VERSION:-}" ]; then
  NODE_VERSION="$TRACENIUM_NODE_VERSION"
elif [ -f "$ROOT_DIR/.nodeversion" ]; then
  NODE_VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/.nodeversion")"
else
  # Hardcoded fallback — only used if .nodeversion is missing. MUST match
  # the .nodeversion contents to avoid version drift. Currently 22.22.3
  # (Jod LTS); see build-linux-binaries.sh for the rationale on why we
  # downgraded from 24 LTS.
  NODE_VERSION="22.22.3"
fi

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
STATUS_ICON_PNG="$ROOT_DIR/Tracenium_tryicon.png"
STATUS_APP_DIR="$ROOT_DIR/macos/TraceniumAgentStatus"
# ⚠️ El icono de la APP no es el mismo PNG que el de la barra de menús.
#
# Tracenium_tryicon.png es un glifo blanco puro con la forma en el alpha: eso es
# justo lo que necesita el menubar (se pinta como template y se adapta a la
# barra), y justo lo que NO sirve como icono de aplicación — macOS lo compone
# sobre su fondo gris claro y en Ajustes → Privacidad y seguridad → Localización
# el icono blanco desaparece.
#
# appicon-source.png es el mismo glifo sobre el fondo del portal, rgb(63,66,78).
# Se genera con scripts/make-macos-appicon.swift y se commitea como asset.
STATUS_APPICON_PNG="$STATUS_APP_DIR/Resources/appicon-source.png"
STATUS_APP_INFO_TEMPLATE="$STATUS_APP_DIR/Resources/Info.plist"
STATUS_APP_BUILD_DIR="$BUILD_DIR/AgentStatus"
STATUS_APP_BUNDLE_NAME="Tracenium Agent Status.app"
STATUS_APP_BUNDLE_DIR="$STATUS_APP_BUILD_DIR/$STATUS_APP_BUNDLE_NAME"
STATUS_APP_ICONSET_DIR="$BUILD_DIR/AgentStatus/icon.iconset"
STATUS_APP_ICON_ICNS="$STATUS_APP_BUILD_DIR/TraceniumAgentStatus.icns"

# VERSION resolution:
#   1) Si TRACENIUM_AGENT_VERSION está exportada → la usa (override
#      explícito, útil para builds de QA con sufijos tipo "1.1.5-rc1").
#   2) Si no, lee `version` del package.json del agent repo. Esa es
#      la single source of truth — esbuild la inlinea en agent-core.js
#      via `import pkg from '../../package.json'`, y el .pkg que
#      generamos debe llevar el mismo string en el filename y en el
#      uploaded blob path para que el metadata endpoint y el agent
#      self-report estén en sync.
#
# Antes había un fallback hardcoded "1.1.2" que quedaba stale entre
# releases — si alguien corría el script sin exportar la env var, se
# producía un .pkg con filename "1.1.2" pero bundle "1.1.x" actual.
# Mismatch peligroso en uploads + auto-update.
if [ -n "${TRACENIUM_AGENT_VERSION:-}" ]; then
  VERSION="$TRACENIUM_AGENT_VERSION"
else
  VERSION="$(/usr/bin/sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$ROOT_DIR/package.json" | head -n 1)"
  if [ -z "$VERSION" ]; then
    echo "ERROR: Could not resolve version — package.json missing or malformed at $ROOT_DIR/package.json" >&2
    echo "       Pass TRACENIUM_AGENT_VERSION=x.y.z explicitly to override." >&2
    exit 1
  fi
fi
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
      --external:node-pty \
      --external:node-datachannel \
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

build_screencap_helper() {
  # RCP M3.S1 — compile + sign the screen-capture helper that PrivSvc
  # spawns into the console user's GUI session (via launchctl asuser).
  # Vive junto a privsvc.js, que es donde lo busca el orquestador.
  #
  # ⚠️ La firma estable NO existe para que un perfil PPPC conceda Grabación de
  # Pantalla: Apple no lo permite, el servicio es deny-only en PPPC. Sirve para
  # que la concesión que hace UNA PERSONA sobreviva a las actualizaciones del
  # agente — si la identidad cambiara en cada build, el usuario tendría que
  # volver a aprobar en cada versión.
  # El helper viaja como BUNDLE .app, no como ejecutable suelto. Dos motivos,
  # los dos medidos en campo:
  #
  #   1. TCC. Un ejecutable Unix suelto tiene problemas conocidos para
  #      aparecer en la lista de Grabación de Pantalla (hay regresión abierta
  #      en macOS 26.1), y el selector de Ajustes solo deja escoger
  #      aplicaciones — así que ni siquiera se podía autorizar a mano.
  #   2. Es una persona quien aprueba. En el diálogo y en la lista aparece el
  #      nombre del bundle, así que tiene que ser algo que el usuario final
  #      reconozca, no "tracenium-screencap".
  local src="$ROOT_DIR/privsvc/macos/helpers/screencap/main.swift"
  local app_dir="$BUILD_DIR/PrivSvc/macos/Tracenium Screen Helper.app"
  local out="$app_dir/Contents/MacOS/tracenium-screencap"

  if [ ! -f "$src" ]; then
    echo "ERROR: missing screencap helper source: $src" >&2
    exit 1
  fi

  if ! command -v swiftc >/dev/null 2>&1; then
    if [ "${TRACENIUM_SKIP_SCREENCAP:-}" = "1" ]; then
      echo "WARNING: swiftc not found and TRACENIUM_SKIP_SCREENCAP=1 — rcp.screen will be unavailable in this build." >&2
      return 0
    fi
    echo "ERROR: swiftc not found (install Xcode Command Line Tools) — required to build the rcp.screen helper." >&2
    echo "       Set TRACENIUM_SKIP_SCREENCAP=1 to build without screen capture." >&2
    exit 1
  fi

  rm -rf "$app_dir"
  mkdir -p "$app_dir/Contents/MacOS"

  # LSUIElement: sin icono en el Dock ni menú. Es un helper, no una app que el
  # usuario abra — pero sigue siendo un bundle para que TCC y Ajustes lo traten
  # como ciudadano de primera.
  cat > "$app_dir/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.certusws.tracenium.screencap</string>
  <key>CFBundleName</key>
  <string>Tracenium Screen Helper</string>
  <key>CFBundleDisplayName</key>
  <string>Tracenium Screen Helper</string>
  <key>CFBundleExecutable</key>
  <string>tracenium-screencap</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.3</string>
  <key>LSUIElement</key>
  <true/>
</dict>
</plist>
PLIST

  local tmp; tmp="$(mktemp -d)"
  echo "→ building tracenium-screencap (arm64 + x86_64, target macos12.3)"
  swiftc -O -target arm64-apple-macos12.3  "$src" -o "$tmp/screencap.arm64"
  swiftc -O -target x86_64-apple-macos12.3 "$src" -o "$tmp/screencap.x86_64"
  lipo -create "$tmp/screencap.arm64" "$tmp/screencap.x86_64" -output "$out"
  rm -rf "$tmp"
  chmod 0755 "$out"

  # Sign with hardened runtime + Developer ID. No entitlements: the
  # helper is not a JIT/V8 process, and TCC keys on the (stable)
  # signature, so defaults are correct here (same rationale as the
  # internal-binary signing block below). This signature must NOT be
  # re-applied by the *.node loop later — it isn't, that loop only
  # touches node + *.node files.
  if [ "$(printf "%s" "${TRACENIUM_CODESIGN_IDENTITY:-}" | tr '[:upper:]' '[:lower:]')" = "skip" ]; then
    echo "Skipping screencap helper codesign (TRACENIUM_CODESIGN_IDENTITY=skip)."
  else
    local CODESIGN_ID="${TRACENIUM_CODESIGN_IDENTITY:-Developer ID Application: CERTUS ITM LLC (3CN673MCWH)}"
    /usr/bin/xattr -cr "$app_dir" || true
    echo "→ codesign $app_dir"
    # -i pins a STABLE signing identifier so the MDM PPPC profile's
    # CodeRequirement (identifier "com.certusws.tracenium.screencap" and
    # anchor apple generic and certificate leaf[subject.OU]="3CN673MCWH")
    # matches deterministically. Without -i the identifier defaults to the
    # binary filename, which is fine today but brittle. See
    # privsvc/macos/helpers/README.md.
    # Se firma el BUNDLE entero, no el ejecutable suelto: TCC ancla el
    # permiso al bundle, y firmar solo el binario de dentro deja el .app sin
    # sello y la concesión sin sitio donde agarrarse.
    codesign --force --options runtime --timestamp \
      -i com.certusws.tracenium.screencap \
      --sign "$CODESIGN_ID" "$app_dir"
    codesign --verify --strict --verbose=2 "$app_dir"
  fi
}

build_status_app_bundle() {
  if [ ! -d "$STATUS_APP_DIR" ]; then
    echo "Missing status app source directory: $STATUS_APP_DIR" >&2
    exit 1
  fi

  if [ ! -f "$STATUS_APP_INFO_TEMPLATE" ]; then
    echo "Missing status app Info.plist template: $STATUS_APP_INFO_TEMPLATE" >&2
    exit 1
  fi

  (
    cd "$STATUS_APP_DIR"
    # Build UNIVERSAL (arm64 + x86_64) so a single build serves both the
    # arm64 and the x64 pkg — same approach as the screencap helper above.
    # Plain `swift build` targets only the build host, which silently put
    # an arm64 status app inside the x64 pkg (caught by
    # verify_payload_arch).
    swift build -c release --arch arm64 --arch x86_64
  )

  local executable_path
  # A multi-arch build lands under .build/apple/Products/Release. The
  # single-arch layout (.build/release → arch-specific symlink) is kept
  # as a fallback so this still works if the universal build is ever
  # reverted.
  executable_path="$STATUS_APP_DIR/.build/apple/Products/Release/TraceniumAgentStatus"
  if [ ! -x "$executable_path" ]; then
    executable_path="$STATUS_APP_DIR/.build/release/TraceniumAgentStatus"
  fi
  if [ ! -x "$executable_path" ]; then
    echo "Missing built status app executable: $executable_path" >&2
    exit 1
  fi

  rm -rf "$STATUS_APP_BUNDLE_DIR"
  rm -rf "$STATUS_APP_ICONSET_DIR"
  mkdir -p "$STATUS_APP_BUNDLE_DIR/Contents/MacOS"
  mkdir -p "$STATUS_APP_BUNDLE_DIR/Contents/Resources"
  mkdir -p "$STATUS_APP_ICONSET_DIR"

  sips -z 16 16 "$STATUS_APPICON_PNG" --out "$STATUS_APP_ICONSET_DIR/icon_16x16.png" >/dev/null
  sips -z 32 32 "$STATUS_APPICON_PNG" --out "$STATUS_APP_ICONSET_DIR/icon_16x16@2x.png" >/dev/null
  sips -z 32 32 "$STATUS_APPICON_PNG" --out "$STATUS_APP_ICONSET_DIR/icon_32x32.png" >/dev/null
  sips -z 64 64 "$STATUS_APPICON_PNG" --out "$STATUS_APP_ICONSET_DIR/icon_32x32@2x.png" >/dev/null
  sips -z 128 128 "$STATUS_APPICON_PNG" --out "$STATUS_APP_ICONSET_DIR/icon_128x128.png" >/dev/null
  sips -z 256 256 "$STATUS_APPICON_PNG" --out "$STATUS_APP_ICONSET_DIR/icon_128x128@2x.png" >/dev/null
  sips -z 256 256 "$STATUS_APPICON_PNG" --out "$STATUS_APP_ICONSET_DIR/icon_256x256.png" >/dev/null
  sips -z 512 512 "$STATUS_APPICON_PNG" --out "$STATUS_APP_ICONSET_DIR/icon_256x256@2x.png" >/dev/null
  sips -z 512 512 "$STATUS_APPICON_PNG" --out "$STATUS_APP_ICONSET_DIR/icon_512x512.png" >/dev/null
  sips -z 1024 1024 "$STATUS_APPICON_PNG" --out "$STATUS_APP_ICONSET_DIR/icon_512x512@2x.png" >/dev/null
  if ! iconutil --convert icns "$STATUS_APP_ICONSET_DIR" --output "$STATUS_APP_ICON_ICNS" 2>/dev/null; then
    STATUS_APP_ICONSET_DIR="$STATUS_APP_ICONSET_DIR" STATUS_APP_ICON_ICNS="$STATUS_APP_ICON_ICNS" python3 - <<'PY'
from pathlib import Path
import os
import struct

iconset = Path(os.environ["STATUS_APP_ICONSET_DIR"])
out = Path(os.environ["STATUS_APP_ICON_ICNS"])
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

  cp "$executable_path" "$STATUS_APP_BUNDLE_DIR/Contents/MacOS/TraceniumAgentStatus"
  cp "$STATUS_APP_ICON_ICNS" "$STATUS_APP_BUNDLE_DIR/Contents/Resources/tracenium.icns"
  cp "$STATUS_ICON_PNG" "$STATUS_APP_BUNDLE_DIR/Contents/Resources/Tracenium_tryicon.png"
  # Logo a color del header del popover (StatusPopoverViewController.configureHeader).
  cp "$STATUS_APP_DIR/Resources/tracenium_logo_color.png" "$STATUS_APP_BUNDLE_DIR/Contents/Resources/tracenium_logo_color.png"
  sed \
    -e "s/@TRACENIUM_AGENT_VERSION@/$VERSION/g" \
    "$STATUS_APP_INFO_TEMPLATE" > "$STATUS_APP_BUNDLE_DIR/Contents/Info.plist"

  /bin/chmod 755 "$STATUS_APP_BUNDLE_DIR/Contents/MacOS/TraceniumAgentStatus"

  # ---------------------------------------------------------------------------
  # Codesign the .app bundle so flotas con Gatekeeper estricto puedan ejecutarlo
  # cuando launchctl lo arranca como LaunchAgent. Sin firma, equipos con MDM
  # configurado en "Allow apps downloaded from: App Store and identified
  # developers" pueden bloquear el binario y el icono nunca aparece en menubar.
  #
  # Tres caminos:
  #   (a) TRACENIUM_CODESIGN_IDENTITY="skip"                   → SKIP explícito sin
  #                                                              warning ruidoso.
  #   (b) TRACENIUM_CODESIGN_IDENTITY="<exact identity>"       → usa esa identidad,
  #                                                              valida que exista
  #                                                              en el keychain.
  #   (c) variable no exportada                                → cae al default
  #                                                              configurado abajo.
  #
  # DEFAULT_CODESIGN_IDENTITY: el Developer ID Application emitido a
  # CERTUS ITM LLC. Es el cert productivo — válido para distribución a
  # flotas externas. Una vez firmado el .app, queda Gatekeeper-compliant
  # en cualquier Mac (no solo los registrados en la cuenta de developer).
  #
  # Notarización: para suprimir el banner de "downloaded from internet"
  # de Gatekeeper, hay que notarizar el .pkg final con `xcrun notarytool
  # submit` + `xcrun stapler staple` post-build. Es un paso aparte que
  # corre fuera de este script (requiere app-specific password y un
  # keychain profile). Sin notarización el .pkg igual instala vía
  # `installer -pkg` y los daemons arrancan, pero un usuario que haga
  # doble-click al .pkg verá el warning.
  #
  # Ojo con TeamIDs: el "Developer ID Application" usa el TeamID de la
  # organización (3CN673MCWH = CERTUS ITM LLC), distinto al TeamID de
  # los certs "Apple Development" individuales (B8P773B3XB). Apple los
  # gestiona en accounts separadas pero están vinculados.
  #
  # Override:
  #   TRACENIUM_CODESIGN_IDENTITY="Apple Development: …"  → cert de QA
  #                                                         (firma local
  #                                                         que sirve solo
  #                                                         en máquinas
  #                                                         del Team)
  #   TRACENIUM_CODESIGN_IDENTITY=skip                    → sin firma
  # ---------------------------------------------------------------------------
  DEFAULT_CODESIGN_IDENTITY="Developer ID Application: CERTUS ITM LLC (3CN673MCWH)"
  CODESIGN_ID="${TRACENIUM_CODESIGN_IDENTITY:-$DEFAULT_CODESIGN_IDENTITY}"

  if [ "$(printf "%s" "$CODESIGN_ID" | tr '[:upper:]' '[:lower:]')" = "skip" ]; then
    echo "Status app codesign explicitly skipped (TRACENIUM_CODESIGN_IDENTITY=skip)."
  else
    # Pre-flight: la identity DEBE existir en el keychain ANTES de
    # invocar codesign, si no `set -eu` mata todo el pipeline con un
    # mensaje genérico ("no identity found"). Detectamos antes y damos
    # un error útil. `security find-identity -v -p codesigning` lista
    # todas las identidades válidas para code signing; buscamos un
    # match substring case-sensitive porque los nombres son lo que
    # codesign también usa (incluido el (TEAMID) entre paréntesis).
    if ! security find-identity -v -p codesigning 2>/dev/null | grep -qF "$CODESIGN_ID"; then
      echo "" >&2
      echo "ERROR: TRACENIUM_CODESIGN_IDENTITY does not match any identity in this Mac's keychain." >&2
      echo "       Configured value: $CODESIGN_ID" >&2
      echo "" >&2
      echo "       Available signing identities:" >&2
      security find-identity -v -p codesigning 2>/dev/null | sed 's/^/         /' >&2
      echo "" >&2
      echo "       Hints:" >&2
      echo "         * El placeholder 'Developer ID Application: CertusWS Inc. (TEAMID)' es literal —" >&2
      echo "           reemplázalo con uno de los strings exactos arriba." >&2
      echo "         * Para skipear codesigning en builds locales:  unset TRACENIUM_CODESIGN_IDENTITY" >&2
      echo "         * O explícito sin warning:                      export TRACENIUM_CODESIGN_IDENTITY=skip" >&2
      exit 1
    fi

    # codesign falla con "resource fork, Finder information, or similar
    # detritus not allowed" si cualquier archivo dentro del bundle
    # arrastra extended attributes (típicamente com.apple.FinderInfo,
    # com.apple.quarantine, o com.apple.metadata:*). Estos vienen del
    # filesystem cuando copiamos archivos con `cp` desde fuentes que
    # los tienen — por ejemplo el Tracenium_tryicon.png que el
    # finder/AirDrop puede haber tocado, o los .icns generados por
    # iconutil. Limpiamos recursivamente antes de firmar — es seguro:
    # solo borra metadata extra, no el contenido de los archivos.
    echo "Stripping extended attributes from .app bundle..."
    /usr/bin/xattr -cr "$STATUS_APP_BUNDLE_DIR"

    echo "Codesigning status app with identity: $CODESIGN_ID"
    codesign --force --deep \
      --options runtime \
      --timestamp \
      --sign "$CODESIGN_ID" \
      "$STATUS_APP_BUNDLE_DIR"

    echo "Verifying status app signature..."
    codesign --verify --deep --strict --verbose=2 "$STATUS_APP_BUNDLE_DIR"
    spctl --assess --type execute --verbose=2 "$STATUS_APP_BUNDLE_DIR" || \
      echo "WARNING: spctl assessment failed; signed but not yet notarized."
  fi
}

rebuild_better_sqlite3() {
  local target_node_version
  target_node_version="$("$BUILD_DIR/Runtime/node" -p 'process.versions.node')"

  mkdir -p "$NPM_CACHE_DIR" "$NODE_GYP_CACHE_DIR"

  # node-gyp decides "headers for <version> are already installed" purely
  # from <devdir>/<version>/installVersion, and skips the download when it
  # exists. If that marker is present but the headers aren't, the build
  # dies with "common.gypi not found" — which is exactly what a stray
  # committed installVersion produced on a clean CI checkout. Treat an
  # incomplete header dir as absent so node-gyp fetches a full copy.
  if [ -f "$NODE_GYP_CACHE_DIR/$target_node_version/installVersion" ] && \
     [ ! -f "$NODE_GYP_CACHE_DIR/$target_node_version/common.gypi" ]; then
    echo "→ node-gyp headers for $target_node_version are incomplete; refetching"
    rm -rf "$NODE_GYP_CACHE_DIR/$target_node_version"
  fi

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

# Auto-stage the bundled Node runtime if missing. We download the
# official darwin tarball from nodejs.org (same source the Linux build
# uses) and copy ONLY the `node` binary into Runtime/ — we don't ship
# npm/npx (the agent runs node directly via launchd, doesn't shell out
# to npm).
#
# Why download instead of using /usr/local/bin/node: the host node may
# be a different major version than what the agent was built/tested
# against. Pinning via .nodeversion + downloading guarantees the same
# runtime regardless of which Mac built the .pkg.
# node-datachannel ships N-API PREBUILDS (its install script is
# `prebuild-install -r napi`), so what sits in the host's node_modules
# is whatever arch this Mac is — arm64 on Apple Silicon. Unlike
# better-sqlite3 (rebuilt from source above) and node-pty (which vendors
# a prebuild per platform/arch under prebuilds/ and picks at runtime),
# node-datachannel carries exactly ONE binary. Copying it verbatim into
# an x64 payload ships an arm64 .node → the agent loads fine until RCP
# starts, then PeerConnection dies on an Intel Mac. So: check the arch
# of what we staged and re-fetch the correct prebuild when it doesn't
# match the target.
lipo_arch_for() {
  # Map Node's arch token to the one `lipo -archs` reports.
  case "$1" in
    x64) echo "x86_64" ;;
    arm64) echo "arm64" ;;
    *) echo "$1" ;;
  esac
}

stage_node_datachannel() {
  local binding="$BUILD_DIR/Agent/node_modules/node-datachannel/build/Release/node_datachannel.node"
  local want; want="$(lipo_arch_for "$ARCH")"

  if [ -f "$binding" ] && lipo -archs "$binding" 2>/dev/null | tr ' ' '\n' | grep -qx "$want"; then
    echo "→ node-datachannel already $want, keeping staged copy"
    return 0
  fi

  echo "→ fetching node-datachannel prebuild for darwin-$ARCH"
  (
    cd "$BUILD_DIR/Agent/node_modules/node-datachannel"
    HOME="$ROOT_DIR/build" \
    npm_config_cache="$NPM_CACHE_DIR" \
    "$ROOT_DIR/node_modules/.bin/prebuild-install" \
      -r napi --platform=darwin --arch="$ARCH" --force
  ) || {
    echo "ERROR: no node-datachannel prebuild for darwin-$ARCH." >&2
    echo "       Remote control (RCP) would fail at runtime on that arch." >&2
    exit 1
  }

  # Never ship the wrong slice: verify rather than trust the fetch.
  if ! lipo -archs "$binding" 2>/dev/null | tr ' ' '\n' | grep -qx "$want"; then
    echo "ERROR: node-datachannel is still not $want after prebuild-install." >&2
    echo "       Got: $(lipo -archs "$binding" 2>/dev/null || echo 'unreadable')" >&2
    exit 1
  fi
  echo "  node-datachannel: $want ✓"
}

stage_macos_node() {
  mkdir -p "$BUILD_DIR/Runtime"
  local cache_dir="$ROOT_DIR/build/.node-cache"
  local tarball="node-v$NODE_VERSION-darwin-$ARCH.tar.gz"
  local url="https://nodejs.org/dist/v$NODE_VERSION/$tarball"
  local cached="$cache_dir/$tarball"
  local extracted="$cache_dir/node-v$NODE_VERSION-darwin-$ARCH"

  mkdir -p "$cache_dir"

  if [ ! -f "$cached" ]; then
    echo "→ downloading $tarball"
    /usr/bin/curl -fsSL "$url" -o "$cached" || {
      rm -f "$cached"
      echo "ERROR: failed to download node $NODE_VERSION (darwin-$ARCH)" >&2
      echo "       URL: $url" >&2
      exit 1
    }
    # SHA256 verification against nodejs.org's official SHASUMS256.txt.
    local sums_url="https://nodejs.org/dist/v$NODE_VERSION/SHASUMS256.txt"
    local expected_sha
    expected_sha=$(/usr/bin/curl -fsSL "$sums_url" | /usr/bin/grep "  $tarball\$" | /usr/bin/awk '{print $1}')
    if [ -z "$expected_sha" ]; then
      rm -f "$cached"
      echo "ERROR: no SHA256 entry for $tarball in $sums_url" >&2
      exit 1
    fi
    local actual_sha
    actual_sha=$(/usr/bin/shasum -a 256 "$cached" | /usr/bin/awk '{print $1}')
    if [ "$expected_sha" != "$actual_sha" ]; then
      rm -f "$cached"
      echo "ERROR: node tarball SHA256 mismatch (expected $expected_sha, got $actual_sha)" >&2
      exit 1
    fi
    echo "→ node tarball SHA256 verified"
  fi

  if [ ! -d "$extracted" ]; then
    echo "→ extracting node"
    /usr/bin/tar -C "$cache_dir" -xzf "$cached"
  fi

  cp "$extracted/bin/node" "$BUILD_DIR/Runtime/node"
  chmod 0755 "$BUILD_DIR/Runtime/node"
}

# BUILD_DIR is shared by every arch ($ROOT_DIR/build/macos), so a runtime
# left behind by a previous build of a DIFFERENT arch will happily sit
# here. Staging only "if missing" then silently ships the wrong slice:
# an x64 build inherits the arm64 node, the better-sqlite3 ABI probe runs
# arm64-module-under-arm64-node and passes, and the result is a
# `-x64.pkg` full of arm64 binaries that dies on an Intel Mac. Verify the
# arch, not just the presence.
if [ ! -x "$BUILD_DIR/Runtime/node" ]; then
  stage_macos_node
elif ! lipo -archs "$BUILD_DIR/Runtime/node" 2>/dev/null | tr ' ' '\n' | grep -qx "$(lipo_arch_for "$ARCH")"; then
  echo "→ staged Node runtime is not $(lipo_arch_for "$ARCH") (stale build dir); re-staging"
  rm -rf "$BUILD_DIR/Runtime"
  stage_macos_node
fi

# Stage LaunchDaemons plists from the repo into BUILD_DIR before
# packaging. These used to be expected pre-staged by an operator
# (footgun on a clean checkout) — now the script copies them from
# their canonical home under privsvc/macos/launchd/.
mkdir -p "$BUILD_DIR/LaunchDaemons"
if [ -d "$ROOT_DIR/privsvc/macos/launchd" ]; then
  /usr/bin/find "$ROOT_DIR/privsvc/macos/launchd" -maxdepth 1 -name "com.certusws.tracenium.*.plist" \
    -not -name "*.agentstatus.plist" \
    -exec /bin/cp {} "$BUILD_DIR/LaunchDaemons/" \;
fi
# The agentstatus.plist is a LaunchAgent (user-scoped), not a daemon —
# the main script copies it directly to LaunchAgents/ later. Excluded
# from the find above so it doesn't end up in LaunchDaemons/ by mistake.

build_agent_bundle
build_privsvc_bundle
build_screencap_helper
build_status_app_bundle

# Stage native deps into the Agent payload.
#
# Why: build_agent_bundle's esbuild call uses `--external:better-sqlite3`,
# so the bundle expects to resolve better-sqlite3 from node_modules/ at
# runtime (it's a C++ binding, can't be bundled). We need to ship the
# host's better-sqlite3 + its sibling deps under
# $BUILD_DIR/Agent/node_modules/. Same convention the Linux build uses.
#
# Pre-CI this directory was usually already populated by a previous
# local run that pre-staged the files into build/. In CI the checkout
# is clean, so we MUST do this copy explicitly.
#
# After this stage step the existing ABI-mismatch detector below will
# rebuild better-sqlite3 against the BUNDLED node (different ABI from
# the host node that ran npm), so what we copy here is just the source
# tree — the .node binding gets rewritten by rebuild_better_sqlite3.
mkdir -p "$BUILD_DIR/Agent/node_modules"
# RCP M1+M2+M3 — node-pty + node-datachannel are native modules
# (esbuild marks them external; runtime lookup expects them as
# sibling packages next to the bundle).
for pkg in better-sqlite3 bindings file-uri-to-path node-pty node-datachannel; do
  if [ -d "$ROOT_DIR/node_modules/$pkg" ]; then
    rm -rf "$BUILD_DIR/Agent/node_modules/$pkg"
    cp -R "$ROOT_DIR/node_modules/$pkg" "$BUILD_DIR/Agent/node_modules/"
  else
    echo "ERROR: required native dep '$pkg' missing from host node_modules" >&2
    echo "       Run 'npm ci' at the repo root before invoking this script." >&2
    exit 1
  fi
done

# Must run AFTER the copy loop above (it operates on the staged copy)
# and BEFORE the pkg is assembled.
stage_node_datachannel

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

# Arch check, explicitly BEFORE the ABI probe below. What we copied comes
# from the host's node_modules (this Mac's arch), which is wrong whenever
# ARCH != host. Relying on the ABI probe alone is not enough: it only
# proves the module loads in the staged runtime, so a matching-but-wrong
# arch pair passes it.
BSQ_BINDING="$BUILD_DIR/Agent/node_modules/better-sqlite3/build/Release/better_sqlite3.node"
if [ -f "$BSQ_BINDING" ] && \
   ! lipo -archs "$BSQ_BINDING" 2>/dev/null | tr ' ' '\n' | grep -qx "$(lipo_arch_for "$ARCH")"; then
  echo "better-sqlite3 is not $(lipo_arch_for "$ARCH") (host/stale copy). Rebuilding..." >&2
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

if [ ! -f "$STATUS_ICON_PNG" ]; then
  echo "Missing status app icon source: $STATUS_ICON_PNG" >&2
  exit 1
fi

rm -rf "$PKG_ROOT" "$COMPONENT_OUT" "$PKG_OUT" "$ROOT_DIR/build/pkg-distribution"
mkdir -p "$PKG_ROOT/Library/Application Support/Tracenium"
mkdir -p "$PKG_ROOT/Library/LaunchDaemons"
mkdir -p "$PKG_ROOT/Library/LaunchAgents"
mkdir -p "$PKG_ROOT/Applications"
mkdir -p "$COMPONENT_OUT"
mkdir -p "$PKG_OUT"
mkdir -p "$(dirname "$DIST_BUILD")"

rsync -a --exclude ".DS_Store" "$BUILD_DIR/Runtime/" "$PKG_ROOT/Library/Application Support/Tracenium/Runtime/"
rsync -a --exclude ".DS_Store" "$BUILD_DIR/PrivSvc/" "$PKG_ROOT/Library/Application Support/Tracenium/PrivSvc/"
rsync -a --exclude ".DS_Store" "$BUILD_DIR/Agent/" "$PKG_ROOT/Library/Application Support/Tracenium/Agent/"
rsync -a --exclude ".DS_Store" "$BUILD_DIR/LaunchDaemons/" "$PKG_ROOT/Library/LaunchDaemons/"
rsync -a --exclude ".DS_Store" "$ROOT_DIR/privsvc/macos/launchd/com.certusws.tracenium.agentstatus.plist" "$PKG_ROOT/Library/LaunchAgents/"
rsync -a --exclude ".DS_Store" "$STATUS_APP_BUNDLE_DIR/" "$PKG_ROOT/Applications/$STATUS_APP_BUNDLE_NAME/"

rm -f "$PKG_ROOT/Library/Application Support/Tracenium/Agent/.env"
find "$PKG_ROOT" -name ".DS_Store" -delete

chmod +x "$SCRIPTS_DIR/preinstall" "$SCRIPTS_DIR/postinstall"

# ─────────────────────────────────────────────────────────────────────
# Arch gate: refuse to package a payload that doesn't match $ARCH.
#
# The per-module checks above each guard one dependency; this is the
# backstop that catches anything they miss (a new native dep, a stale
# artifact in the shared build dir, a copy from the host's node_modules).
# A wrong slice here is invisible until the agent runs on the target Mac,
# so failing the build is strictly better than shipping it.
#
# Universal binaries pass: `lipo -archs` lists every slice, and one of
# them matching the target is enough (the screencap helper is arm64 +
# x86_64 on purpose). node-pty's prebuilds/ tree is skipped — it vendors
# one binary per platform/arch and selects at runtime, so foreign-arch
# files in there are expected, not a defect.
# NOTE: this file runs under #!/bin/sh — no process substitution, and a
# `find | while` pipeline puts the loop in a SUBSHELL (a counter mutated
# in there would be lost). Mismatches are collected in a temp file so the
# verdict survives the subshell.
verify_payload_arch() {
  want="$(lipo_arch_for "$ARCH")"
  bad_list="$BUILD_DIR/.arch-mismatches"
  : > "$bad_list"

  echo "→ verifying every payload binary is $want"
  /usr/bin/find "$PKG_ROOT" -type f \
    \( -name "*.node" -o -name "node" -o -perm -u+x \) | while IFS= read -r f; do
    case "$f" in
      */node-pty/prebuilds/*) continue ;;
    esac
    # Mach-O only; skip shell scripts, plists and data files.
    /usr/bin/file -b "$f" 2>/dev/null | grep -q "Mach-O" || continue
    archs="$(lipo -archs "$f" 2>/dev/null || echo '')"
    if ! printf '%s' "$archs" | tr ' ' '\n' | grep -qx "$want"; then
      printf '%s  → [%s]\n' "${f#"$PKG_ROOT"}" "$archs" >> "$bad_list"
    fi
  done

  if [ -s "$bad_list" ]; then
    echo "ERROR: payload binaries are not $want — refusing to build a mislabeled $ARCH pkg:" >&2
    sed 's/^/  ✗ /' "$bad_list" >&2
    exit 1
  fi
  echo "  payload arch OK ($want)"
}

verify_payload_arch

# ─────────────────────────────────────────────────────────────────────
# Sign all Mach-O binaries inside the pkg payload BEFORE pkgbuild.
#
# Why this is necessary for notarization:
#   Apple's notary service rejects any .pkg that contains an unsigned
#   executable, even if the .pkg itself or the .app inside it IS signed.
#   "Invalid" status from notarytool with no further context is the
#   typical symptom — running `xcrun notarytool log <id>` reveals the
#   per-binary verdicts.
#
# The unsigned binaries in our payload are:
#   * Library/Application Support/Tracenium/Runtime/node     (downloaded
#     from nodejs.org — unsigned by Apple definition)
#   * Library/Application Support/Tracenium/Agent/node_modules/
#       better-sqlite3/build/Release/better_sqlite3.node      (Mach-O
#     dylib produced by node-gyp during npm rebuild, unsigned)
#
# Status.app and its inner exe are already signed in build_status_app_bundle.
# JS files (agent-core.js, privsvc.js) don't need signing.
#
# Signing format:
#   --options runtime        hardened runtime (required for notary)
#   --timestamp              embedded timestamp (required for notary)
#   --sign "$IDENTITY"       Developer ID Application cert
#   (no entitlements file — defaults are fine for these helpers)
# ─────────────────────────────────────────────────────────────────────
if [ "$(printf "%s" "${TRACENIUM_CODESIGN_IDENTITY:-}" | tr '[:upper:]' '[:lower:]')" = "skip" ]; then
  echo "Skipping internal-binary codesign (TRACENIUM_CODESIGN_IDENTITY=skip)."
else
  # Resolve identity the same way build_status_app_bundle did so the
  # whole pkg is signed under ONE identity. Reading from env or
  # hardcoded default mirrors that function.
  CODESIGN_ID="${TRACENIUM_CODESIGN_IDENTITY:-Developer ID Application: CERTUS ITM LLC (3CN673MCWH)}"

  # Entitlements applied when signing Node + native .node files.
  # CRITICAL: without these, hardened-runtime'd Node crashes with
  # Trace/BPT trap: 5 (SIGTRAP) the first time V8 tries to allocate
  # a JIT page. The file lives in the repo so the build is
  # reproducible; see the plist's header comment for details.
  NODE_ENTITLEMENTS="$ROOT_DIR/privsvc/macos/distribution/resources/node-entitlements.plist"
  if [ ! -f "$NODE_ENTITLEMENTS" ]; then
    echo "ERROR: missing entitlements file: $NODE_ENTITLEMENTS" >&2
    echo "       Required for hardened-runtime'd Node to run V8's JIT." >&2
    exit 1
  fi

  sign_internal_bin() {
    local target="$1"
    if [ ! -f "$target" ]; then
      return 0   # not present in this build — skip silently
    fi
    # Strip xattrs that codesign refuses (FinderInfo, quarantine, etc.).
    /usr/bin/xattr -c "$target" || true
    echo "→ codesign $target"
    # --entitlements is REQUIRED here because hardened runtime
    # (--options runtime) without the allow-jit entitlement kills
    # any V8 process at first JIT allocation. The same entitlement
    # set is harmless for non-JIT binaries (.node native modules),
    # so we apply uniformly.
    codesign --force \
      --options runtime \
      --timestamp \
      --entitlements "$NODE_ENTITLEMENTS" \
      --sign "$CODESIGN_ID" \
      "$target"
    codesign --verify --strict --verbose=2 "$target"
  }

  PKG_PREFIX="$PKG_ROOT/Library/Application Support/Tracenium"
  sign_internal_bin "$PKG_PREFIX/Runtime/node"

  # Sign every .node native binding under the Agent's node_modules.
  # Sign EVERY Mach-O in the payload — not just *.node.
  #
  # node-pty ships `spawn-helper`, an EXTENSIONLESS executable under
  # prebuilds/darwin-<arch>/. The old `-name "*.node"` filter skipped it,
  # so Apple's notary service rejected the whole pkg with three errors
  # against that one file ("The binary is not signed", "The signature
  # does not include a secure timestamp", "The executable does not have
  # the hardened runtime enabled"). That's why notarization had been
  # failing on BOTH arches — the pkg shipped signed-but-not-notarized.
  #
  # Matching on content instead of filename also covers whatever native
  # dep gets added next. Non-Mach-O files (the win32/linux prebuilds, JS,
  # JSON, licenses) are filtered out by `file`, so they're untouched.
  # Foreign-arch Mach-O (the darwin-x64 helper inside an arm64 pkg and
  # vice versa) still gets signed — Apple validates every slice it finds,
  # regardless of the pkg's target arch.
  #
  # Y de paso, el bit de ejecución. node-pty publica en npm el prebuild
  # darwin-x64 de `spawn-helper` SIN +x (el darwin-arm64 sí lo trae), así
  # que en un Mac Intel node-pty falla al arrancar con
  # `pty_spawn_failed: forkpty(3) failed` — un modo de fallo que no menciona
  # permisos por ningún lado. Un chmod aquí lo cubre venga el bit mal de
  # npm, del `cp -R` o de lo que se añada después: si es Mach-O ejecutable,
  # tiene que poder ejecutarse. Los .node son bundles, no ejecutables, así
  # que `file` los deja fuera y no se tocan.
  find "$PKG_PREFIX/Agent/node_modules" -type f 2>/dev/null | while IFS= read -r cand; do
    kind="$(/usr/bin/file -b "$cand" 2>/dev/null)"
    case "$kind" in *Mach-O*) ;; *) continue ;; esac
    case "$kind" in *executable*) chmod 0755 "$cand" ;; esac
    sign_internal_bin "$cand"
  done
fi

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

# ---------------------------------------------------------------------------
# Component plist con BundleIsRelocatable=false para CADA bundle.
#
# Por qué: macOS Installer tiene una "feature" llamada Bundle Relocation —
# si un .app con el mismo CFBundleIdentifier ya existe en otra ruta del
# disco (ej. una copia de dev en ~/build/macos/AgentStatus/...), el
# installer redirige la instalación a ESA ruta en vez de copiar al destino
# original (/Applications/). Eso rompe el LaunchAgent plist que apunta
# fijamente a /Applications/Tracenium Agent Status.app/Contents/MacOS/...
# y causa que `launchctl bootstrap` arranque un binario inexistente, el
# daemon entra en respawn loop, `launchctl kickstart -k` se cuelga
# esperando estado limpio, y a los 10 minutos macOS Installer mata el
# postinstall con PKInstallErrorDomain Code=112.
#
# El fix oficial: generar un component plist con `pkgbuild --analyze`,
# poner BundleIsRelocatable=false en cada entry, y pasar el plist
# modificado a pkgbuild via --component-plist. Eso hace que el installer
# instale al destino fijo siempre, ignorando bundles existentes.
# ---------------------------------------------------------------------------

COMPONENT_PLIST="$ROOT_DIR/build/pkg-component.plist"
pkgbuild --analyze --root "$PKG_ROOT" "$COMPONENT_PLIST"

# Iterate por todos los bundle entries en el plist y forzar
# BundleIsRelocatable=false. Usamos Python con plistlib porque es la
# forma más robusta — PlistBuddy es frágil con índices de array.
python3 - "$COMPONENT_PLIST" <<'PY'
import plistlib, sys

path = sys.argv[1]
with open(path, "rb") as f:
    entries = plistlib.load(f)

mutated = 0
for entry in entries:
    if entry.get("BundleIsRelocatable", False):
        entry["BundleIsRelocatable"] = False
        mutated += 1

with open(path, "wb") as f:
    plistlib.dump(entries, f)

print(f"Disabled BundleIsRelocatable on {mutated}/{len(entries)} bundle entries.")
PY

pkgbuild \
  --root "$PKG_ROOT" \
  --component-plist "$COMPONENT_PLIST" \
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

# ─────────────────────────────────────────────────────────────────────
# Sign the OUTER .pkg with Developer ID Installer cert.
#
# Apple's notary service rejects unsigned .pkg files with error:
#   "The binary is not signed" — path: <pkg-filename>
# even when every binary INSIDE the pkg is properly signed. The pkg
# wrapper itself must be signed with a Developer ID INSTALLER cert
# (different from Developer ID Application that signs Mach-O binaries
# — the team certs are issued separately under the same Developer
# Program but for different purposes).
#
# Same skip-via-env model as the internal-binary signing earlier:
#   TRACENIUM_INSTALLER_IDENTITY=skip → no productsign (local builds
#     without an Installer cert; notarize WILL fail, but build still
#     completes for "I just want to test the pkg locally" flows).
#   TRACENIUM_INSTALLER_IDENTITY="Developer ID Installer: …" → use this.
#   unset → fall back to DEFAULT_INSTALLER_IDENTITY (CERTUS ITM LLC).
#
# IMPORTANT: this step must come AFTER the Rez/SetFile icon attachment,
# because Rez mutates the .pkg bytes (writes 'icns' resource) and would
# invalidate any pre-existing signature. Sign LAST.
# ─────────────────────────────────────────────────────────────────────
DEFAULT_INSTALLER_IDENTITY="Developer ID Installer: CERTUS ITM LLC (3CN673MCWH)"
INSTALLER_ID="${TRACENIUM_INSTALLER_IDENTITY:-$DEFAULT_INSTALLER_IDENTITY}"

if [ "$(printf "%s" "$INSTALLER_ID" | tr '[:upper:]' '[:lower:]')" = "skip" ]; then
  echo "Skipping pkg productsign (TRACENIUM_INSTALLER_IDENTITY=skip)."
  echo "  NOTE: notarization WILL fail without an Installer-signed pkg."
elif ! security find-identity -v 2>/dev/null | grep -qF "$INSTALLER_ID"; then
  echo "" >&2
  echo "WARNING: Installer identity not in keychain — pkg will NOT be signed." >&2
  echo "         Configured: $INSTALLER_ID" >&2
  echo "         Available identities:" >&2
  security find-identity -v 2>/dev/null | sed 's/^/           /' >&2
  echo "" >&2
  echo "         To enable productsign:" >&2
  echo "           1. https://developer.apple.com/account/resources/certificates/list" >&2
  echo "              Add a 'Developer ID Installer' cert (free under your Dev Program)." >&2
  echo "           2. Import to Keychain + export as .p12 (same flow as the App cert)." >&2
  echo "           3. Set TRACENIUM_INSTALLER_IDENTITY to its exact name." >&2
  echo "" >&2
  echo "         Or pass TRACENIUM_INSTALLER_IDENTITY=skip to silence this." >&2
else
  echo "→ productsign $FINAL_PKG with $INSTALLER_ID"
  SIGNED_PKG="${FINAL_PKG}.signed"
  productsign \
    --sign "$INSTALLER_ID" \
    --timestamp \
    "$FINAL_PKG" \
    "$SIGNED_PKG"
  mv -f "$SIGNED_PKG" "$FINAL_PKG"

  # Verify the signature took.
  pkgutil --check-signature "$FINAL_PKG" | sed 's/^/  /'
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
