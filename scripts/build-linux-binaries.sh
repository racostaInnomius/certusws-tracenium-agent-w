#!/bin/sh
# build-linux-pkg.sh
#
# Build .deb + .rpm installers for the Tracenium Agent on Linux.
# Sibling of build-macos-pkg.sh — same workspace layout and version
# resolution, but invokes nfpm instead of pkgbuild/productbuild.
#
# Pipeline:
#   1. Resolve version (env override or package.json).
#   2. Ensure node binary for the target arch is downloaded.
#   3. Bundle agent + privsvc with esbuild, mirror macOS build.
#   4. Stage everything under build/linux/pkg-root/ in the layout
#      nfpm.yaml expects.
#   5. Render nfpm.yaml.tmpl → nfpm.yaml with current version + arch.
#   6. Run nfpm twice: once with --packager deb, once with --packager rpm.
#   7. Drop both files under build/linux/pkg-out/.
#
# Usage:
#   ./scripts/build-linux-pkg.sh
#   TRACENIUM_AGENT_VERSION=1.1.21 ./scripts/build-linux-pkg.sh
#   TRACENIUM_AGENT_ARCH=arm64 ./scripts/build-linux-pkg.sh
#
# Run-host requirements:
#   * MUST run on Linux. better-sqlite3 needs to be rebuilt for the
#     bundled node ABI on the same OS family — cross-compiling from
#     macOS is technically possible but adds toolchain complexity
#     for no real win (every CI runner already has Linux available).
#   * nfpm in PATH (https://nfpm.goreleaser.com/install/).
#   * Node 24 + npm in PATH (we ship our own at runtime, but the
#     build pipeline needs npm to install + rebuild dependencies).
#   * curl, tar — for downloading the bundled node.

set -eu

# Resolve the agent repo from this script's location. After the
# May 2026 consolidation, scripts/ lives INSIDE the agent repo, so
# ROOT_DIR is simply the parent of the dir holding this script.
#
# Layout (post-consolidation):
#   <agent-repo>/
#     scripts/                        <- this file lives here
#     src/  privsvc/  windows/  ...   <- repo sources
#     build/                          <- generated outputs (gitignored)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -f "$ROOT_DIR/package.json" ]; then
  echo "ERROR: Could not find agent repo root at: $ROOT_DIR" >&2
  echo "       (package.json missing — is scripts/ still in the right place?)" >&2
  exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
  echo "ERROR: build-linux-pkg.sh must run on Linux." >&2
  echo "       Current host: $(uname -s). Use a Linux VM/container or CI runner." >&2
  echo "       Cross-compiling from macOS isn't supported because better-sqlite3" >&2
  echo "       must be rebuilt against the bundled node's libc/ABI." >&2
  exit 1
fi

BUILD_DIR="$ROOT_DIR/build/linux"
PKG_ROOT="$BUILD_DIR/pkg-root"
PKG_OUT="$BUILD_DIR/pkg-out"
NPM_CACHE_DIR="$BUILD_DIR/.npm-cache"
NODE_CACHE_DIR="$BUILD_DIR/.node-cache"

# ── Version resolution (mirror of build-macos-pkg.sh) ─────────────
if [ -n "${TRACENIUM_AGENT_VERSION:-}" ]; then
  VERSION="$TRACENIUM_AGENT_VERSION"
else
  VERSION="$(/bin/sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$ROOT_DIR/package.json" | head -n 1)"
  if [ -z "$VERSION" ]; then
    echo "ERROR: Could not resolve version — package.json missing or malformed at $ROOT_DIR/package.json" >&2
    echo "       Pass TRACENIUM_AGENT_VERSION=x.y.z explicitly to override." >&2
    exit 1
  fi
fi

# ── Architecture mapping ──────────────────────────────────────────
# nfpm uses Debian-style arch names ("amd64" / "arm64"). Node uses
# its own ("x64" / "arm64"). Map both.
ARCH="${TRACENIUM_AGENT_ARCH:-amd64}"
case "$ARCH" in
  amd64|x86_64)
    ARCH="amd64"
    NODE_ARCH="x64"
    ;;
  arm64|aarch64)
    ARCH="arm64"
    NODE_ARCH="arm64"
    ;;
  *)
    echo "ERROR: Unsupported arch: $ARCH (use amd64 or arm64)" >&2
    exit 1
    ;;
esac

# NODE_VERSION resolution:
#   1) Env override (TRACENIUM_NODE_VERSION=24.x.y) for CI / experiments
#   2) .nodeversion file at repo root (committed — single source of truth)
#   3) Hardcoded fallback (last resort, matches the .nodeversion default)
if [ -n "${TRACENIUM_NODE_VERSION:-}" ]; then
  NODE_VERSION="$TRACENIUM_NODE_VERSION"
elif [ -f "$ROOT_DIR/.nodeversion" ]; then
  NODE_VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/.nodeversion")"
else
  # Hardcoded fallback — only used if .nodeversion is missing. MUST match
  # the .nodeversion contents to avoid version drift if a developer somehow
  # deletes the file. Currently 22.22.3 (Jod LTS) because the upstream
  # `node-datachannel` package publishes prebuilds built against Node 18 —
  # those prebuilds are stable on Node 22 but fastfail at PeerConnection
  # construct on Node 24 (STATUS_STACK_BUFFER_OVERRUN, 0xC0000409) due to
  # ABI drift in the Node 22→24 jump. Bump this in lockstep with .nodeversion.
  NODE_VERSION="22.22.3"
fi

echo "==== build-linux-pkg ===="
echo "  version: $VERSION"
echo "  arch:    $ARCH (node: $NODE_ARCH)"
echo "  node:    $NODE_VERSION"
echo ""

# ── Tooling checks ────────────────────────────────────────────────
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command '$1' not found in PATH" >&2
    exit 1
  }
}
require_cmd nfpm
require_cmd node
require_cmd npm
require_cmd curl
require_cmd tar

# ── Clean output dirs ─────────────────────────────────────────────
# We wipe PKG_ROOT (the staged file tree nfpm consumes) and PKG_OUT
# (where the .deb/.rpm land) every run — those are pure output.
# We DO NOT wipe $BUILD_DIR/staging: that's where the isolated
# node_modules + source mirror lives, and reusing it across builds
# is what makes incremental builds fast (npm ci is the slow step).
# Cache invalidation for staging is handled below — npm ci only
# re-runs when package-lock.json actually changed.
rm -rf "$PKG_ROOT" "$PKG_OUT"
mkdir -p "$PKG_ROOT/agent" "$PKG_ROOT/privsvc" "$PKG_ROOT/proto" "$PKG_ROOT/assets"
mkdir -p "$PKG_OUT" "$NODE_CACHE_DIR"

# ── Download bundled node ─────────────────────────────────────────
NODE_TARBALL="node-v$NODE_VERSION-linux-$NODE_ARCH.tar.xz"
NODE_URL="https://nodejs.org/dist/v$NODE_VERSION/$NODE_TARBALL"
NODE_CACHED="$NODE_CACHE_DIR/$NODE_TARBALL"

if [ ! -f "$NODE_CACHED" ]; then
  echo "→ downloading $NODE_TARBALL"
  curl -fsSL "$NODE_URL" -o "$NODE_CACHED" || {
    rm -f "$NODE_CACHED"
    echo "ERROR: failed to download node $NODE_VERSION for $NODE_ARCH from $NODE_URL" >&2
    exit 1
  }

  # Verify against nodejs.org's official SHASUMS256.txt. Defense
  # against MITM, a compromised mirror, or accidental cache poisoning.
  # We fetch the SHASUMS file fresh on every download to avoid trusting
  # a stale cached sums file. Nodejs.org signs the SHASUMS256.txt with
  # the release-team GPG key; for now we trust HTTPS + the fact that
  # the file lives on the same host as the binary.
  SUMS_URL="https://nodejs.org/dist/v$NODE_VERSION/SHASUMS256.txt"
  expected_sha=$(curl -fsSL "$SUMS_URL" | grep "  $NODE_TARBALL\$" | awk '{print $1}')
  if [ -z "$expected_sha" ]; then
    rm -f "$NODE_CACHED"
    echo "ERROR: could not resolve expected SHA256 for $NODE_TARBALL" >&2
    echo "       (no matching line in $SUMS_URL — version typo?)" >&2
    exit 1
  fi
  actual_sha=$(sha256sum "$NODE_CACHED" | awk '{print $1}')
  if [ "$expected_sha" != "$actual_sha" ]; then
    rm -f "$NODE_CACHED"
    echo "ERROR: node tarball SHA256 mismatch" >&2
    echo "       expected: $expected_sha" >&2
    echo "       got:      $actual_sha" >&2
    exit 1
  fi
  echo "→ node tarball SHA256 verified"
fi

NODE_EXTRACTED="$NODE_CACHE_DIR/node-v$NODE_VERSION-linux-$NODE_ARCH"

# Defensive completeness check: a previous run (or actions/cache@v4
# restore) can leave the EXTRACTED-DIR present but with partial
# contents — typically the top-level folder exists but `bin/node`
# inside doesn't. Guarding only on dir-presence makes the cp below
# fail at runtime with a vague "cannot stat" error. Instead, treat
# the absence of bin/node as "extraction incomplete, redo it".
if [ ! -x "$NODE_EXTRACTED/bin/node" ]; then
  echo "→ extracting node"
  rm -rf "$NODE_EXTRACTED"
  if ! tar -C "$NODE_CACHE_DIR" -xJf "$NODE_CACHED"; then
    echo "ERROR: tar -xJf failed for $NODE_CACHED" >&2
    rm -f "$NODE_CACHED"
    exit 1
  fi
fi

if [ ! -x "$NODE_EXTRACTED/bin/node" ]; then
  echo "ERROR: after extraction, $NODE_EXTRACTED/bin/node is still missing" >&2
  echo "       Tarball may be corrupt — dropping cache and aborting." >&2
  echo "       Re-run the workflow; next attempt will redownload from scratch." >&2
  ls -la "$NODE_EXTRACTED" 2>&1 | sed 's/^/         /' >&2 || true
  rm -rf "$NODE_CACHED" "$NODE_EXTRACTED"
  exit 1
fi

cp "$NODE_EXTRACTED/bin/node" "$PKG_ROOT/node"
chmod 0755 "$PKG_ROOT/node"

# ── Build agent + privsvc bundles (esbuild) ───────────────────────
# All npm install + esbuild + native-rebuild work happens inside an
# isolated staging dir (build/linux/staging/) — we NEVER touch the
# host repo's node_modules.
#
# Why: this script runs on Linux, but the agent repo is often a
# shared/mounted workspace whose `$ROOT_DIR/node_modules` belongs to
# the developer's macOS install (Darwin arm64 binaries). Writing
# Linux x64 binaries into that tree breaks the next
# `./scripts/build-macos-pkg.sh` run with a cryptic "cannot execute
# binary file" — that's exactly the bug we shipped before this fix:
# esbuild's `node_modules/.bin/esbuild` shim landing on a Linux ELF
# when running on a Mac.
#
# Staging layout (a complete mirror of just what esbuild needs):
#   build/linux/staging/
#     ├── package.json         (copy of $ROOT_DIR/package.json)
#     ├── package-lock.json    (copy of $ROOT_DIR/package-lock.json)
#     ├── tsconfig.json        (copy, auto-discovered by esbuild)
#     ├── src/                 (copy of $ROOT_DIR/src/)
#     ├── privsvc/             (copy of $ROOT_DIR/privsvc/)
#     ├── proto/               (copy — referenced by privsvc bundle)
#     └── node_modules/        (created by npm ci INSIDE staging)
#
# The previous install is reused across builds when the lock hasn't
# changed (compared byte-for-byte) — saves ~1–2 min on incremental
# builds while still re-installing on dependency bumps.
STAGING_DIR="$BUILD_DIR/staging"
mkdir -p "$STAGING_DIR"

# Refresh source trees each build. cp -r is sub-second for the
# agent's src/ + privsvc/ (small TS projects, no node_modules
# inside). We rm-then-cp instead of rsync to avoid adding rsync to
# the build-host requirements.
rm -rf "$STAGING_DIR/src" "$STAGING_DIR/privsvc" "$STAGING_DIR/proto"
cp -r "$ROOT_DIR/src"     "$STAGING_DIR/src"
cp -r "$ROOT_DIR/privsvc" "$STAGING_DIR/privsvc"
cp -r "$ROOT_DIR/proto"   "$STAGING_DIR/proto"
[ -f "$ROOT_DIR/tsconfig.json" ] && cp "$ROOT_DIR/tsconfig.json" "$STAGING_DIR/tsconfig.json"

# ALWAYS refresh package.json + package-lock.json into staging — even
# when we plan to skip `npm ci`.
#
# Why: `src/bootstrap/config.ts` does `import pkg from "../../package.json"`,
# and esbuild resolves that to `staging/package.json` at bundle time,
# inlining the literal JSON (including `version`) into the output. If
# the staged copy is stale, the bundle ships the WRONG agentVersion —
# even though the .deb filename and dpkg metadata are correct (because
# those come from `$VERSION` resolved above, not from inside the bundle).
#
# Confirmed in CI on 1.1.21: actions/cache restored `staging/` with the
# previous build's package.json. CI logged "reusing cached staging
# node_modules (lock unchanged)" → the `if NEED_INSTALL=1` branch below
# never ran → the staged package.json from the prior cache cycle (still
# at 1.1.21) was bundled. Agent reported `Agent hello context
# agentVersion: '1.1.21'` despite being installed as 1.1.21-1.
#
# Fix: do the refresh unconditionally. It's a 1 KB copy — irrelevant
# to build time. The `npm ci` skip logic stays, but now keys off a
# separate marker file (`.last-installed-lock-hash`) so we don't lose
# the optimization.
cp "$ROOT_DIR/package.json"      "$STAGING_DIR/package.json"
cp "$ROOT_DIR/package-lock.json" "$STAGING_DIR/package-lock.json"

NEED_INSTALL=0
if [ ! -d "$STAGING_DIR/node_modules" ]; then
  NEED_INSTALL=1
elif [ ! -f "$STAGING_DIR/.last-installed-lock-hash" ]; then
  NEED_INSTALL=1
elif ! cmp -s "$STAGING_DIR/.last-installed-lock-hash" "$STAGING_DIR/package-lock.json" 2>/dev/null; then
  NEED_INSTALL=1
fi

if [ "$NEED_INSTALL" = "1" ]; then
  echo "→ npm ci (staging — isolated from \$ROOT_DIR/node_modules)"
  (cd "$STAGING_DIR" && npm ci --cache "$NPM_CACHE_DIR")
  cp "$STAGING_DIR/package-lock.json" "$STAGING_DIR/.last-installed-lock-hash"
else
  echo "→ reusing cached staging node_modules (lock unchanged)"
fi

echo "→ esbuild agent core"
"$STAGING_DIR/node_modules/.bin/esbuild" "$STAGING_DIR/src/index.ts" \
  --bundle \
  --platform=node \
  --format=cjs \
  --target=node24 \
  --external:better-sqlite3 \
  --external:node-pty \
  --external:node-datachannel \
  --outfile="$PKG_ROOT/agent/index.js"

echo "→ esbuild privsvc"
"$STAGING_DIR/node_modules/.bin/esbuild" "$STAGING_DIR/privsvc/linux/src/index.ts" \
  --bundle \
  --platform=node \
  --format=cjs \
  --target=node24 \
  --outfile="$PKG_ROOT/privsvc/index.js"

# ── RCP M3.S1 — screen capture helper (X11) ───────────────────────
# Compiles the X11 capture helper that PrivSvc spawns as the session
# user (runuser). It MUST sit next to privsvc/index.js — the orchestrator
# resolves it via path.resolve(__dirname, "tracenium-screencap"), the
# same __dirname the proto path uses. Links libX11 + libjpeg. Build host
# needs: libx11-dev + libjpeg-dev (Debian) / libX11-devel +
# libjpeg-turbo-devel (RHEL). Native arch only — to cross-compile, point
# CC at a cross toolchain. See privsvc/linux/helpers/README.md.
SCREENCAP_SRC="$ROOT_DIR/privsvc/linux/helpers/screencap.c"
SCREENCAP_OUT="$PKG_ROOT/privsvc/tracenium-screencap"
if [ ! -f "$SCREENCAP_SRC" ]; then
  echo "ERROR: missing screencap helper source: $SCREENCAP_SRC" >&2
  exit 1
fi
echo "→ cc screencap helper (X11 + libjpeg)"
if ! "${CC:-cc}" -O2 -Wall "$SCREENCAP_SRC" -o "$SCREENCAP_OUT" -lX11 -ljpeg; then
  if [ "${TRACENIUM_SKIP_SCREENCAP:-}" = "1" ]; then
    echo "WARNING: screencap helper failed to build and TRACENIUM_SKIP_SCREENCAP=1 — installing a stub that reports the capability is unavailable so rcp.screen degrades cleanly." >&2
    # Stub keeps the nfpm contents entry satisfied AND makes the runtime
    # return a clean screen_capture_helper_missing instead of a black
    # frame on a package built without X11/libjpeg dev headers.
    printf '#!/bin/sh\nprintf "{\\"ok\\":false,\\"code\\":\\"screen_capture_helper_missing\\",\\"message\\":\\"screen capture not built into this package\\"}\\n"\n' > "$SCREENCAP_OUT"
  else
    echo "ERROR: failed to compile screencap helper. Install libx11-dev + libjpeg-dev" >&2
    echo "       (Debian) or libX11-devel + libjpeg-turbo-devel (RHEL), or set" >&2
    echo "       TRACENIUM_SKIP_SCREENCAP=1 to build without screen capture." >&2
    exit 1
  fi
fi
[ -f "$SCREENCAP_OUT" ] && chmod 0755 "$SCREENCAP_OUT"

# ── RCP — helper del shell remoto privilegiado ────────────────────
# JS plano, sin compilar ni empaquetar: carga node-pty (nativo) desde el árbol
# del agente en tiempo de ejecución, así que no puede ir dentro del bundle de
# privsvc —esbuild lo construye SIN externals y no admite módulos nativos—.
# Va junto a privsvc/index.js porque rcp-pty.ts lo resuelve con
# path.resolve(__dirname, "tracenium-rcp-pty"), igual que el de screencap.
#
# Sin ejecutable (0644): lo lanza privsvc pasándoselo a su propio node, no se
# ejecuta por sí solo. Un shell de root de menos que quede colgando de un bit
# de permisos.
RCPPTY_SRC="$ROOT_DIR/privsvc/linux/helpers/rcp-pty-helper.js"
RCPPTY_OUT="$PKG_ROOT/privsvc/tracenium-rcp-pty"
if [ ! -f "$RCPPTY_SRC" ]; then
  echo "ERROR: missing rcp pty helper source: $RCPPTY_SRC" >&2
  exit 1
fi
echo "→ copy rcp pty helper"
cp "$RCPPTY_SRC" "$RCPPTY_OUT"
chmod 0644 "$RCPPTY_OUT"

# ── Rebuild + copy better-sqlite3 native binding ──────────────────
# The agent uses better-sqlite3 (outbox.db). Native binding must be
# ABI-compatible with the bundled node we ship in the package. We:
#   1. Run `npm rebuild better-sqlite3` INSIDE staging, against the
#      bundled node's include headers (NOT the host's system node).
#   2. Copy the resulting node_modules/better-sqlite3 into the .deb
#      payload.
#
# Same isolation rationale as the npm ci above: the resulting .node
# binary is linux-<arch>, which would break the macOS dev's node_modules
# if it landed in $ROOT_DIR/node_modules/.
echo "→ rebuilding better-sqlite3 against bundled node (staging)"
(
  cd "$STAGING_DIR"
  PATH="$NODE_EXTRACTED/bin:$PATH" \
    npm rebuild better-sqlite3 --build-from-source --cache "$NPM_CACHE_DIR"
)

# Sanity check: does the bundled node actually load better-sqlite3?
if ! "$PKG_ROOT/node" -e "require('$STAGING_DIR/node_modules/better-sqlite3');" >/dev/null 2>&1; then
  echo "ERROR: bundled node cannot load better-sqlite3 — ABI mismatch" >&2
  echo "       This typically means the rebuild used a different node" >&2
  echo "       version than the bundled one. Check NODE_VERSION matches" >&2
  echo "       the node in \$NODE_EXTRACTED/bin used for npm rebuild." >&2
  exit 1
fi

# Copy better-sqlite3 + its transitive runtime dependencies into
# the bundle. Hoisted layout means Node resolves `require('bindings')`
# from inside better-sqlite3/lib/database.js by walking up looking
# for sibling packages in node_modules — so we have to ship those
# siblings, not just better-sqlite3 itself.
#
# Hardcoded list (small, stable across better-sqlite3 minor
# releases). Walking package.json to compute the transitive set
# correctly = reimplementing npm's resolution algorithm in shell;
# the failure mode of "we missed a new dep" is loud and obvious
# (MODULE_NOT_FOUND on first agent start), which makes the manual
# update path a non-issue.
mkdir -p "$PKG_ROOT/agent/node_modules"
# RCP M1+M2+M3 — node-pty (shell PTY) and node-datachannel (WebRTC) are
# native modules with .node bindings. esbuild can't bundle .node files
# (hence --external:node-pty/--external:node-datachannel above), so we
# ship the whole package directory next to the bundle. The bundled
# `require("node-pty")` / `require("node-datachannel")` resolves to
# $PKG_ROOT/agent/node_modules/* at runtime via Node's standard lookup.
for pkg in better-sqlite3 bindings file-uri-to-path node-pty node-datachannel; do
  if [ -d "$STAGING_DIR/node_modules/$pkg" ]; then
    cp -r "$STAGING_DIR/node_modules/$pkg" "$PKG_ROOT/agent/node_modules/"
  else
    echo "WARNING: expected dep $pkg not found in staging node_modules — agent will fail at runtime" >&2
  fi
done

# ── Validación de node-pty ────────────────────────────────────────
# better-sqlite3 se rebuildea Y se comprueba que el node empaquetado lo
# carga (arriba). node-pty y node-datachannel viajaban con un `cp -r`
# pelado y CERO comprobaciones, y así se colo el defecto que costó una
# noche: el paquete desplegado tenía build/Release/pty.node pero NO
# spawn-helper, que node-pty 1.1.0 exige en POSIX —
# `helperPath = native.dir + "/spawn-helper"` en lib/unixTerminal.js.
# Sin él, remote shell muere en cuanto se abre la sesión y el mensaje no
# menciona ningún fichero que falte.
#
# Los prebuilds que SÍ trae node-pty son darwin-x64/darwin-arm64 (Mach-O),
# inútiles aquí, así que no sirven de red de seguridad.
PTY_DIR="$PKG_ROOT/agent/node_modules/node-pty"
PTY_HELPER="$PTY_DIR/build/Release/spawn-helper"
if [ ! -f "$PTY_DIR/build/Release/pty.node" ]; then
  echo "ERROR: node-pty sin build/Release/pty.node en el payload." >&2
  echo "       El agente no podrá abrir sesiones de remote shell." >&2
  exit 1
fi
# spawn-helper: node-pty calcula helperPath = native.dir + "/spawn-helper"
# y se lo pasa a pty.fork, pero MEDIDO EN CAMPO el fork funciona sin él en
# Linux — así que su ausencia NO es motivo para abortar el build. (Primera
# versión de este bloque sí abortaba; habría roto builds sanos. La causa
# real del "forkpty(3) failed" en el endpoint era AppArmor, no este
# fichero.) Si está, nos aseguramos de que pueda ejecutarse.
if [ -f "$PTY_HELPER" ]; then
  chmod 0755 "$PTY_HELPER"
else
  echo "→ nota: node-pty sin spawn-helper; el fork no lo necesita en Linux"
fi

# Prueba de humo de verdad: abrir un pty con el node empaquetado. Es la
# única comprobación que distingue "los ficheros están" de "esto funciona".
if ! "$PKG_ROOT/node" -e "
  const pty = require('$PTY_DIR');
  const p = pty.spawn('/bin/sh', ['-c', 'exit 0'], { cols: 80, rows: 24 });
  if (!p.pid) { process.exit(1); }
" >/dev/null 2>&1; then
  echo "ERROR: el node empaquetado no puede abrir un pty con node-pty." >&2
  echo "       Puede ser ABI mismatch (node-pty se compiló contra otro" >&2
  echo "       node) o el spawn-helper. Reproduce el error con:" >&2
  echo "         $PKG_ROOT/node -e \"require('$PTY_DIR').spawn('/bin/sh',[],{})\"" >&2
  exit 1
fi
echo "→ node-pty OK (pty.node + spawn-helper + apertura de pty)"

# ── Proto + assets ────────────────────────────────────────────────
cp "$ROOT_DIR/proto/controlplane.proto" "$PKG_ROOT/proto/controlplane.proto"

# Bundled root CA. Critical for TLS verification of the gRPC stream
# to grpc.tracenium.com — the enrollment endpoint only returns the
# Issuing CA in the caBundle, not the self-signed Root CA above it,
# so without this file in /var/lib/tracenium/assets/ the agent's
# Node TLS chain validation fails and the gRPC channel goes
# TRANSIENT_FAILURE in a tight reconnect loop with no useful log
# (the channel-state watcher fires before any app-level error).
#
# Resolution order:
#   1. If the operator pre-staged a root cert at the macOS resource
#      path (the historical location), use it.
#   2. Otherwise fetch the chain from the live grpc.tracenium.com,
#      pick the self-signed cert (subject==issuer) at the top of the
#      chain, and use that. Cached under the build dir so subsequent
#      builds in the same session don't re-fetch.
#   3. Hard fail if neither source produces a valid root cert. We do
#      NOT silently emit an empty placeholder anymore — that's the
#      bug we shipped in the first build round and it cost us a
#      whole evening to diagnose.
ROOT_CA_SRC=""
if [ -f "$ROOT_DIR/privsvc/macos/distribution/resources/root-ca.crt" ]; then
  ROOT_CA_SRC="$ROOT_DIR/privsvc/macos/distribution/resources/root-ca.crt"
  echo "→ using bundled root CA from macOS resources"
fi

# Windows PrivSvc ships the same Root CA as a committed asset. Use it
# as the canonical source for Linux too — single file in the repo,
# kept in sync as part of the Windows build. This is also the only
# location the file lives in the public repo today (the macOS path
# above is a leftover from the original layout; packaging/linux/assets
# is reserved for an explicit per-distro override).
if [ -z "$ROOT_CA_SRC" ] && [ -f "$ROOT_DIR/privsvc/windows/Tracenium.PrivSvc.Windows/assets/root-ca.crt" ]; then
  ROOT_CA_SRC="$ROOT_DIR/privsvc/windows/Tracenium.PrivSvc.Windows/assets/root-ca.crt"
  echo "→ using bundled root CA from Windows PrivSvc assets"
fi

# Also accept a Linux-specific override if a future operator wants
# to ship a different root for Linux only.
if [ -z "$ROOT_CA_SRC" ] && [ -f "$ROOT_DIR/packaging/linux/assets/root-ca.crt" ]; then
  ROOT_CA_SRC="$ROOT_DIR/packaging/linux/assets/root-ca.crt"
  echo "→ using bundled root CA from packaging/linux/assets"
fi

if [ -z "$ROOT_CA_SRC" ]; then
  # Auto-fetch from the live gRPC backend. This requires network
  # connectivity from the build host — fail loudly if absent so the
  # build doesn't silently produce a broken .deb.
  echo "→ no bundled root CA on disk, fetching from grpc.tracenium.com:443"
  CHAIN_DIR="$BUILD_DIR/.ca-cache"
  mkdir -p "$CHAIN_DIR"
  rm -f "$CHAIN_DIR"/chain-*.pem

  # Pull the full chain the server presents.
  if ! echo | openssl s_client -connect grpc.tracenium.com:443 \
       -servername grpc.tracenium.com -showcerts 2>/dev/null \
       | sed -n '/BEGIN CERT/,/END CERT/p' \
       | awk '/BEGIN CERT/{i++} {print > "'"$CHAIN_DIR"'/chain-" i ".pem"}'; then
    echo "ERROR: openssl s_client to grpc.tracenium.com:443 failed" >&2
    echo "       Either restore network connectivity or place the Root CA at:" >&2
    echo "         $ROOT_DIR/packaging/linux/assets/root-ca.crt" >&2
    exit 1
  fi

  # Find the self-signed root in the chain (subject == issuer).
  for f in "$CHAIN_DIR"/chain-*.pem; do
    [ -f "$f" ] || continue
    subj=$(openssl x509 -in "$f" -noout -subject 2>/dev/null | sed 's/^subject=//')
    issu=$(openssl x509 -in "$f" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    if [ -n "$subj" ] && [ "$subj" = "$issu" ]; then
      ROOT_CA_SRC="$f"
      echo "→ identified Root CA: $subj"
      break
    fi
  done

  if [ -z "$ROOT_CA_SRC" ]; then
    echo "ERROR: no self-signed cert found in grpc.tracenium.com chain" >&2
    echo "       Place the Root CA manually at $ROOT_DIR/packaging/linux/assets/root-ca.crt" >&2
    exit 1
  fi
fi

cp "$ROOT_CA_SRC" "$PKG_ROOT/assets/root-ca.crt"
# Sanity-check: the file must be a parseable cert. A 0-byte file
# would cause silent TLS verify failures at runtime — the very bug
# this whole block exists to prevent.
if ! openssl x509 -in "$PKG_ROOT/assets/root-ca.crt" -noout -subject >/dev/null 2>&1; then
  echo "ERROR: root-ca.crt copied to staging is not a valid PEM" >&2
  exit 1
fi
echo "→ root CA staged ($(wc -c < "$PKG_ROOT/assets/root-ca.crt") bytes)"

# ── Render nfpm.yaml from template ────────────────────────────────
NFPM_TMPL="$ROOT_DIR/packaging/linux/nfpm.yaml.tmpl"
NFPM_RENDERED="$PKG_ROOT/nfpm.yaml"

# We do the substitution by hand instead of `envsubst` to keep
# dependencies minimal — nfpm itself doesn't ship envsubst, and
# we don't want to add gettext to the build host.
#
# Tokens use __TOKEN__ delimiters (not ${TOKEN}) so no shell-syntax
# sigils leak into the YAML — protects against accidental expansion
# if a future maintainer runs envsubst over the rendered file.
sed \
  -e "s/__VERSION__/$VERSION/g" \
  -e "s/__ARCH__/$ARCH/g" \
  -e "s|__BUILD_DIR__|$PKG_ROOT|g" \
  -e "s|__REPO_ROOT__|$ROOT_DIR|g" \
  "$NFPM_TMPL" > "$NFPM_RENDERED"

# ── Run nfpm twice — once per target format ────────────────────────
cd "$PKG_ROOT"

echo "→ building .deb"
nfpm package --packager deb --target "$PKG_OUT/" --config "$NFPM_RENDERED"

echo "→ building .rpm"
nfpm package --packager rpm --target "$PKG_OUT/" --config "$NFPM_RENDERED"

# ── Rename to cross-platform convention ───────────────────────────
# nfpm names files using each distro's native convention:
#   .deb → tracenium-agent_<version>_<deb-arch>.deb
#   .rpm → tracenium-agent-<version>-1.<rpm-arch>.rpm
# Both are valid installer filenames (apt/dpkg/dnf will install them
# regardless of name — install metadata comes from the control/spec
# inside the package, not the filename). But the operator sees three
# different conventions across Windows/macOS/Linux when listing
# release artifacts, and our blob storage uses a single convention:
#
#   Tracenium-Agent-<version>-<arch>.<ext>
#
# So we rename the on-disk files to match. This:
#   * Matches what publish-binaries.sh uploads to the blob — one
#     filename through the whole pipeline, less mental tax.
#   * Mirrors the macOS .pkg and Windows .msi naming (build-macos-pkg.sh
#     emits `Tracenium-Agent-<v>-<arch>.pkg` directly via productbuild).
#   * Uses the Node-style arch token (x64/arm64) on every platform,
#     even though the .deb/.rpm metadata internally still uses
#     amd64/x86_64 (that's set in nfpm.yaml and the package manager
#     reads it from the control file).
DEB_SRC="$(find "$PKG_OUT" -maxdepth 1 -name '*.deb' -print -quit)"
RPM_SRC="$(find "$PKG_OUT" -maxdepth 1 -name '*.rpm' -print -quit)"

if [ -z "$DEB_SRC" ] || [ -z "$RPM_SRC" ]; then
  echo "ERROR: nfpm did not produce expected outputs under $PKG_OUT" >&2
  ls -la "$PKG_OUT/" >&2
  exit 1
fi

DEB_FINAL="$PKG_OUT/Tracenium-Agent-$VERSION-$NODE_ARCH.deb"
RPM_FINAL="$PKG_OUT/Tracenium-Agent-$VERSION-$NODE_ARCH.rpm"

# `mv -f` so re-running the script after a partial failure doesn't
# leave both the nfpm-name and the renamed version side-by-side.
mv -f "$DEB_SRC" "$DEB_FINAL"
mv -f "$RPM_SRC" "$RPM_FINAL"

# ── Done ──────────────────────────────────────────────────────────
DEB_SHA="$(sha256sum "$DEB_FINAL" | awk '{print $1}')"
RPM_SHA="$(sha256sum "$RPM_FINAL" | awk '{print $1}')"
DEB_SIZE="$(stat -c%s "$DEB_FINAL" 2>/dev/null || wc -c < "$DEB_FINAL" | tr -d ' ')"
RPM_SIZE="$(stat -c%s "$RPM_FINAL" 2>/dev/null || wc -c < "$RPM_FINAL" | tr -d ' ')"

echo ""
echo "================================ BUILD DONE ================================"
echo "  version: $VERSION"
echo "  arch:    $NODE_ARCH (deb: $ARCH / rpm: see filename)"
echo ""
echo "  deb : $DEB_FINAL"
echo "        size   : $DEB_SIZE bytes"
echo "        sha256 : $DEB_SHA"
echo ""
echo "  rpm : $RPM_FINAL"
echo "        size   : $RPM_SIZE bytes"
echo "        sha256 : $RPM_SHA"
echo "============================================================================"
echo ""
echo "  install (Debian/Ubuntu):  sudo apt install $DEB_FINAL"
echo "  install (RHEL/Rocky):     sudo dnf install $RPM_FINAL"
echo "  inspect:                  dpkg-deb --contents $DEB_FINAL  /  rpm -qlp $RPM_FINAL"
