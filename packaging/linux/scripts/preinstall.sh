#!/bin/sh
# packaging/linux/scripts/preinstall.sh
#
# Runs BEFORE files are unpacked, on both .deb (preinst) and .rpm
# (%pre) install paths. nfpm wires this script into both formats
# from the single config so we maintain one copy.
#
# Job:
#   1. REQUIRE an enrollment token at /tmp/tracenium-enrollment.token.
#      Same gate Windows / macOS installers enforce — without a
#      token, the agent has no way to obtain its mTLS identity and
#      would idle uselessly. Failing here aborts the install with a
#      clear diagnostic instead of producing a broken state.
#   2. Create the `tracenium` system group + user. Both services
#      depend on these existing — privsvc chowns the socket to
#      root:tracenium, agent runs as tracenium:tracenium. If we
#      ran this work in postinstall, there'd be a window where the
#      systemd unit files exist on disk but the user doesn't,
#      causing systemctl daemon-reload to log a warning. Doing it
#      in preinstall closes the gap.
#   3. Stop pre-existing services (upgrades) so the unpack step
#      doesn't fail on "Text file busy" when replacing the running
#      node binary.
#
# Idempotent — safe to re-run on upgrade.
set -eu

LOG_FILE="/var/log/tracenium-install.log"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

# Capture the operator's original stderr at fd 4 BEFORE we redirect
# our verbose chatter into the log file. Critical errors (token
# missing, etc.) write to fd 4 so the operator sees them on the
# terminal even though informational `echo` lines all go to the
# log file. This mirrors the macOS preinstall pattern.
exec 4>&2
exec >> "$LOG_FILE" 2>&1
echo "==== $(date -u '+%Y-%m-%dT%H:%M:%SZ') tracenium preinstall start ===="

# ── Enrollment token gate ──────────────────────────────────────────
# Detect whether this is a fresh install vs an upgrade. Upgrades
# don't need a fresh token — the existing /var/lib/tracenium/
# enrollment.token + installed mTLS cert from the previous version
# already provide identity continuity.
#
# We detect "fresh install" by checking for the absence of the
# tracenium user (preinst on first install runs BEFORE we create
# the user later in this same script) AND the absence of any prior
# enrollment artifacts in /var/lib/tracenium/.
#
# .deb args:  "install" / "upgrade <oldver>"
# .rpm arg:   1 (first install) / 2+ (upgrade)
IS_FRESH_INSTALL=1
case "${1:-}" in
    install)         IS_FRESH_INSTALL=1 ;;
    upgrade)         IS_FRESH_INSTALL=0 ;;
    1)               IS_FRESH_INSTALL=1 ;;   # rpm first install
    2|3|4|5|6|7|8|9) IS_FRESH_INSTALL=0 ;;   # rpm upgrade (count ≥ 2)
    *)
        # Unknown arg shape — be conservative: if a previous
        # enrollment exists, treat as upgrade; otherwise fresh.
        if [ -f /var/lib/tracenium/enrollment.token ] || \
           [ -f /etc/tracenium/certs/client.crt.pem ] || \
           getent passwd tracenium >/dev/null 2>&1; then
            IS_FRESH_INSTALL=0
        fi
        ;;
esac

TMP_TOKEN="/tmp/tracenium-enrollment.token"
if [ "$IS_FRESH_INSTALL" = "1" ]; then
    if [ ! -f "$TMP_TOKEN" ]; then
        # Mirror of the macOS / Windows installer behaviour: we need
        # the one-time enrollment JWT to bootstrap mTLS identity.
        # Fail loudly so the operator KNOWS to fetch the token and
        # retry, instead of finding out hours later that the agent
        # never came online on the dashboard.
        cat >&4 <<EOF
==============================================================
Tracenium agent install ABORTED — enrollment token required.

  Place the one-time enrollment JWT at:

    /tmp/tracenium-enrollment.token

  (Generate one in the dashboard: Settings → Devices →
   Add Device → copy the token, then paste into the file.)

  Then re-run the install:
    sudo dpkg -i tracenium-agent_VERSION_amd64.deb     # Debian/Ubuntu
    sudo dnf install ./tracenium-agent-VERSION.rpm     # RHEL/Rocky
==============================================================
EOF
        echo "  enrollment token missing at $TMP_TOKEN — aborting install"
        exit 1
    fi

    # Sanity-check the token has reasonable contents. JWTs are
    # base64url-encoded segments separated by dots; smallest valid
    # ones are well over 100 bytes. A 0-byte file is almost certainly
    # an operator who `touch`ed the path expecting it to be filled.
    TOKEN_SIZE=$(wc -c < "$TMP_TOKEN" 2>/dev/null || echo 0)
    if [ "$TOKEN_SIZE" -lt 50 ]; then
        cat >&4 <<EOF
==============================================================
Tracenium agent install ABORTED — enrollment token looks invalid.

  $TMP_TOKEN exists but is only $TOKEN_SIZE bytes.
  A valid enrollment JWT is several hundred bytes.

  Replace the file with the full token from the dashboard
  and re-run the install.
==============================================================
EOF
        echo "  enrollment token at $TMP_TOKEN is suspiciously small ($TOKEN_SIZE bytes) — aborting"
        exit 1
    fi

    echo "  enrollment token detected at $TMP_TOKEN (${TOKEN_SIZE} bytes)"
else
    echo "  upgrade path — skipping enrollment-token check"
fi

# ── Create system group + user ─────────────────────────────────────
# Use --system to keep the uid/gid out of the regular user range
# (typically <1000 on Debian, <500 on RHEL — distro-dependent).
# --shell /usr/sbin/nologin so a compromised agent can't drop a
# shell via su. --home-dir /var/lib/tracenium because that's where
# the agent's working files (outbox.db, baselines) live; systemd's
# ProtectSystem=strict + ReadWritePaths=/var/lib/tracenium relies
# on this being the writable surface.

# `getent` is the canonical way to ask "does this group/user exist
# in any of NSS's data sources" (local files + LDAP/AD if configured).
# We don't want to silently shadow an existing tracenium account
# from a directory service.
if ! getent group tracenium >/dev/null; then
    groupadd --system tracenium
    echo "  created group tracenium"
fi

if ! getent passwd tracenium >/dev/null; then
    useradd \
        --system \
        --gid tracenium \
        --home-dir /var/lib/tracenium \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "Tracenium agent" \
        tracenium
    echo "  created user tracenium"
fi

# ── Stop existing services if upgrading ────────────────────────────
# An upgrade replaces /usr/lib/tracenium/node and the bundle .js
# files. If the daemons are still using them, the unpack works
# (Linux unlinks the old inode while the running process keeps a
# handle) but the running daemons keep executing the OLD bundle
# until they restart. Stopping here forces a clean restart on the
# postinstall systemctl start.
#
# `is-active --quiet` returns 0 if active, 3 otherwise — we only
# stop if currently active. systemctl returns non-zero on stop
# failures (e.g. unit file removed mid-upgrade) which we ignore;
# postinstall will daemon-reload + start fresh anyway.
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet tracenium-agent.service; then
        systemctl stop tracenium-agent.service || true
        echo "  stopped tracenium-agent (was running)"
    fi
    if systemctl is-active --quiet tracenium-privsvc.service; then
        systemctl stop tracenium-privsvc.service || true
        echo "  stopped tracenium-privsvc (was running)"
    fi
fi

echo "==== preinstall ok ===="
exit 0
