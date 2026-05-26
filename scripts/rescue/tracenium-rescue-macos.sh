#!/bin/sh
# tracenium-rescue-macos.sh
#
# One-shot rescue for macOS devices stuck on an old agent that won't
# self-update. Reinstalls the agent from a locally-supplied .pkg.
#
# Usage:
#   sudo ./tracenium-rescue-macos.sh /path/to/Tracenium-Agent-1.1.20-arm64.pkg
#
# What it does:
#   1. Stops the existing daemons via launchctl bootout
#   2. Installs the new .pkg via `installer -pkg` (bypasses Gatekeeper
#      because it runs as root + signed pkg has Developer ID Installer)
#   3. Waits for postinstall to bootstrap the new daemons
#   4. Sanity-checks that the new agent process is alive (no crash loop)
#
# Tolerates a clean device too — bootout returns 0 if nothing to stop.

set -eu

PKG="${1:-}"
if [ -z "$PKG" ] || [ ! -f "$PKG" ]; then
  echo "Usage: sudo $0 /path/to/Tracenium-Agent-1.1.20-arm64.pkg" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: must run as root (sudo $0 ...)" >&2
  exit 1
fi

echo "==== Tracenium macOS rescue ===="
echo "  pkg: $PKG"
echo "  size: $(stat -f%z "$PKG" 2>/dev/null || echo "?") bytes"
echo "  sha256: $(shasum -a 256 "$PKG" | awk '{print $1}')"
echo ""

# 1) Stop daemons (idempotent — bootout returns 0 if not loaded)
echo "→ stopping existing daemons (if any)"
/bin/launchctl bootout system/com.certusws.tracenium.agent     2>/dev/null || true
/bin/launchctl bootout system/com.certusws.tracenium.privsvc   2>/dev/null || true
/bin/launchctl bootout system/com.certusws.tracenium.logrotate 2>/dev/null || true

# Also stop the GUI status app if it's running for the console user
CONSOLE_USER="$(/usr/bin/stat -f %Su /dev/console 2>/dev/null || true)"
if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
  CONSOLE_UID="$(/usr/bin/id -u "$CONSOLE_USER" 2>/dev/null || true)"
  if [ -n "$CONSOLE_UID" ]; then
    /bin/launchctl bootout "gui/$CONSOLE_UID/com.certusws.tracenium.agentstatus" 2>/dev/null || true
  fi
fi

# 2) Install — the pkg's postinstall script reboots the daemons
echo ""
echo "→ installing pkg (this runs postinstall which boots daemons)"
/usr/sbin/installer -pkg "$PKG" -target / -verboseR 2>&1 | tail -20

# 3) Wait for postinstall + first heartbeat
echo ""
echo "→ waiting 15s for postinstall + first heartbeat"
sleep 15

# 4) Sanity check — no crash loop, daemon running
echo ""
echo "==== POST-INSTALL STATE ===="
echo "agent service:"
/bin/launchctl print system/com.certusws.tracenium.agent 2>/dev/null \
  | /usr/bin/grep -E "state|successive crashes|pid" \
  | /usr/bin/sed 's/^/  /'

echo ""
echo "privsvc service:"
/bin/launchctl print system/com.certusws.tracenium.privsvc 2>/dev/null \
  | /usr/bin/grep -E "state|successive crashes|pid" \
  | /usr/bin/sed 's/^/  /'

echo ""
echo "running node processes (should see 2: agent-core + privsvc):"
/bin/ps auxww | /usr/bin/grep -E "agent-core\.js|privsvc.*\.js" | /usr/bin/grep -v grep | /usr/bin/sed 's/^/  /'

# Verdict
CRASHES_AGENT=$(/bin/launchctl print system/com.certusws.tracenium.agent 2>/dev/null \
  | /usr/bin/awk -F'= ' '/successive crashes/ {print $2; exit}')
if [ -n "$CRASHES_AGENT" ] && [ "$CRASHES_AGENT" -gt 0 ] 2>/dev/null; then
  echo ""
  echo "⚠️  WARNING: agent has $CRASHES_AGENT successive crashes — check Console.app"
  echo "    or /Library/Application Support/Tracenium/Logs/ for details."
  exit 2
fi

echo ""
echo "✓ Rescue complete. Device should report 1.1.20 to backend within 1-2 min."
echo "  Verify: should appear at version 1.1.20 in the portal."
