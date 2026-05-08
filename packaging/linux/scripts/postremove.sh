#!/bin/sh
# packaging/linux/scripts/postremove.sh
#
# Runs AFTER files are removed. Wired into .deb (postrm) and .rpm
# (%postun) by nfpm.
#
# Argument convention:
#   * .deb postrm: "remove" / "purge" / "upgrade" / ...
#   * .rpm %postun: 0 (uninstall) / 1 (upgrade)
#
# Job:
#   1. systemctl daemon-reload so systemd forgets the now-gone
#      unit files cleanly.
#   2. On `purge` (Debian) or final uninstall: optionally remove
#      the `tracenium` user/group. We DON'T remove /etc/tracenium
#      or /var/lib/tracenium — those hold mTLS certs and the
#      enrollment record, and a customer who reinstalls within
#      minutes shouldn't have to re-enroll. Real "wipe" cleanup
#      is the operator's responsibility (`rm -rf /etc/tracenium
#      /var/lib/tracenium`); the package manager doesn't do it
#      automatically because it's destructive.
#
# Idempotent — safe regardless of state.
set -eu

LOG_FILE="/var/log/tracenium-install.log"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
exec >> "$LOG_FILE" 2>&1
echo "==== $(date -u '+%Y-%m-%dT%H:%M:%SZ') tracenium postremove start (arg=${1:-?}) ===="

# Was this a real uninstall, or just an upgrade?
IS_PURGE=0
IS_UNINSTALL=0
case "${1:-}" in
    purge)        # .deb purge — config files removed
        IS_PURGE=1
        IS_UNINSTALL=1
        ;;
    remove)       # .deb remove — config files preserved
        IS_UNINSTALL=1
        ;;
    0)            # .rpm uninstall
        IS_UNINSTALL=1
        ;;
    upgrade|failed-upgrade|abort-install|abort-upgrade|disappear)
        IS_UNINSTALL=0
        ;;
    1)            # .rpm upgrade
        IS_UNINSTALL=0
        ;;
    *)
        IS_UNINSTALL=1
        ;;
esac

# daemon-reload always — even on upgrade, where the new unit files
# may have changed shape, systemd needs to re-read them.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    # systemd >=230 has reset-failed which clears stuck "failed"
    # state from a unit that crashed during the previous version.
    systemctl reset-failed tracenium-agent.service tracenium-privsvc.service 2>/dev/null || true
fi

# On Debian `purge` we can clean up the tracenium user. We
# deliberately do NOT delete /var/lib/tracenium or /etc/tracenium
# even on purge — those contain the enrollment record + private
# key. A reinstall within the same day is a common scenario (we
# pushed a bad version, operator rolls back, agent should reuse
# its identity). If the operator genuinely wants to wipe, they
# remove those dirs themselves.
#
# Why not also do this on rpm uninstall? RPM doesn't have a
# "purge" notion — every uninstall is the equivalent of `apt
# remove`, not `apt purge`. So the convention there is "user
# decides whether to clean up users". We match the Debian
# behaviour: purge is destructive-but-limited; remove is
# minimum-impact.
if [ "$IS_PURGE" = "1" ]; then
    # Don't fail purge if the user/group doesn't exist or is
    # still referenced. userdel returns 8 ("user is currently
    # logged in") in some edge cases — we ignore.
    if getent passwd tracenium >/dev/null; then
        userdel tracenium 2>/dev/null || true
        echo "  removed user tracenium"
    fi
    if getent group tracenium >/dev/null; then
        groupdel tracenium 2>/dev/null || true
        echo "  removed group tracenium"
    fi
fi

if [ "$IS_UNINSTALL" = "1" ]; then
    # Phase 10 hardening — best-effort module unload. Failures
    # silenced because the parsers/tools may have been removed
    # before us in a sweeping uninstall (e.g. `apt purge apparmor`
    # ran first); the orphan files we leave behind are inert.
    if command -v apparmor_parser >/dev/null 2>&1; then
        apparmor_parser -R /etc/apparmor.d/usr.lib.tracenium.privsvc 2>/dev/null || true
    fi
    if command -v semodule >/dev/null 2>&1; then
        semodule -r tracenium 2>/dev/null || true
    fi

    echo "  uninstall complete; preserved /etc/tracenium and /var/lib/tracenium"
    echo "  (delete those manually for a complete wipe)"
fi

echo "==== postremove ok ===="
exit 0
