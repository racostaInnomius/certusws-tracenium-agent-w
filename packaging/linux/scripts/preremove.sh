#!/bin/sh
# packaging/linux/scripts/preremove.sh
#
# Runs BEFORE files are removed. Wired into .deb (prerm) and .rpm
# (%preun) by nfpm.
#
# Argument convention:
#   * .deb prerm: "remove" / "upgrade" / "deconfigure" / "failed-upgrade"
#   * .rpm %preun: 0 (uninstall) / 1 (upgrade)
#
# We need to disable + stop the daemons. On a real uninstall the
# unit files are about to disappear; on an upgrade systemd would
# re-execute the replaced bundle anyway and the stop here gives us
# a clean handoff.
#
# Idempotent — safe regardless of whether services were running.
set -eu

LOG_FILE="/var/log/tracenium-install.log"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
exec >> "$LOG_FILE" 2>&1
echo "==== $(date -u '+%Y-%m-%dT%H:%M:%SZ') tracenium preremove start (arg=${1:-?}) ===="

# Detect whether this is an uninstall vs upgrade. We disable units
# only on real uninstall — on upgrade the .service files will be
# replaced and remain enabled for the new version.
IS_UNINSTALL=0
case "${1:-}" in
    remove|purge)         # .deb uninstall paths
        IS_UNINSTALL=1
        ;;
    0)                    # .rpm uninstall (count of post-install instances = 0)
        IS_UNINSTALL=1
        ;;
    upgrade|deconfigure|failed-upgrade)
        IS_UNINSTALL=0
        ;;
    1)                    # .rpm upgrade
        IS_UNINSTALL=0
        ;;
    *)
        # Unknown argument — be conservative and treat as uninstall
        # so we don't leave orphaned services running.
        IS_UNINSTALL=1
        ;;
esac

if command -v systemctl >/dev/null 2>&1; then
    # Always stop the running services. Stop the agent BEFORE
    # privsvc — the agent has Requires=tracenium-privsvc so
    # systemd would stop them in the right order anyway, but
    # being explicit avoids a noisy "failed to connect to
    # privsvc" log line in the agent's last second of life.
    if systemctl is-active --quiet tracenium-agent.service; then
        systemctl stop tracenium-agent.service || true
        echo "  stopped tracenium-agent"
    fi
    if systemctl is-active --quiet tracenium-privsvc.service; then
        systemctl stop tracenium-privsvc.service || true
        echo "  stopped tracenium-privsvc"
    fi

    if [ "$IS_UNINSTALL" = "1" ]; then
        # Disable so they don't come back at next boot. We don't
        # remove the unit files here — the package manager will
        # delete them as part of the uninstall transaction
        # (postremove confirms). systemctl disable just removes
        # the WantedBy symlinks under /etc/systemd/system/
        # multi-user.target.wants/.
        systemctl disable tracenium-agent.service tracenium-privsvc.service 2>/dev/null || true
        echo "  disabled units (uninstall)"
    fi
fi

echo "==== preremove ok ===="
exit 0
