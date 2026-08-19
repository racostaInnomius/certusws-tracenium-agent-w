#!/bin/sh
# packaging/linux/scripts/postinstall.sh
#
# Runs AFTER files are unpacked. Wired into .deb (postinst) and
# .rpm (%post) by nfpm.
#
# Argument convention differs between formats but we don't care —
# the work here is idempotent on every code path:
#   * .deb postinst args: "configure" $oldver  (install or upgrade)
#                          "abort-upgrade"     (failed upgrade)
#                          "abort-remove"      (failed remove)
#   * .rpm %post arg:     1 (first install) or 2 (upgrade)
#
# Job:
#   1. Set ownership/perms on /etc/tracenium, /var/lib/tracenium,
#      /var/log/tracenium so the agent (user `tracenium`) can read
#      certs and write state without privsvc handing them over.
#   2. Migrate an enrollment token from /tmp into /var/lib/tracenium/
#      if present. The dashboard hands operators a one-time token;
#      they drop it at /tmp/tracenium-enrollment.token before
#      installing the package; we move it where the agent expects
#      to find it.
#   3. Reload + enable + start the systemd units.
set -eu

LOG_FILE="/var/log/tracenium-install.log"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
exec >> "$LOG_FILE" 2>&1
echo "==== $(date -u '+%Y-%m-%dT%H:%M:%SZ') tracenium postinstall start ===="

# ── Directory ownership + perms ────────────────────────────────────
# nfpm creates the directories listed in `contents` with whatever
# perms we declared, but the dpkg/rpm extractor strips ownership
# back to root:root. We re-apply here so the running services can
# read/write what they need.
#
# Intentional layout (also documented in privsvc/linux/src/paths.ts):
#   /etc/tracenium             0755 root:root
#   /etc/tracenium/certs       0750 root:tracenium  (agent reads,
#                                                    privsvc writes)
#   /etc/tracenium/agent.json  0644 root:root       (read-only config)
#   /var/lib/tracenium         0750 tracenium:tracenium
#   /var/log/tracenium         0750 tracenium:tracenium
#
# /run/tracenium is created by systemd at service start via
# RuntimeDirectory= — not our concern here.

# Idempotent: create dirs that may have been removed (dpkg garbage-
# collects empty dirs on `apt remove` even if they were declared
# `type: dir` in the package — common gotcha for /etc/tracenium/certs
# which is empty before first enrollment), then enforce ownership.
mkdir -p /etc/tracenium/certs /var/lib/tracenium /var/lib/tracenium/assets /var/log/tracenium

chmod 0755 /etc/tracenium       2>/dev/null || true
chown root:root /etc/tracenium  2>/dev/null || true

chmod 0750 /etc/tracenium/certs       2>/dev/null || true
chown root:tracenium /etc/tracenium/certs 2>/dev/null || true

chmod 0750 /var/lib/tracenium                          2>/dev/null || true
chown -R tracenium:tracenium /var/lib/tracenium        2>/dev/null || true

chmod 0750 /var/log/tracenium                          2>/dev/null || true
chown -R tracenium:tracenium /var/log/tracenium        2>/dev/null || true

# ── Enrollment token migration ─────────────────────────────────────
# Operators obtain a one-time enrollment JWT from the dashboard,
# drop it at /tmp/tracenium-enrollment.token, then install the
# package. preinstall.sh enforces presence on fresh installs —
# upgrades may not have a fresh token, the existing enrollment
# in /var/lib/tracenium/ + installed cert provide continuity.
#
# The agent's bootstrap code (src/bootstrap/token-source.ts) looks
# for the token at /var/lib/tracenium/enrollment.token — we move
# it from /tmp into place + chown it so the agent can read.
#
# After successful enrollment the agent itself unlinks the token
# (one-shot credential, never persisted on disk longer than needed).
TMP_TOKEN="/tmp/tracenium-enrollment.token"
DST_TOKEN="/var/lib/tracenium/enrollment.token"

if [ -f "$TMP_TOKEN" ]; then
    # Move (not copy) so the bearer credential doesn't linger in
    # /tmp where any local user could read it. mv is atomic on the
    # same filesystem — /tmp and /var/lib are typically both ext4
    # or btrfs on the same disk on a normal install.
    mv "$TMP_TOKEN" "$DST_TOKEN"
    chmod 0600 "$DST_TOKEN" || true
    chown tracenium:tracenium "$DST_TOKEN" || true
    echo "  migrated enrollment token from /tmp"
elif [ ! -f "$DST_TOKEN" ] && [ ! -f /etc/tracenium/certs/client.crt.pem ]; then
    # No /tmp token AND no prior enrollment — preinstall should have
    # caught this on a fresh install. We're here only if preinstall
    # was bypassed (e.g. dpkg --no-triggers). Loud warning + the
    # services will still start but agent won't connect.
    echo "  WARNING: no enrollment token AND no prior cert — agent will not connect until enrollment is provided"
fi

# ── Phase 10 hardening — AppArmor + SELinux ────────────────────────
# Both checks are best-effort: a host that lacks the dev tools just
# skips the load step. The packaging files end up on disk either way,
# so a manual operator run later (after installing the dev tools)
# completes the load without re-installing the package.

# AppArmor (Debian/Ubuntu).
#
# ⚠️ EL OPT-IN QUE HABIA AQUI ERA FICTICIO. Este script no cargaba el
# perfil salvo TRACENIUM_LOAD_APPARMOR=1, en la creencia de que asi no
# se aplicaba. Pero `apparmor.service` viene enabled en Debian/Ubuntu y
# su ExecStart es `/lib/apparmor/apparmor.systemd reload`, que carga
# TODO lo que haya en /etc/apparmor.d/. Dejar el fichero ahi ya basta
# para que el perfil se aplique desde el primer reboot.
#
# O sea que no cargarlo aqui no evitaba nada: solo aplazaba el efecto
# hasta un reinicio cualquiera, cuando ya nadie lo relaciona con la
# instalacion. Asi llego el deadlock que congelo SRVOC-MainAgent cuatro
# dias en 1.1.35 — nadie habia puesto la variable, y el perfil estaba
# enforcing igual.
#
# Ahora el perfil se envia en modo COMPLAIN (registra, no bloquea), asi
# que cargarlo es seguro y ademas deja el host en un estado
# DETERMINISTA desde la instalacion en vez de uno que cambia solo en el
# proximo arranque.
#
# Para recoger lo que se denegaria en este host:
#   sudo journalctl -k | grep 'apparmor="ALLOWED"' | grep tracenium
#
# Opt-out REAL: borrar el fichero es lo unico que impide la carga en
# boot, asi que eso es lo que hace la variable.
if [ "${TRACENIUM_SKIP_APPARMOR:-0}" = "1" ]; then
    rm -f /etc/apparmor.d/usr.lib.tracenium.privsvc
    echo "  AppArmor profile REMOVED (TRACENIUM_SKIP_APPARMOR=1) — no se cargara en boot"
elif command -v apparmor_parser >/dev/null 2>&1 \
     && [ -f /etc/apparmor.d/usr.lib.tracenium.privsvc ]; then
    if apparmor_parser -r /etc/apparmor.d/usr.lib.tracenium.privsvc 2>/dev/null; then
        echo "  AppArmor profile loaded in COMPLAIN mode (registra, no bloquea)"
    else
        # No abortar: un perfil que no carga deja el host sin confinamiento,
        # que es exactamente el estado en el que ha vivido hasta ahora.
        echo "  AppArmor profile load failed (continuing)"
    fi
else
    echo "  AppArmor profile installed; apparmor_parser ausente, se cargara en el proximo boot"
fi

# SELinux (RHEL-family). `semodule` is in `policycoreutils`
# (always present on RHEL with SELinux enabled) but compiling our
# .te → .pp needs `selinux-policy-devel` which isn't always
# pre-installed. We probe for both.
if command -v semodule >/dev/null 2>&1 && [ -f /usr/share/selinux/devel/Makefile ]; then
    if [ -f /usr/share/tracenium/selinux/tracenium.te ]; then
        # Compile + load in a temp workdir so the .pp + .mod
        # artifacts don't pollute the install dir.
        SE_WORK=$(mktemp -d)
        cp /usr/share/tracenium/selinux/tracenium.te /usr/share/tracenium/selinux/tracenium.fc "$SE_WORK/" 2>/dev/null || true
        if (cd "$SE_WORK" && make -f /usr/share/selinux/devel/Makefile tracenium.pp >/dev/null 2>&1); then
            if semodule -i "$SE_WORK/tracenium.pp" 2>/dev/null; then
                # Apply the labels from tracenium.fc to existing files.
                restorecon -RF /etc/tracenium /var/lib/tracenium /var/log/tracenium /run/tracenium 2>/dev/null || true
                echo "  SELinux module loaded"
            else
                echo "  SELinux module install failed (continuing)"
            fi
        else
            echo "  SELinux module compile failed (continuing — selinux-policy-devel may need updating)"
        fi
        rm -rf "$SE_WORK"
    fi
elif command -v getenforce >/dev/null 2>&1; then
    # SELinux is enabled but selinux-policy-devel isn't installed.
    # Common on Rocky/Alma minimal images. The daemon still runs
    # under init_t (default for systemd-spawned services) and our
    # cert/data dirs end up unlabelled — works, just no fine-grained
    # confinement.
    echo "  SELinux detected but selinux-policy-devel missing — skipping module load"
fi

# ── systemd lifecycle ──────────────────────────────────────────────
# daemon-reload picks up the new unit files. Then enable so the
# services come back after reboot. Then start now.
#
# `--no-block` on start is intentional: postinstall must complete
# even if the agent's first connect attempt is slow (DNS, TLS,
# enrollment REST round trip). Holding the package transaction open
# for tens of seconds while the daemon bootstraps would make
# `apt install` feel broken.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true

    # Mask + unmask trick to clear any "masked" state from a
    # previous failed install. Idempotent if the unit wasn't
    # masked.
    systemctl unmask tracenium-privsvc.service tracenium-agent.service 2>/dev/null || true

    systemctl enable tracenium-privsvc.service tracenium-agent.service || true

    # ── Restart running services to pick up the new binaries ─────
    # `try-restart` is the load-bearing call for the UPGRADE case:
    #   * If the unit is running → systemd stops + starts it, so the
    #     daemon loads the new agent-core.js / privsvc.js we just
    #     unpacked. Without this, the previous (old-version) daemon
    #     keeps running in memory and the agent reports the OLD
    #     `agentVersion` indefinitely. We observed exactly that
    #     against the Ubuntu host: package upgraded on disk, agent
    #     stayed on 1.1.13 because nothing was restarted.
    #   * If the unit is NOT running (fresh install) → no-op. The
    #     `start` below brings them up for the first time.
    #
    # Order matters: privsvc first (agent has Requires= privsvc,
    # so systemd would restart the agent anyway when privsvc
    # restarts, but doing privsvc explicitly first keeps the boot
    # ordering visible in journald and avoids a brief window where
    # the agent's IPC client retries against a missing socket).
    #
    # This runs from inside an agent-upgrade dpkg postinstall, but
    # dpkg itself was launched by `systemd-run --scope` (see
    # privsvc/linux/src/agent-install.ts) so it lives in a transient
    # scope OUTSIDE both unit cgroups. systemd killing privsvc /
    # agent doesn't reach us — try-restart is safe even though
    # we're restarting the very service whose IPC initiated the
    # install.
    systemctl try-restart tracenium-privsvc.service 2>/dev/null || true
    systemctl try-restart tracenium-agent.service   2>/dev/null || true

    # Fresh install path: `start` is no-op if the unit is already
    # active after try-restart. `--no-block` so the package
    # transaction doesn't hold open waiting for DNS / TLS /
    # enrollment REST during the agent's first connect attempt.
    systemctl start --no-block tracenium-privsvc.service || true
    systemctl start --no-block tracenium-agent.service || true

    echo "  systemd units enabled + (re)started"
else
    echo "  WARNING: systemctl not found — services will not auto-start. This system uses a non-systemd init."
fi

echo "==== postinstall ok ===="
exit 0
