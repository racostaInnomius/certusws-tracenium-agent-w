// privsvc/linux/src/agent-install.ts
//
// Handler for `agent.install` — installs an agent self-upgrade package
// (.deb or .rpm) as root.
//
// Why this exists at all (vs the agent invoking dpkg/rpm directly): on
// Linux the agent daemon runs as the unprivileged `tracenium` user
// (see packaging/linux/systemd/tracenium-agent.service:User=tracenium).
// dpkg / apt-get / dnf all require root to install system packages.
// The previous Linux update path in src/update/updater-runner.ts called
// `spawn("/usr/bin/dpkg", ...)` from the agent process itself and the
// kernel immediately rejected it with EPERM — but the spawn() returned
// successfully (the child started, then exited 1), the agent reported
// `{ started: true }` upstream, and the server-side update job ACK'd
// as success. The Ubuntu host stayed on the old version forever while
// the dashboard insisted the update had "started".
//
// privsvc runs as User=root, so this handler can do the install
// directly. Same pattern as `sdp.install` / `patch.install` — both
// already in this module — but specialized for the agent self-upgrade
// flow.
//
// Special concerns for AGENT self-upgrade (vs SDP/patch):
//
//   1. dpkg's postinstall script (packaging/linux/scripts/postinstall.sh)
//      restarts both tracenium-privsvc AND tracenium-agent units on the
//      upgrade path. If dpkg runs as a CHILD of the privsvc process,
//      systemd's KillMode=control-group default would kill dpkg along
//      with privsvc when the unit gets restarted, leaving the install
//      half-complete (the dpkg postinst trigger would never finish).
//
//      Fix: launch dpkg via `systemd-run --scope`, which creates a
//      transient systemd scope that lives OUTSIDE privsvc's cgroup. The
//      scope persists across the privsvc restart and finishes on its
//      own. systemd-run is part of the systemd suite — available on
//      every distro we ship to (Ubuntu, Debian, RHEL/Rocky/Alma, SUSE).
//
//   2. The handler returns "started" immediately and does NOT wait for
//      the install to finish. The agent that called us is about to be
//      restarted by systemd as part of the upgrade — there's nobody to
//      receive a completion response. The orchestrator on the server
//      side confirms success on the agent's next HELLO (new
//      `agentVersion` field matches the requested target version).
//
//   3. Path validation: only accept paths inside /var/lib/tracenium/
//      updates/, which is owned by `tracenium:tracenium` 0750. The
//      agent writes its download there. Refusing anything else
//      prevents a compromised agent from talking us into running
//      /etc/init.d/whatever as root.

import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import { detectFamily } from "./distro";
import { logger } from "./logger";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { DATA_DIR } from "./paths";

// Agent download staging dir, mirrors src/update/update-service.ts where
// the agent writes the .deb/.rpm. We validate that any path the agent
// asks us to install lives under here.
const UPDATES_DIR = path.join(DATA_DIR, "updates");

export async function handleAgentInstall(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const params = req.params || {};
  const packagePath = String(params.path || "");
  const format = String(params.format || "");
  const targetVersion = String(params.version || "");

  // ── Validate path ──────────────────────────────────────────────
  // Defense in depth: the kernel already gates this IPC behind the
  // socket's root:tracenium 0660 mode (only the agent user, who is
  // tracenium, can connect), so we trust the CALLER's identity but
  // not necessarily the CONTENT of the call. A compromised agent (or
  // a future bug in update-task) shouldn't be able to make us install
  // an arbitrary package — refuse anything not in our updates dir.
  const absPath = path.resolve(packagePath);
  const absUpdatesDir = path.resolve(UPDATES_DIR);
  if (!absPath.startsWith(absUpdatesDir + path.sep)) {
    return fail(req.id, "bad_request", `path outside updates dir: ${absPath}`);
  }
  if (!fs.existsSync(absPath)) {
    return fail(req.id, "bad_request", `package not found: ${absPath}`);
  }

  // ── Format ↔ distro family ─────────────────────────────────────
  const distro = detectFamily();
  if (format === "deb" && distro.family !== "debian") {
    return fail(req.id, "format_unsupported", `deb on non-debian (${distro.family})`);
  }
  if (format === "rpm" && distro.family !== "rhel" && distro.family !== "suse") {
    return fail(req.id, "format_unsupported", `rpm on non-rpm family (${distro.family})`);
  }
  if (format !== "deb" && format !== "rpm") {
    return fail(req.id, "format_unsupported", `unknown format: ${format}`);
  }

  // ── Build the install command ───────────────────────────────────
  // For .deb we use `dpkg -i` directly rather than `apt-get install
  // ./<file>.deb` because:
  //   * dpkg is deterministic — it installs the bytes we downloaded
  //     and sha-verified. apt could in theory swap in a "better" file
  //     from cache.
  //   * The agent's .deb has no external deps (we bundle our own node
  //     and better-sqlite3), so apt's dep-resolution adds nothing.
  //   * --force-confold + --force-confdef preserves the operator's
  //     /etc/tracenium/agent.env across upgrades. nfpm marked it as
  //     `type: config|noreplace` so dpkg already knows, but the flags
  //     are belt-and-braces.
  //
  // For .rpm we use `rpm -U` similarly (upgrade, not reinstall).
  // --nodeps because we bundle everything. --force gets us past any
  // residual conflicts from a previous half-failed install.
  let installCmd: string;
  let installArgs: string[];
  if (format === "deb") {
    installCmd = "/usr/bin/dpkg";
    installArgs = ["-E", "--force-confold", "--force-confdef", "-i", absPath];
  } else {
    // format === "rpm"
    installCmd = "/usr/bin/rpm";
    installArgs = ["-U", "--force", "--nodeps", absPath];
  }

  // ── Detach via systemd-run --scope ──────────────────────────────
  // The dpkg/rpm we're about to launch will, via its postinst, ask
  // systemd to restart tracenium-privsvc and tracenium-agent. If we
  // ran the installer as a normal child of THIS process, KillMode=
  // control-group on the privsvc unit would kill the installer
  // mid-postinst when systemd stops the unit. systemd-run --scope
  // creates a transient systemd scope outside our cgroup; the
  // installer continues running there independently of what systemd
  // does to our unit.
  //
  // --collect: clean up the scope record after exit so we don't leak
  //   systemctl-visible units.
  // --quiet: no "Running as unit: ..." line to stdout; we log
  //   ourselves.
  // --slice=system.slice: park the scope at the same hierarchy level
  //   as other system services (default would be the calling user's
  //   slice).
  const scopeUnit = `tracenium-agent-update-${process.pid}-${Date.now()}.scope`;
  const systemdRunArgs = [
    "--scope",
    "--collect",
    "--quiet",
    "--slice=system.slice",
    `--unit=${scopeUnit}`,
    "--",
    installCmd,
    ...installArgs,
  ];

  logger.info("agent_install_start", {
    targetVersion,
    format,
    family: distro.family,
    path: absPath,
    scopeUnit,
  });

  try {
    const child = spawn("/usr/bin/systemd-run", systemdRunArgs, {
      detached: true,
      stdio: "ignore",
      env: {
        ...process.env,
        DEBIAN_FRONTEND: "noninteractive",
        LANG: "C",
        LC_ALL: "C",
      },
    });

    // unref so this process won't keep the event loop alive waiting
    // for the scope. We're "fire and forget" from privsvc's POV —
    // success/failure shows up via the agent's next HELLO carrying the
    // new agentVersion (or failing to, if the install died).
    child.unref();

    logger.info("agent_install_dispatched", {
      targetVersion,
      pid: child.pid,
      scopeUnit,
    });

    return success(req.id, {
      started: true,
      command: installCmd,
      args: installArgs,
      scopeUnit,
    });
  } catch (err: any) {
    logger.error("agent_install_spawn_failed", {
      error: err?.message || String(err),
      targetVersion,
    });
    return fail(req.id, "install_failed", err?.message || String(err));
  }
}
