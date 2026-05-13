// src/update/updater-runner.ts

import { spawn } from "child_process";
import fs from "fs";
import type { RunUpdateResult } from "./update-types";
import { updateUpdateState } from "./update-state";

export function runWindowsMsiUpdate(msiPath: string): RunUpdateResult {
  if (!fs.existsSync(msiPath)) {
    throw new Error(`msi_not_found: ${msiPath}`);
  }

  const args = ["/i", msiPath, "/qn", "/norestart"];

  try {
    const child = spawn("msiexec", args, {
      detached: true,
      stdio: "ignore",
      windowsHide: true
    });

    child.on("error", (err) => {
      console.error("[update] msiexec spawn error", {
        error: err?.message || err,
        path: msiPath
      });
    });

    child.unref();

    console.log("[update] msiexec launched", {
      path: msiPath,
      pid: child.pid
    });

    return {
      started: true,
      command: "msiexec",
      args
    };
  } catch (err: any) {
    console.error("[update] failed to start msiexec", {
      error: err?.message || err,
      path: msiPath
    });

    throw err;
  }
}

export function runMacosPkgUpdate(pkgPath: string): RunUpdateResult {
  if (!fs.existsSync(pkgPath)) {
    throw new Error(`pkg_not_found: ${pkgPath}`);
  }

  const args = ["-pkg", pkgPath, "-target", "/"];

  try {
    // stdio: pipe so we can capture installer output for diagnostics.
    // On success the postinstall kickstarts the daemon and this parent
    // process is killed — we never observe the exit event. On failure
    // (bad pkg, bad signature, disk full, etc.) the installer exits
    // with non-zero BEFORE the postinstall runs, we see the exit event,
    // persist `install_failed`, and the backend will surface the error
    // on the next heartbeat instead of silently believing success.
    const child = spawn("/usr/sbin/installer", args, {
      detached: true,
      stdio: ["ignore", "pipe", "pipe"]
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    const MAX_CAPTURE_BYTES = 16 * 1024;
    let capturedBytes = 0;

    const capture = (store: Buffer[]) => (chunk: Buffer) => {
      if (capturedBytes >= MAX_CAPTURE_BYTES) return;
      const remaining = MAX_CAPTURE_BYTES - capturedBytes;
      const slice = chunk.length > remaining ? chunk.slice(0, remaining) : chunk;
      store.push(slice);
      capturedBytes += slice.length;
    };

    child.stdout?.on("data", capture(stdoutChunks));
    child.stderr?.on("data", capture(stderrChunks));

    child.on("error", (err) => {
      console.error("[update] installer spawn error", {
        error: err?.message || err,
        path: pkgPath
      });
      try {
        updateUpdateState({
          updateInProgress: false,
          status: "failed",
          lastError: `installer_spawn_error: ${err?.message || err}`
        });
      } catch {}
    });

    child.on("exit", (code, signal) => {
      const stderr = Buffer.concat(stderrChunks).toString("utf8").trim();
      const stdout = Buffer.concat(stdoutChunks).toString("utf8").trim();

      if (code === 0) {
        // If we're still alive to see this, the postinstall either didn't
        // run yet or the pkg was a no-op. The next startup will reconcile.
        console.log("[update] installer exited cleanly", { code, pid: child.pid });
      } else {
        console.error("[update] installer FAILED", {
          code,
          signal,
          pid: child.pid,
          stdoutTail: stdout.slice(-500),
          stderrTail: stderr.slice(-500)
        });
        try {
          updateUpdateState({
            updateInProgress: false,
            status: "failed",
            lastError: `installer_exit_${code ?? signal ?? "unknown"}: ${(stderr || stdout).slice(0, 300)}`
          });
        } catch {}
      }
    });

    child.unref();

    console.log("[update] macOS installer launched", {
      path: pkgPath,
      pid: child.pid
    });

    return {
      started: true,
      command: "/usr/sbin/installer",
      args
    };
  } catch (err: any) {
    console.error("[update] failed to start macOS installer", {
      error: err?.message || err,
      path: pkgPath
    });

    throw err;
  }
}

// ── Linux self-update is handled by privsvc ──────────────────────
//
// The previous implementation lived here and spawned `dpkg -i` /
// `rpm -U` directly from the agent process. That doesn't work: the
// agent daemon runs as the unprivileged `tracenium` user (per
// packaging/linux/systemd/tracenium-agent.service), and dpkg/rpm need
// root. The previous code spawned detached + unref'd, which masked
// the EPERM exit — the agent reported `{ started: true }` to the
// orchestrator, the dashboard saw an ACK, and the host stayed on the
// old version forever.
//
// The Linux install path now goes through privsvc's `agent.install`
// IPC method (privsvc/linux/src/agent-install.ts). privsvc runs as
// root, so it can shell out to dpkg/rpm — and it launches them via
// `systemd-run --scope` so the install survives the postinstall's
// `systemctl try-restart` of privsvc itself. See update-service.ts's
// `performLinuxUpdate` for the call site.
