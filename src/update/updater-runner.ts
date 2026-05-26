// src/update/updater-runner.ts

import { spawn } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import type { RunUpdateResult } from "./update-types";
import { updateUpdateState } from "./update-state";

export function runWindowsMsiUpdate(msiPath: string): RunUpdateResult {
  if (!fs.existsSync(msiPath)) {
    throw new Error(`msi_not_found: ${msiPath}`);
  }

  // ── Why we don't `spawn("msiexec", ...)` directly ─────────────────
  // The agent runs as a Windows Service under LocalSystem via WinSW.
  // Windows wraps the service's processes in a Job Object. If we spawn
  // msiexec as a CHILD of this process, msiexec lives inside the same
  // Job Object. The MSI itself then issues a STOP_SIGNAL to the
  // TraceniumAgentCore service so it can replace node.exe and the .dll
  // payload — but stopping the service tears down the Job Object,
  // which KILLS our msiexec child mid-install. Result: half-applied
  // install, files in inconsistent state, agent stuck on the prior
  // version forever (saw this on ETE-3X5P8F4 + TNS-OPER-SNOC04 in
  // 1.1.14 → 1.1.19 rollout — exact mirror of the pre-0655a70 Linux
  // bug where dpkg got killed by systemd's cgroup tear-down).
  //
  // The Linux fix uses `systemd-run --scope` to launch dpkg outside
  // privsvc's cgroup. The Windows equivalent is to schedule a one-shot
  // Task Scheduler task that runs msiexec under the Task Scheduler's
  // own job hierarchy — completely independent of our service's Job
  // Object. We give it a small delay so the agent has time to
  // gracefully exit before msiexec starts hammering the install dir.
  //
  // schtasks is part of Windows since Vista. The /f flag overwrites
  // any prior task with the same name (e.g. from a previous failed
  // attempt). /ru SYSTEM grants the task LocalSystem privileges
  // without needing a password. Task auto-deletes after running via
  // /z + /sd /ed combo (we set ed = now + 1 hour as the cutoff).

  // 1. Write a tiny .cmd shim that:
  //    - waits 10 seconds (gives the agent time to be stopped cleanly)
  //    - runs msiexec
  //    - deletes itself afterwards
  // Using a shim instead of inlining the command in /tr keeps quoting
  // sane for paths with spaces (Program Files, etc.).
  const shimPath = path.join(
    os.tmpdir(),
    `tracenium-update-${Date.now()}-${process.pid}.cmd`
  );
  const shimContents = [
    "@echo off",
    "rem One-shot update launcher — see updater-runner.ts header for rationale.",
    "timeout /t 10 /nobreak >nul",
    `msiexec.exe /i "${msiPath}" /qn /norestart`,
    "set MSIEXEC_RC=%ERRORLEVEL%",
    "rem self-delete after run",
    `del /q "%~f0"`,
    "exit /b %MSIEXEC_RC%"
  ].join("\r\n");

  try {
    fs.writeFileSync(shimPath, shimContents, "utf8");
  } catch (err: any) {
    throw new Error(`update_shim_write_failed: ${err?.message || err}`);
  }

  // 2. Compute "start in 30 seconds" for the schtasks /st HH:MM time.
  // schtasks accepts HH:mm only (no seconds), so we round up.
  const startAt = new Date(Date.now() + 60_000);
  const hh = String(startAt.getHours()).padStart(2, "0");
  const mm = String(startAt.getMinutes()).padStart(2, "0");
  const startTime = `${hh}:${mm}`;

  const taskName = `TraceniumAgentUpdate_${Date.now()}`;
  const schArgs = [
    "/create",
    "/tn", taskName,
    "/tr", shimPath,
    "/sc", "ONCE",
    "/st", startTime,
    "/ru", "SYSTEM",
    "/rl", "HIGHEST",
    "/f"
  ];

  try {
    const child = spawn("schtasks.exe", schArgs, {
      detached: true,
      stdio: "ignore",
      windowsHide: true
    });

    child.on("error", (err) => {
      console.error("[update] schtasks spawn error", {
        error: err?.message || err,
        taskName,
        shimPath
      });
    });

    child.unref();

    console.log("[update] scheduled msiexec via Task Scheduler", {
      taskName,
      startTime,
      shimPath,
      msiPath
    });

    return {
      started: true,
      command: "schtasks.exe",
      args: schArgs
    };
  } catch (err: any) {
    console.error("[update] failed to create scheduled update task", {
      error: err?.message || err,
      msiPath
    });
    // Don't leave a leaked shim file behind.
    try { fs.unlinkSync(shimPath); } catch {}
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
