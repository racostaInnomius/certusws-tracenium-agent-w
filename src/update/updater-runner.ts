// src/update/updater-runner.ts

import { spawn } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import type { RunUpdateResult } from "./update-types";
import { updateUpdateState } from "./update-state";

/** How long a shim has to be untouched before we consider it abandoned. */
const SHIM_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * Delete update shims left by earlier runs.
 *
 * Best-effort by design: a shim we cannot remove is litter in %TEMP%, not a
 * reason to abandon an update. The age guard keeps us off a shim that a task
 * scheduled a minute ago is about to execute — the schtasks start time has
 * minute granularity, so "written recently" and "already running" overlap.
 */
function purgeOldShims(now: number = Date.now()): void {
  const dir = os.tmpdir();
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return;
  }

  for (const name of names) {
    if (!name.startsWith("tracenium-update-") || !name.endsWith(".cmd")) continue;
    const full = path.join(dir, name);
    try {
      if (now - fs.statSync(full).mtimeMs < SHIM_MAX_AGE_MS) continue;
      fs.unlinkSync(full);
    } catch {
      // Locked, already gone, or not ours to delete. Leave it.
    }
  }
}

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
  // 1.1.14 → 1.1.21 rollout — exact mirror of the pre-0655a70 Linux
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

  // Shims from previous updates. They used to delete themselves, which is
  // exactly what broke the exit code (see the shim below), so cleanup moved
  // here: the NEXT update sweeps the last one's leftovers, and nothing has to
  // delete a file it is currently executing.
  purgeOldShims();

  // 1. Write a tiny .cmd shim that:
  //    - waits 10 seconds (gives the agent time to be stopped cleanly)
  //    - runs msiexec
  //    - removes the one-shot task it was launched from
  // Using a shim instead of inlining the command in /tr keeps quoting
  // sane for paths with spaces (Program Files, etc.).
  const shimPath = path.join(
    os.tmpdir(),
    `tracenium-update-${Date.now()}-${process.pid}.cmd`
  );

  // Compute "start in ~1 minute" for the schtasks /st HH:MM time.
  // schtasks accepts HH:mm only (no seconds), so we round up.
  const startAt = new Date(Date.now() + 60_000);
  const hh = String(startAt.getHours()).padStart(2, "0");
  const mm = String(startAt.getMinutes()).padStart(2, "0");
  const startTime = `${hh}:${mm}`;

  // Named before the shim is written: the shim deletes this task by name.
  const taskName = `TraceniumAgentUpdate_${Date.now()}`;

  const shimContents = [
    "@echo off",
    "rem One-shot update launcher — see updater-runner.ts header for rationale.",
    "rem",
    "rem `timeout` is NOT used here. It reads the console input handle, and a",
    "rem task running as SYSTEM with no interactive session has none: it aborts",
    "rem instantly with \"Input redirection is not supported\". The 10-second",
    "rem grace period this design depends on — letting the agent exit before",
    "rem msiexec starts hammering the install dir — therefore never happened.",
    "rem `ping` is the portable console-free sleep: -n 11 waits ~10s.",
    "ping -n 11 127.0.0.1 >nul",
    `msiexec.exe /i "${msiPath}" /qn /norestart`,
    "set MSIEXEC_RC=%ERRORLEVEL%",
    "rem Remove the one-shot task. The header of this file used to claim that",
    "rem `/z /sd /ed` did this, but those flags were never passed — so every",
    "rem update left a scheduled task behind, permanently, on every endpoint",
    "rem (4 of them found on one host, 2026-08-14).",
    `schtasks.exe /delete /tn "${taskName}" /f >nul 2>&1`,
    "rem NOTE: this shim deliberately does NOT delete itself. `del \"%~f0\"` on",
    "rem the running .cmd makes cmd.exe fail to read the next line, so the",
    "rem `exit /b` below never ran and Task Scheduler recorded LastResult 1 on",
    "rem installs that had in fact succeeded (all three on 2026-08-13, against",
    "rem an Event Log saying \"status: 0\"). That cost us the only signal we had",
    "rem for whether an update worked. The next run purges it instead.",
    "exit /b %MSIEXEC_RC%"
  ].join("\r\n");

  try {
    fs.writeFileSync(shimPath, shimContents, "utf8");
  } catch (err: any) {
    throw new Error(`update_shim_write_failed: ${err?.message || err}`);
  }
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
