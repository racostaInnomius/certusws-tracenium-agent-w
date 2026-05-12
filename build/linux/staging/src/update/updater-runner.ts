// src/update/updater-runner.ts

import { spawn } from "child_process";
import fs from "fs";
import type { RunUpdateResult } from "./update-types";
import { updateUpdateState } from "./update-state";
import { detectFamily } from "../platform/linux/distro";

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

// ── Phase 10 — Linux OTA self-update ─────────────────────────────
//
// Same shape as the Mac/Windows runners: detached, capture stdio
// best-effort, return immediately. The .deb/.rpm postinstall
// scripts (Phase 4) call `systemctl restart` on both daemons,
// which sends SIGTERM to the parent agent process mid-install —
// we never observe the exit event on the happy path. On failure
// we capture exit code + stderr so the next agent boot reports
// the real reason.
//
// Why bypass apt/dnf and use bare `dpkg -i` / `rpm -U`:
//   * apt-get install <file.deb> resolves deps from the customer's
//     repo set. If the customer pinned a transitive dep we need to
//     a different version than the new agent expects, the apt
//     resolver might decline. dpkg -i ignores deps; we ship the
//     bundled node + better-sqlite3 inside the package, so we have
//     no external runtime deps to satisfy. Same for rpm -U.
//   * Avoids a network round-trip to the customer repo on every
//     self-update — agent should remain functional even if the
//     customer's apt/dnf repos are unreachable.
//   * Deterministic: dpkg/rpm run the same .deb/.rpm bytes we
//     downloaded + sha-verified. apt/dnf could in theory swap in
//     a "better" file from cache.
//
// The downside is that if a future package release introduces a
// real external dep (unlikely — we go to lengths to avoid that),
// dpkg -i would fail with "Errors were encountered while processing".
// We catch that explicitly and surface as install_failed; the
// agent keeps running on the old version, the dashboard sees the
// failure on the next heartbeat.

export function runLinuxDebUpdate(debPath: string): RunUpdateResult {
  if (!fs.existsSync(debPath)) {
    throw new Error(`deb_not_found: ${debPath}`);
  }

  // -E: don't reinstall the same version (idempotent on a no-op
  // metadata-only refresh).
  // --force-confold + --force-confdef: keep operator-edited
  // /etc/tracenium/agent.json across upgrades. Same flags Phase 7
  // patch-install uses.
  const args = [
    "-E",
    "--force-confold",
    "--force-confdef",
    "-i",
    debPath,
  ];

  try {
    const child = spawn("/usr/bin/dpkg", args, {
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, DEBIAN_FRONTEND: "noninteractive", LANG: "C", LC_ALL: "C" },
    });

    captureChildExit(child, debPath, "dpkg");
    child.unref();

    console.log("[update] linux dpkg launched", {
      path: debPath,
      pid: child.pid,
    });

    return {
      started: true,
      command: "/usr/bin/dpkg",
      args,
    };
  } catch (err: any) {
    console.error("[update] failed to start dpkg", {
      error: err?.message || err,
      path: debPath,
    });
    throw err;
  }
}

export function runLinuxRpmUpdate(rpmPath: string): RunUpdateResult {
  if (!fs.existsSync(rpmPath)) {
    throw new Error(`rpm_not_found: ${rpmPath}`);
  }

  // -U: upgrade if installed, install if not. --force gets us past
  // package-name conflicts on a re-install. --nodeps because we
  // bundle our own runtime — see the design comment above on why
  // we deliberately skip dep resolution here.
  const args = [
    "-U",
    "--force",
    "--nodeps",
    rpmPath,
  ];

  try {
    const child = spawn("/usr/bin/rpm", args, {
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, LANG: "C", LC_ALL: "C" },
    });

    captureChildExit(child, rpmPath, "rpm");
    child.unref();

    console.log("[update] linux rpm launched", {
      path: rpmPath,
      pid: child.pid,
    });

    return {
      started: true,
      command: "/usr/bin/rpm",
      args,
    };
  } catch (err: any) {
    console.error("[update] failed to start rpm", {
      error: err?.message || err,
      path: rpmPath,
    });
    throw err;
  }
}

// Helper — same exit/error capture pattern as runMacosPkgUpdate.
function captureChildExit(child: ReturnType<typeof spawn>, packagePath: string, tool: string) {
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
    console.error(`[update] ${tool} spawn error`, {
      error: err?.message || err,
      path: packagePath,
    });
    try {
      updateUpdateState({
        updateInProgress: false,
        status: "failed",
        lastError: `${tool}_spawn_error: ${err?.message || err}`,
      });
    } catch {}
  });

  child.on("exit", (code, signal) => {
    const stderr = Buffer.concat(stderrChunks).toString("utf8").trim();
    const stdout = Buffer.concat(stdoutChunks).toString("utf8").trim();

    if (code === 0) {
      // Postinstall ran systemctl restart and we're either dead
      // (SIGTERM mid-process) or this is a no-op upgrade. Either
      // way, success.
      console.log(`[update] ${tool} exited cleanly`, { code, pid: child.pid });
    } else {
      console.error(`[update] ${tool} FAILED`, {
        code,
        signal,
        pid: child.pid,
        stdoutTail: stdout.slice(-500),
        stderrTail: stderr.slice(-500),
      });
      try {
        updateUpdateState({
          updateInProgress: false,
          status: "failed",
          lastError: `${tool}_exit_${code ?? signal ?? "unknown"}: ${(stderr || stdout).slice(0, 300)}`,
        });
      } catch {}
    }
  });
}

// Dispatch helper for the update-service: pick the right runner by
// distro family. Called from performLinuxUpdate.
export function runLinuxUpdate(packagePath: string): RunUpdateResult {
  const distro = detectFamily();
  if (distro.family === "debian") {
    return runLinuxDebUpdate(packagePath);
  }
  if (distro.family === "rhel" || distro.family === "suse") {
    return runLinuxRpmUpdate(packagePath);
  }
  throw new Error(`linux_update_unsupported_family: ${distro.family}`);
}
