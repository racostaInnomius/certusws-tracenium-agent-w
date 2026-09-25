// src/update/updater-runner.ts

import { spawn, spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import type { RunUpdateResult } from "./update-types";
import { updateUpdateState } from "./update-state";
import { agentDataDir } from "../bootstrap/paths";

/** How long a shim has to be untouched before we consider it abandoned. */
const SHIM_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * How long a task that could not start keeps trying. After that it expires
 * and Task Scheduler deletes it (DeleteExpiredTaskAfter): a missed update is
 * retried by the agent with a fresh task, never by a stale one days later.
 */
const TASK_WINDOW_MS = 24 * 60 * 60 * 1000;

/** `2026-09-25T11:10:16` in the machine's local time — what StartBoundary expects. */
export function localIsoSeconds(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}` +
    `T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
  );
}

const xmlText = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/**
 * The update task, as Task Scheduler XML.
 *
 * 🔴 W11_JPR_LAB (Latitude 5400) sat on 1.1.77 through four update jobs
 * (2026-09-24/25). The agent created every task and acked `update_started`,
 * and none of them ever ran: `schtasks /query` showed Last Run Time
 * 11/30/1999, Last Result 267011 (SCHED_S_TASK_HAS_NOT_RUN), Power
 * Management "Stop On Battery Mode, No Start On Batteries". That is what
 * `schtasks /create /sc ONCE` gives a task by default, and there is no
 * command-line flag to change it — hence the XML. Older tasks on the same
 * host had ended in 0x800710E0, the scheduler refusing to start them.
 *
 * What each setting is for:
 *  - DisallowStartIfOnBatteries=false: a laptop on battery updates. A battery
 *    that is nearly flat is caught before this, in battery-gate.ts, where the
 *    deferral can be reported.
 *  - StopIfGoingOnBatteries=false: unplugging mid-install used to KILL the
 *    task — msiexec with the services stopped and the files half-replaced.
 *  - StartWhenAvailable=true: a start missed while asleep runs on wake.
 *  - EndBoundary + DeleteExpiredTaskAfter: a task that never ran cleans
 *    itself up. The same host had 27 of them, back to May.
 *  - S-1-5-18 + HighestAvailable: LocalSystem, as `/ru SYSTEM /rl HIGHEST`.
 */
export function buildUpdateTaskXml(opts: { shimPath: string; startAt: Date; endAt: Date }): string {
  return [
    `<?xml version="1.0" encoding="UTF-16"?>`,
    `<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">`,
    `  <RegistrationInfo>`,
    `    <Description>Tracenium agent self-update (one-shot).</Description>`,
    `  </RegistrationInfo>`,
    `  <Triggers>`,
    `    <TimeTrigger>`,
    `      <StartBoundary>${localIsoSeconds(opts.startAt)}</StartBoundary>`,
    `      <EndBoundary>${localIsoSeconds(opts.endAt)}</EndBoundary>`,
    `      <Enabled>true</Enabled>`,
    `    </TimeTrigger>`,
    `  </Triggers>`,
    `  <Principals>`,
    `    <Principal id="Author">`,
    `      <UserId>S-1-5-18</UserId>`,
    `      <RunLevel>HighestAvailable</RunLevel>`,
    `    </Principal>`,
    `  </Principals>`,
    `  <Settings>`,
    `    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>`,
    `    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>`,
    `    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>`,
    `    <AllowHardTerminate>true</AllowHardTerminate>`,
    `    <StartWhenAvailable>true</StartWhenAvailable>`,
    `    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>`,
    `    <IdleSettings>`,
    `      <StopOnIdleEnd>false</StopOnIdleEnd>`,
    `      <RestartOnIdle>false</RestartOnIdle>`,
    `    </IdleSettings>`,
    `    <AllowStartOnDemand>true</AllowStartOnDemand>`,
    `    <Enabled>true</Enabled>`,
    `    <Hidden>false</Hidden>`,
    `    <RunOnlyIfIdle>false</RunOnlyIfIdle>`,
    `    <WakeToRun>false</WakeToRun>`,
    `    <DeleteExpiredTaskAfter>PT1H</DeleteExpiredTaskAfter>`,
    `    <Priority>7</Priority>`,
    `  </Settings>`,
    `  <Actions Context="Author">`,
    `    <Exec>`,
    `      <Command>${xmlText(opts.shimPath)}</Command>`,
    `    </Exec>`,
    `  </Actions>`,
    `</Task>`
  ].join("\r\n");
}

/**
 * UTF-16LE with a BOM. schtasks /xml rejects a UTF-8 file as malformed on
 * some Windows builds; UTF-16 is what Task Scheduler itself exports.
 */
export function encodeTaskXml(xml: string): Buffer {
  return Buffer.from("﻿" + xml, "utf16le");
}

/** Every `TraceniumAgentUpdate_<ms>` in a `schtasks /query /fo csv /nh` listing. */
export function updateTaskNamesIn(listing: string): string[] {
  const names = new Set<string>();
  for (const m of listing.matchAll(/\\(TraceniumAgentUpdate_\d+)"/g)) names.add(m[1]);
  return [...names];
}

/**
 * Delete the update tasks earlier attempts left registered.
 *
 * Only a task that ran to the end removes itself (the shim does it after
 * msiexec); one that never started stayed forever, and with StartWhenAvailable
 * it could now fire later next to the new one — two msiexec, one of them 1618.
 * Best-effort, like purgeOldShims: litter is not a reason to abandon an update.
 */
function purgeOldUpdateTasks(): void {
  let listing: string;
  try {
    const res = spawnSync("schtasks.exe", ["/query", "/fo", "csv", "/nh"], {
      windowsHide: true,
      encoding: "utf8"
    });
    if (res.error || res.status !== 0) return;
    listing = String(res.stdout || "");
  } catch {
    return;
  }
  for (const name of updateTaskNamesIn(listing)) {
    try {
      spawnSync("schtasks.exe", ["/delete", "/tn", name, "/f"], { windowsHide: true });
    } catch {
      // Not ours to fight over. Leave it.
    }
  }
}

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
  // The task is registered from XML (buildUpdateTaskXml), not from
  // `schtasks /sc ONCE /st`: the command-line form gives the task the
  // Task Scheduler defaults, and those refuse to start on battery.

  // Shims from previous updates. They used to delete themselves, which is
  // exactly what broke the exit code (see the shim below), so cleanup moved
  // here: the NEXT update sweeps the last one's leftovers, and nothing has to
  // delete a file it is currently executing.
  purgeOldShims();
  // Same for the tasks: one that never ran is still registered, and would
  // fire alongside this one if its trigger ever came round.
  purgeOldUpdateTasks();

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

  // Log del MSI y resultado del shim. Van al directorio de datos del agente y
  // no a TEMP: TEMP lo barre Windows y lo barre nuestro propio purgeOldShims,
  // y estos dos tienen que SOBREVIVIR a la actualización para poder contar qué
  // pasó cuando el agente vuelva.
  const msiStem = path.basename(msiPath).replace(/\.msi$/i, "");
  const msiLogPath = path.join(agentDataDir(), `update-msi-${msiStem}.log`);
  const resultPath = path.join(agentDataDir(), "update-result.json");

  // Arranque en 30 segundos exactos. Con `/st HH:MM` había que truncar al
  // minuto y hacía falta un margen de 90 s para no caer nunca en el pasado
  // (una hora pasada con `/sc ONCE` no se ejecutaba jamás); el XML lleva
  // segundos, y además StartWhenAvailable recoge un arranque perdido.
  const startAt = new Date(Date.now() + 30_000);
  const startTime = localIsoSeconds(startAt);

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
    // /l*v: log verboso del instalador. Sin él, un msiexec que falla —1618
    // "otra instalación en curso", un rollback, un archivo bloqueado— no deja
    // ni una pista: /qn no imprime nada y su salida iba a >nul. Cuando un
    // equipo se queda atascado en una versión, este fichero es lo único que
    // dice por qué.
    `msiexec.exe /i "${msiPath}" /qn /norestart /l*v "${msiLogPath}"`,
    "set MSIEXEC_RC=%ERRORLEVEL%",
    "rem Dejar el resultado donde el agente pueda leerlo al arrancar. Hasta",
    "rem ahora el código de salida solo existía en el LastResult de Task",
    "rem Scheduler, que nadie mira y que no viaja al control plane: un update",
    "rem fallido era indistinguible de uno que nunca se programó.",
    `> "${resultPath}" echo {"msi":"${msiStem}","exitCode":%MSIEXEC_RC%,"atLocal":"%DATE% %TIME%"}`,
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
  // The definition goes through a file because that is the only way schtasks
  // takes XML. It is copied into the task store on /create, so it is deleted
  // as soon as schtasks returns.
  const xmlPath = shimPath.replace(/\.cmd$/i, ".xml");
  try {
    fs.writeFileSync(
      xmlPath,
      encodeTaskXml(
        buildUpdateTaskXml({ shimPath, startAt, endAt: new Date(startAt.getTime() + TASK_WINDOW_MS) })
      )
    );
  } catch (err: any) {
    try { fs.unlinkSync(shimPath); } catch {}
    throw new Error(`update_task_xml_write_failed: ${err?.message || err}`);
  }
  const schArgs = ["/create", "/tn", taskName, "/xml", xmlPath, "/f"];

  try {
    // ⚠️ Se ESPERA a schtasks y se mira su código de salida.
    //
    // Antes se lanzaba con detached + stdio:"ignore" + unref() y se devolvía
    // started:true pase lo que pase. Si schtasks fallaba —permisos, nombre
    // inválido, hora rechazada— nadie se enteraba: el agente reportaba
    // "update started", ponía la marca, la marca caducaba, y volvía a
    // intentarlo. Un equipo podía quedarse así indefinidamente sin una sola
    // línea que dijera por qué.
    //
    // Sigue siendo un proceso corto (schtasks devuelve en milisegundos), así
    // que esperarlo no bloquea nada: lo que se quería evitar con detached era
    // que msiexec heredara nuestro Job Object, y eso lo resuelve la propia
    // Task Scheduler, no el detached de schtasks.
    const res = spawnSync("schtasks.exe", schArgs, {
      windowsHide: true,
      encoding: "utf8"
    });
    const code = res.error ? -1 : (res.status ?? -1);
    if (res.error) {
      console.error("[update] schtasks spawn error", {
        error: res.error.message,
        taskName,
        shimPath
      });
    } else if (code !== 0) {
      console.error("[update] schtasks refused to create the task", {
        exitCode: code,
        stderr: String(res.stderr || "").trim().slice(0, 500),
        stdout: String(res.stdout || "").trim().slice(0, 200),
        taskName,
        startTime
      });
    }

    if (code !== 0) {
      // No se programó nada. Decirlo, en vez de reportar un arranque que no
      // ocurrió: la diferencia decide si alguien va a mirar este equipo.
      return {
        started: false,
        command: "schtasks.exe",
        args: schArgs,
        error: `schtasks_failed_rc_${code}`
      } as any;
    }

    console.log("[update] scheduled msiexec via Task Scheduler", {
      taskName,
      startTime,
      shimPath,
      msiPath,
      msiLogPath,
      resultPath
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
  } finally {
    try { fs.unlinkSync(xmlPath); } catch {}
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
