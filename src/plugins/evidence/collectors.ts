// src/plugins/evidence/collectors.ts
//
// ADR-0032 F2 — los nueve colectores de evidencia, por plataforma.
//
// Misma doctrina que las sondas de ADR-0029, y por las mismas razones:
// lecturas, nunca escrituras; `execFile` con argumentos separados y NUNCA una
// shell; y sin PowerShell, que arranca lento y que un EDR mira con lupa cuando
// cuelga de un servicio.
//
// ⚠️ «No pude recogerlo» NO es «no había nada». Un colector que falla devuelve
// `failed` CON su motivo, y ese motivo acaba impreso en el informe como «no se
// pudo recoger». Un artefacto vacío que se presenta como bueno es peor que su
// ausencia: afirma que ahí no pasaba nada.
//
// ⚠️ NO se recoge nada de almacenes de credenciales (~/.ssh, SAM, NTDS, DPAPI,
// llaveros). Además del problema evidente, leerlos dispara al EDR del cliente:
// una prueba nuestra que leyó ~/.ssh generó una detección High en CrowdStrike.
// Ver ADR-0032 D6.

import crypto from "crypto";
import fs from "fs";
import fsp from "fs/promises";
import os from "os";
import path from "path";
import { execFile } from "child_process";

export type ExecResult = { code: number | null; stdout: string; stderr: string };
export type ExecFn = (cmd: string, args: string[], opts?: { timeoutMs?: number }) => Promise<ExecResult>;

export type CollectorKey =
  | "sessions"
  | "processes"
  | "services"
  | "network"
  | "event_logs"
  | "scheduled_tasks"
  | "storage"
  | "pending_reboot"
  | "agent_self";

/** Lo que produce un colector: uno o varios ficheros, o un motivo por el que no. */
export type Artifact =
  | { name: string; collector: CollectorKey; status: "ok"; filePath: string }
  | { name: string; collector: CollectorKey; status: "failed" | "skipped"; detail: string };

export type CollectorDeps = {
  platform: NodeJS.Platform;
  exec: ExecFn;
  /** Carpeta de trabajo de ESTA captura. La borra el job al terminar. */
  workDir: string;
  /** Carpeta de datos del agente, para `agent_self`. */
  agentDataDir?: string;
  logger?: { info?: (...a: any[]) => void; warn?: (...a: any[]) => void };
};

const CMD_TIMEOUT_MS = 30_000;
/** El mismo tope que declara el backend. Un artefacto mayor no se sube. */
export const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;

export const defaultExec: ExecFn = (cmd, args, opts) =>
  new Promise((resolve, reject) => {
    execFile(
      cmd,
      args,
      { timeout: opts?.timeoutMs ?? CMD_TIMEOUT_MS, maxBuffer: 64 * 1024 * 1024, windowsHide: true, encoding: "utf8" },
      (err: any, stdout, stderr) => {
        if (err && (err.killed || err.code === "ETIMEDOUT")) return reject(new Error(`${cmd} did not answer in time`));
        if (err && typeof err.code !== "number") return reject(new Error(`could not run ${cmd} (${err.code || err.message})`));
        resolve({ code: typeof err?.code === "number" ? err.code : 0, stdout: String(stdout ?? ""), stderr: String(stderr ?? "") });
      }
    );
  });

/** Los canales que el backend puede pedir → su nombre real en Windows. */
export const EVENT_LOG_CHANNELS: Record<string, string> = {
  System: "System",
  Application: "Application",
  Security: "Security",
  "TerminalServices-LocalSessionManager": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
  "TerminalServices-RemoteConnectionManager": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
  TaskScheduler: "Microsoft-Windows-TaskScheduler/Operational",
  WindowsUpdateClient: "Microsoft-Windows-WindowsUpdateClient/Operational",
};

async function writeArtifact(deps: CollectorDeps, name: string, content: string): Promise<string> {
  const target = path.join(deps.workDir, name);
  await fsp.writeFile(target, content, "utf8");
  return target;
}

/** Un comando cuya SALIDA es el artefacto. */
async function fromCommand(
  deps: CollectorDeps,
  collector: CollectorKey,
  name: string,
  cmd: string,
  args: string[]
): Promise<Artifact> {
  try {
    const res = await deps.exec(cmd, args);
    // ⚠️ El código de salida se guarda, no se interpreta: `sc query` contesta
    // 1060 para «no existe» y `quser` 1 cuando no hay nadie con sesión. Un
    // artefacto que existe con su código y su stderr dice más que un fallo.
    const header = `# tracenium evidence — ${collector}\n# command: ${cmd} ${args.join(" ")}\n# exit: ${res.code}\n`;
    const body = res.stdout + (res.stderr ? `\n# stderr:\n${res.stderr}` : "");
    if (!body.trim() && res.code !== 0) {
      return { name, collector, status: "failed", detail: `${cmd} exited ${res.code} with no output` };
    }
    return { name, collector, status: "ok", filePath: await writeArtifact(deps, name, header + body) };
  } catch (err: any) {
    return { name, collector, status: "failed", detail: String(err?.message ?? err).slice(0, 300) };
  }
}

async function fromJson(deps: CollectorDeps, collector: CollectorKey, name: string, build: () => Promise<unknown>): Promise<Artifact> {
  try {
    const data = await build();
    return { name, collector, status: "ok", filePath: await writeArtifact(deps, name, JSON.stringify(data, null, 2)) };
  } catch (err: any) {
    return { name, collector, status: "failed", detail: String(err?.message ?? err).slice(0, 300) };
  }
}

const notOnPlatform = (collector: CollectorKey, name: string, platform: string): Artifact => ({
  name,
  collector,
  status: "skipped",
  detail: `not available on ${platform}`,
});

// ── Los colectores ──────────────────────────────────────────────────────

export async function collectSessions(deps: CollectorDeps): Promise<Artifact[]> {
  if (deps.platform === "win32") {
    // `query user` no existe en algunas ediciones; su ausencia es un motivo,
    // no un «no hay sesiones».
    return [await fromCommand(deps, "sessions", "sessions.txt", "query.exe", ["user"])];
  }
  return [await fromCommand(deps, "sessions", "sessions.txt", "who", ["-a"])];
}

export async function collectProcesses(deps: CollectorDeps): Promise<Artifact[]> {
  if (deps.platform === "win32") {
    return [await fromCommand(deps, "processes", "processes.csv", "tasklist.exe", ["/FO", "CSV", "/V"])];
  }
  return [await fromCommand(deps, "processes", "processes.txt", "ps", ["aux"])];
}

export async function collectServices(deps: CollectorDeps): Promise<Artifact[]> {
  if (deps.platform === "win32") {
    // `state= all` lleva espacio DESPUÉS del `=`: es la sintaxis de sc.exe, no
    // una errata.
    return [await fromCommand(deps, "services", "services.txt", "sc.exe", ["query", "type=", "service", "state=", "all"])];
  }
  if (deps.platform === "darwin") {
    return [await fromCommand(deps, "services", "services.txt", "launchctl", ["list"])];
  }
  return [await fromCommand(deps, "services", "services.txt", "systemctl", ["list-units", "--type=service", "--all", "--no-pager"])];
}

export async function collectNetwork(deps: CollectorDeps): Promise<Artifact[]> {
  if (deps.platform === "win32") {
    return [await fromCommand(deps, "network", "network.txt", "netstat.exe", ["-ano"])];
  }
  if (deps.platform === "darwin") {
    return [await fromCommand(deps, "network", "network.txt", "netstat", ["-an"])];
  }
  return [await fromCommand(deps, "network", "network.txt", "ss", ["-tulpna"])];
}

/**
 * Los registros de eventos, uno por canal.
 *
 * ⚠️ La ventana se aplica DENTRO de wevtutil con `timediff`, no exportando el
 * canal entero: `Security` de un servidor con meses de historial son cientos de
 * megas, y subir eso ni cabe en el tope ni sirve para leer una mañana concreta.
 */
export async function collectEventLogs(
  deps: CollectorDeps,
  params: { channels?: string[]; windowHours?: number } = {}
): Promise<Artifact[]> {
  if (deps.platform !== "win32") return [notOnPlatform("event_logs", "event_logs.skipped", deps.platform)];

  const channels = (params.channels ?? ["System", "Application", "Security"]).filter((c) => EVENT_LOG_CHANNELS[c]);
  const hours = Math.min(Math.max(Number(params.windowHours) || 24, 1), 72);
  const ms = hours * 3600 * 1000;
  const out: Artifact[] = [];

  for (const key of channels) {
    const channel = EVENT_LOG_CHANNELS[key];
    const name = `${key.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.evtx`;
    const target = path.join(deps.workDir, name);
    try {
      // wevtutil se niega si el destino existe; en un reintento del mismo job
      // el fichero puede estar ahí.
      await fsp.rm(target, { force: true });
      const res = await deps.exec("wevtutil.exe", [
        "epl",
        channel,
        target,
        `/q:*[System[TimeCreated[timediff(@SystemTime) <= ${ms}]]]`,
      ]);
      if (res.code !== 0) {
        out.push({
          name,
          collector: "event_logs",
          status: "failed",
          detail: `wevtutil exited ${res.code}: ${(res.stderr || res.stdout).trim().slice(0, 200)}`,
        });
        continue;
      }
      const stat = await fsp.stat(target).catch(() => null);
      if (!stat) {
        out.push({ name, collector: "event_logs", status: "failed", detail: "wevtutil reported success but wrote no file" });
        continue;
      }
      if (stat.size > MAX_ARTIFACT_BYTES) {
        await fsp.rm(target, { force: true });
        out.push({
          name,
          collector: "event_logs",
          status: "failed",
          detail: `${channel} is ${Math.round(stat.size / 1048576)} MiB for ${hours} h, over the 64 MiB limit — narrow the window`,
        });
        continue;
      }
      out.push({ name, collector: "event_logs", status: "ok", filePath: target });
    } catch (err: any) {
      out.push({ name, collector: "event_logs", status: "failed", detail: String(err?.message ?? err).slice(0, 300) });
    }
  }
  if (!out.length) out.push({ name: "event_logs.skipped", collector: "event_logs", status: "failed", detail: "no channel was requested" });
  return out;
}

export async function collectScheduledTasks(deps: CollectorDeps): Promise<Artifact[]> {
  if (deps.platform === "win32") {
    // `/v` trae «Last Run Time» y «Last Result», que es lo que contesta «¿corrió
    // la tarea?» — la pregunta del caso que originó esto.
    return [await fromCommand(deps, "scheduled_tasks", "scheduled_tasks.csv", "schtasks.exe", ["/query", "/fo", "CSV", "/v"])];
  }
  if (deps.platform === "darwin") {
    return [await fromCommand(deps, "scheduled_tasks", "scheduled_tasks.txt", "launchctl", ["list"])];
  }
  return [await fromCommand(deps, "scheduled_tasks", "scheduled_tasks.txt", "systemctl", ["list-timers", "--all", "--no-pager"])];
}

/** Espacio en disco. Sin comandos: `statfs` es de Node y no se traduce. */
export async function collectStorage(deps: CollectorDeps): Promise<Artifact[]> {
  return [
    await fromJson(deps, "storage", "storage.json", async () => {
      const mounts = deps.platform === "win32" ? await windowsDrives(deps) : ["/"];
      const volumes: unknown[] = [];
      for (const mount of mounts) {
        try {
          const st: any = await (fsp as any).statfs(mount);
          volumes.push({
            mount,
            totalBytes: Number(st.blocks) * Number(st.bsize),
            freeBytes: Number(st.bfree) * Number(st.bsize),
            availableBytes: Number(st.bavail) * Number(st.bsize),
          });
        } catch (err: any) {
          volumes.push({ mount, error: String(err?.message ?? err).slice(0, 200) });
        }
      }
      return { collectedAtUtc: new Date().toISOString(), platform: deps.platform, volumes };
    }),
  ];
}

async function windowsDrives(deps: CollectorDeps): Promise<string[]> {
  try {
    const res = await deps.exec("fsutil.exe", ["fsinfo", "drives"]);
    const found = res.stdout.match(/[A-Za-z]:\\/g) ?? [];
    return found.length ? [...new Set(found)] : ["C:\\"];
  } catch {
    return ["C:\\"];
  }
}

/** Las banderas de reinicio pendiente, leídas del registro con `reg query`. */
export async function collectPendingReboot(deps: CollectorDeps): Promise<Artifact[]> {
  if (deps.platform !== "win32") return [notOnPlatform("pending_reboot", "pending_reboot.skipped", deps.platform)];

  const keys = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired",
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
  ];
  return [
    await fromJson(deps, "pending_reboot", "pending_reboot.json", async () => {
      const flags: Record<string, unknown> = {};
      for (const key of keys) {
        try {
          const res = await deps.exec("reg.exe", ["query", key]);
          // El código 1 de `reg query` es «la clave no existe», que AQUÍ es un
          // dato bueno: no hay reinicio pendiente por esa vía.
          flags[key] = res.code === 0 ? res.stdout.trim().slice(0, 4000) : { absent: true, exit: res.code };
        } catch (err: any) {
          flags[key] = { error: String(err?.message ?? err).slice(0, 200) };
        }
      }
      return { collectedAtUtc: new Date().toISOString(), uptimeSeconds: Math.round(os.uptime()), keys: flags };
    }),
  ];
}

/** Nuestros propios registros: lo primero que mira soporte cuando nos acusan. */
export async function collectAgentSelf(deps: CollectorDeps): Promise<Artifact[]> {
  const dir = deps.agentDataDir;
  if (!dir) return [{ name: "agent_self.skipped", collector: "agent_self", status: "skipped", detail: "agent data directory unknown" }];

  const out: Artifact[] = [];
  const wanted = ["update-result.json", path.join("state", "pmp-state.json")];
  for (const rel of wanted) {
    const src = path.join(dir, rel);
    const name = `agent-${path.basename(rel)}`;
    try {
      const content = await fsp.readFile(src, "utf8");
      out.push({ name, collector: "agent_self", status: "ok", filePath: await writeArtifact(deps, name, content) });
    } catch (err: any) {
      out.push({ name, collector: "agent_self", status: "failed", detail: `${rel}: ${String(err?.code ?? err?.message ?? err)}` });
    }
  }

  // Los dos registros más recientes, recortados por la cola: lo que importa de
  // un log en una incidencia es el final.
  try {
    const logDir = path.join(dir, "logs");
    const files = (await fsp.readdir(logDir))
      .filter((f) => f.endsWith(".log"))
      .map((f) => ({ f, full: path.join(logDir, f) }));
    const stats = await Promise.all(files.map(async (x) => ({ ...x, mtime: (await fsp.stat(x.full)).mtimeMs })));
    stats.sort((a, b) => b.mtime - a.mtime);
    for (const { f, full } of stats.slice(0, 2)) {
      const name = `agent-${f}`;
      out.push({ name, collector: "agent_self", status: "ok", filePath: await tailInto(full, path.join(deps.workDir, name)) });
    }
  } catch (err: any) {
    out.push({ name: "agent-logs.failed", collector: "agent_self", status: "failed", detail: String(err?.message ?? err).slice(0, 200) });
  }

  return out;
}

const TAIL_BYTES = 8 * 1024 * 1024;

/** Copia la COLA de un fichero, para no subir 500 MB de log rotado. */
async function tailInto(src: string, dest: string): Promise<string> {
  const stat = await fsp.stat(src);
  const start = stat.size > TAIL_BYTES ? stat.size - TAIL_BYTES : 0;
  await new Promise<void>((resolve, reject) => {
    const read = fs.createReadStream(src, { start });
    const write = fs.createWriteStream(dest);
    read.on("error", reject);
    write.on("error", reject);
    write.on("finish", () => resolve());
    read.pipe(write);
  });
  return dest;
}

/** SHA-256 en streaming: un .evtx de 60 MB no cabe en memoria a lo tonto. */
export async function sha256File(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

export type CollectorParams = Record<string, Record<string, unknown>>;

/** Despacha UN colector. Devuelve siempre artefactos: fallar también se cuenta. */
export async function runCollector(deps: CollectorDeps, key: CollectorKey, params: CollectorParams = {}): Promise<Artifact[]> {
  switch (key) {
    case "sessions": return collectSessions(deps);
    case "processes": return collectProcesses(deps);
    case "services": return collectServices(deps);
    case "network": return collectNetwork(deps);
    case "event_logs": return collectEventLogs(deps, (params.event_logs ?? {}) as any);
    case "scheduled_tasks": return collectScheduledTasks(deps);
    case "storage": return collectStorage(deps);
    case "pending_reboot": return collectPendingReboot(deps);
    case "agent_self": return collectAgentSelf(deps);
    default:
      return [{ name: `${key}.unknown`, collector: key, status: "failed", detail: `unknown collector '${key}'` }];
  }
}
