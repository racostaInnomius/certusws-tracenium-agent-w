// src/plugins/live-query/probes.ts
//
// ADR-0029 F2 — las seis sondas de la consulta en vivo, por plataforma.
//
// Lecturas, nunca escrituras, y nunca a través de una shell: cada comando se
// lanza con execFile y sus argumentos van separados (el nombre de un servicio
// no puede convertirse en `x & del …`). Sin PowerShell: arranca lento y un EDR
// lo vigila de cerca cuando cuelga de un servicio.
//
// ⚠️ Windows habla el idioma del sistema. `netstat` escribe «ESCUCHANDO» en un
// Windows en español, y `sc query` etiqueta «ESTADO». Nada de aquí empareja
// contra texto traducible:
//   · puerto:   una fila TCP con remoto 0.0.0.0:0 / [::]:0 ESTÁ escuchando
//   · servicio: el código de salida 1060 es «no existe», y el estado/arranque
//               se leen de las constantes (RUNNING, AUTO_START), que no se
//               traducen
//   · usuarios: los dueños de explorer.exe (quser no existe en Windows Home)
//
// ⚠️ «No pude mirarlo» NO es «no». Si el comando no arranca o no termina, la
// respuesta es `error` con el motivo, nunca `running: false`.

import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import { execFile } from "child_process";
import type { LiveQuestion } from "../../domain/live-query-question";

export type ExecResult = { code: number | null; stdout: string; stderr: string };
/** Resuelve SIEMPRE con el código de salida; lanza sólo si no se pudo lanzar o se agotó el tiempo. */
export type ExecFn = (cmd: string, args: string[], opts?: { timeoutMs?: number }) => Promise<ExecResult>;

export type ProbeDeps = {
  platform: NodeJS.Platform;
  exec: ExecFn;
  lstat: (p: string) => Promise<{ isFile(): boolean; isDirectory(): boolean; isSymbolicLink(): boolean; size: number; mtimeMs: number }>;
  sha256File: (p: string) => Promise<string>;
  readFile: (p: string) => Promise<string>;
  /** Nombre del proceso que escucha en un puerto (enriquecimiento; puede no saberse). */
  listenerName?: (port: number) => Promise<string | null>;
};

export type ProbeOutcome =
  | { outcome: "answered"; answer: Record<string, unknown> }
  | { outcome: "unsupported" }
  | { outcome: "error"; error: string };

/** Como FIM: por encima de esto se dice que existe, no se hashea. */
export const MAX_HASH_BYTES = 8 * 1024 * 1024;
const CMD_TIMEOUT_MS = 10_000;

export const defaultExec: ExecFn = (cmd, args, opts) =>
  new Promise((resolve, reject) => {
    execFile(
      cmd,
      args,
      { timeout: opts?.timeoutMs ?? CMD_TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024, windowsHide: true, encoding: "utf8" },
      (err: any, stdout, stderr) => {
        if (err && (err.killed || err.code === "ETIMEDOUT")) return reject(new Error(`${cmd} did not answer in time`));
        if (err && typeof err.code !== "number") return reject(new Error(`could not run ${cmd} (${err.code || err.message})`));
        resolve({ code: err ? Number(err.code) : 0, stdout: String(stdout ?? ""), stderr: String(stderr ?? "") });
      }
    );
  });

export function defaultProbeDeps(): ProbeDeps {
  return {
    platform: os.platform(),
    exec: defaultExec,
    lstat: (p) => fs.promises.lstat(p),
    readFile: (p) => fs.promises.readFile(p, "utf8"),
    sha256File: (p) =>
      new Promise((resolve, reject) => {
        const h = crypto.createHash("sha256");
        fs.createReadStream(p)
          .on("error", reject)
          .on("data", (c) => h.update(c))
          .on("end", () => resolve(h.digest("hex")));
      }),
  };
}

// ── Parsers (puros) ──────────────────────────────────────────────────

/** `tasklist /V /FO CSV /NH`: [imagen, pid, sesión, nº, memoria, estado, USUARIO, cpu, ventana]. */
export function parseTasklistVerbose(out: string): Array<{ image: string; pid: number; user: string | null }> {
  const rows: Array<{ image: string; pid: number; user: string | null }> = [];
  for (const raw of String(out).split(/\r?\n/)) {
    const line = raw.trim();
    // Sin coincidencias, tasklist escribe «INFO: …» traducido: sólo se leen filas CSV.
    if (!line.startsWith('"')) continue;
    const f = line.slice(1, -1).split('","');
    const pid = Number(f[1]);
    if (!f[0] || !Number.isInteger(pid)) continue;
    const user = f[6] && f[6] !== "N/A" && f[6] !== "N/D" ? f[6] : null;
    rows.push({ image: f[0], pid, user });
  }
  return rows;
}

/** `ps -axo pid=,user=,comm=`: comm es la ruta completa en macOS y el nombre (≤ 15) en Linux. */
export function parsePs(out: string): Array<{ pid: number; user: string; comm: string }> {
  const rows: Array<{ pid: number; user: string; comm: string }> = [];
  for (const raw of String(out).split("\n")) {
    const m = raw.match(/^\s*(\d+)\s+(\S+)\s+(.+?)\s*$/);
    if (m) rows.push({ pid: Number(m[1]), user: m[2], comm: m[3] });
  }
  return rows;
}

/** ¿Este comm es el proceso `name`? Linux trunca comm a 15 caracteres. */
export function commMatches(comm: string, name: string, platform: NodeJS.Platform): boolean {
  const base = comm.includes("/") ? comm.slice(comm.lastIndexOf("/") + 1) : comm;
  if (base === name) return true;
  return platform === "linux" && name.length > 15 && base === name.slice(0, 15);
}

const SC_STATES = /:\s*\d+\s+(STOPPED|START_PENDING|STOP_PENDING|RUNNING|CONTINUE_PENDING|PAUSE_PENDING|PAUSED)\b/;
const SC_START = /:\s*\d+\s+(BOOT_START|SYSTEM_START|AUTO_START|DEMAND_START|DISABLED)\b(.*)$/m;

export function parseScState(out: string): "running" | "stopped" | "other" | null {
  const m = String(out).match(SC_STATES);
  if (!m) return null;
  return m[1] === "RUNNING" ? "running" : m[1] === "STOPPED" ? "stopped" : "other";
}

export function parseScStartType(out: string): string | null {
  const m = String(out).match(SC_START);
  if (!m) return null;
  const base = { BOOT_START: "boot", SYSTEM_START: "system", AUTO_START: "auto", DEMAND_START: "manual", DISABLED: "disabled" }[m[1]] ?? null;
  return base && /DELAYED/i.test(m[2] ?? "") ? `${base} (delayed)` : base;
}

export function parseSystemctlShow(out: string): Record<string, string> {
  const props: Record<string, string> = {};
  for (const line of String(out).split("\n")) {
    const i = line.indexOf("=");
    if (i > 0) props[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return props;
}

/**
 * `netstat -ano` de Windows: la fila de un socket a la escucha tiene como
 * remoto 0.0.0.0:0 o [::]:0, se llame como se llame el estado en ese idioma.
 */
export function parseWindowsNetstatListeners(out: string, port: number): Array<{ address: string; pid: number }> {
  const hits: Array<{ address: string; pid: number }> = [];
  for (const raw of String(out).split(/\r?\n/)) {
    const cols = raw.trim().split(/\s+/);
    if (cols.length < 5 || cols[0].toUpperCase() !== "TCP") continue;
    const [, local, remote] = cols;
    if (remote !== "0.0.0.0:0" && remote !== "[::]:0") continue;
    const sep = local.lastIndexOf(":");
    if (Number(local.slice(sep + 1)) !== port) continue;
    hits.push({ address: local.slice(0, sep), pid: Number(cols[cols.length - 1]) });
  }
  return hits;
}

/** /proc/net/tcp{,6}: filas en LISTEN (0A) para `port`, con la dirección legible si es IPv4. */
export function parseProcNetListeners(content: string, port: number): string[] {
  const out: string[] = [];
  for (const line of String(content).split("\n").slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 4 || cols[3] !== "0A") continue;
    const [hexAddr, hexPort] = String(cols[1]).split(":");
    if (parseInt(hexPort, 16) !== port) continue;
    if (hexAddr.length === 8) {
      const b = hexAddr.match(/../g)!.map((h) => parseInt(h, 16)).reverse();
      out.push(b.join("."));
    } else {
      out.push(/^0+$/.test(hexAddr) ? "::" : "ipv6");
    }
  }
  return out;
}

/** `lsof -nP +c 0 -iTCP:<port> -sTCP:LISTEN`: [comando, pid, usuario, …, NAME (LISTEN)]. */
export function parseLsofListen(out: string): Array<{ command: string; pid: number; address: string }> {
  const rows: Array<{ command: string; pid: number; address: string }> = [];
  for (const raw of String(out).split("\n").slice(1)) {
    const cols = raw.trim().split(/\s+/);
    if (cols.length < 9) continue;
    const name = cols[cols.length - 2];
    const sep = name.lastIndexOf(":");
    rows.push({ command: cols[0], pid: Number(cols[1]), address: sep > 0 ? name.slice(0, sep) : name });
  }
  return rows;
}

const REG_TYPES =
  "REG_SZ|REG_EXPAND_SZ|REG_MULTI_SZ|REG_DWORD_BIG_ENDIAN|REG_DWORD|REG_QWORD|REG_BINARY|REG_NONE|REG_LINK|REG_RESOURCE_LIST|REG_FULL_RESOURCE_DESCRIPTOR|REG_RESOURCE_REQUIREMENTS_LIST";

/**
 * `reg query <clave> /v <valor>` (o `/ve`): la primera fila con un tipo REG_*.
 * El nombre del valor por defecto sale traducido («(Predeterminado)»), así que
 * no se empareja por nombre: la consulta ya pidió un solo valor.
 */
export function parseRegQuery(out: string): { type: string; data: string } | null {
  const re = new RegExp(`\\s(${REG_TYPES})(?:\\s+(.*))?$`);
  for (const raw of String(out).split(/\r?\n/)) {
    if (!/^\s{2,}\S/.test(raw)) continue;
    const m = raw.match(re);
    if (m) return { type: m[1], data: (m[2] ?? "").trim() };
  }
  return null;
}

// ── Sondas ───────────────────────────────────────────────────────────

const fail = (error: string): ProbeOutcome => ({ outcome: "error", error: error.slice(0, 300) });

async function processProbe(d: ProbeDeps, rawName: string): Promise<ProbeOutcome> {
  if (d.platform === "win32") {
    // «AnyDesk» y «AnyDesk.exe» son la misma pregunta para quien la escribe.
    const name = path.win32.extname(rawName) ? rawName : `${rawName}.exe`;
    const r = await d.exec("tasklist", ["/V", "/FO", "CSV", "/NH", "/FI", `IMAGENAME eq ${name}`]);
    if (r.code !== 0) return fail(`tasklist exited ${r.code}`);
    const rows = parseTasklistVerbose(r.stdout).filter((x) => x.image.toLowerCase() === name.toLowerCase());
    return { outcome: "answered", answer: { running: rows.length > 0, count: rows.length, instances: rows.slice(0, 20).map((x) => ({ pid: x.pid, user: x.user })) } };
  }
  const r = await d.exec("ps", ["-axo", "pid=,user=,comm="]);
  if (r.code !== 0) return fail(`ps exited ${r.code}`);
  const rows = parsePs(r.stdout).filter((x) => commMatches(x.comm, rawName, d.platform));
  return { outcome: "answered", answer: { running: rows.length > 0, count: rows.length, instances: rows.slice(0, 20).map((x) => ({ pid: x.pid, user: x.user })) } };
}

async function serviceProbe(d: ProbeDeps, name: string): Promise<ProbeOutcome> {
  if (d.platform === "win32") {
    const q = await d.exec("sc.exe", ["query", name]);
    // 1060 = ERROR_SERVICE_DOES_NOT_EXIST. Estable en cualquier idioma.
    if (q.code === 1060) return { outcome: "answered", answer: { exists: false } };
    if (q.code !== 0) return fail(`sc query exited ${q.code}`);
    const state = parseScState(q.stdout);
    if (!state) return fail("sc query output not understood");
    const c = await d.exec("sc.exe", ["qc", name]).catch(() => null);
    return { outcome: "answered", answer: { exists: true, state, startMode: c && c.code === 0 ? parseScStartType(c.stdout) : null } };
  }
  if (d.platform === "linux") {
    const unit = name.includes(".") ? name : `${name}.service`;
    const r = await d.exec("systemctl", ["show", unit, "--no-pager", "--property=LoadState,ActiveState,UnitFileState,Description"]);
    if (r.code !== 0) return fail(`systemctl exited ${r.code}`);
    const p = parseSystemctlShow(r.stdout);
    if (!p.LoadState) return fail("systemctl output not understood");
    if (p.LoadState === "not-found") return { outcome: "answered", answer: { exists: false } };
    const state = p.ActiveState === "active" ? "running" : p.ActiveState === "inactive" || p.ActiveState === "failed" ? "stopped" : "other";
    return { outcome: "answered", answer: { exists: true, state, startMode: p.UnitFileState || null, displayName: p.Description || null } };
  }
  if (d.platform === "darwin") {
    // Sólo el dominio `system` (daemons). Los agentes por usuario no.
    const r = await d.exec("launchctl", ["print", `system/${name}`]);
    if (r.code === 113) return { outcome: "answered", answer: { exists: false } };
    if (r.code !== 0) return fail(`launchctl exited ${r.code}`);
    const m = r.stdout.match(/^\s*state = (.+)$/m);
    const state = m ? (m[1].trim() === "running" ? "running" : m[1].trim() === "not running" ? "stopped" : "other") : "other";
    return { outcome: "answered", answer: { exists: true, state, startMode: null } };
  }
  return { outcome: "unsupported" };
}

async function fileProbe(d: ProbeDeps, p: string): Promise<ProbeOutcome> {
  const windowsPath = /^[a-zA-Z]:\\/.test(p);
  // Una ruta de Windows en un Mac no «falta»: la pregunta no aplica.
  if (windowsPath !== (d.platform === "win32")) return { outcome: "unsupported" };
  let st;
  try {
    st = await d.lstat(p);
  } catch (err: any) {
    if (err?.code === "ENOENT" || err?.code === "ENOTDIR") return { outcome: "answered", answer: { exists: false } };
    return fail(`cannot read the path (${err?.code || err?.message || "error"})`);
  }
  const base = { exists: true, sizeBytes: st.isFile() ? st.size : null, modifiedAt: new Date(st.mtimeMs).toISOString(), sha256: null as string | null };
  // Un enlace no se sigue (como FIM) y un directorio no se hashea.
  if (!st.isFile() || st.isSymbolicLink() || st.size > MAX_HASH_BYTES) return { outcome: "answered", answer: base };
  try {
    return { outcome: "answered", answer: { ...base, sha256: await d.sha256File(p) } };
  } catch {
    return { outcome: "answered", answer: base };
  }
}

async function registryProbe(d: ProbeDeps, key: string, value: string): Promise<ProbeOutcome> {
  if (d.platform !== "win32") return { outcome: "unsupported" };
  // Vista de 64 y luego la de 32, como bootstrap/registry.ts.
  // ⚠️ reg.exe sale con 1 tanto si no existe como si se deniega; como SYSTEM,
  // HKLM y las colmenas cargadas de HKU se leen, así que 1 = no existe.
  for (const view of ["64", "32"]) {
    const args = value ? ["query", key, "/v", value, `/reg:${view}`] : ["query", key, "/ve", `/reg:${view}`];
    const r = await d.exec("reg.exe", args);
    if (r.code === 0) {
      const parsed = parseRegQuery(r.stdout);
      if (parsed) return { outcome: "answered", answer: { exists: true, type: parsed.type, data: parsed.data.slice(0, 512) } };
      return fail("reg query output not understood");
    }
    if (r.code !== 1) return fail(`reg.exe exited ${r.code}`);
  }
  return { outcome: "answered", answer: { exists: false } };
}

async function portProbe(d: ProbeDeps, port: number): Promise<ProbeOutcome> {
  if (d.platform === "win32") {
    const r = await d.exec("netstat", ["-ano"]);
    if (r.code !== 0) return fail(`netstat exited ${r.code}`);
    const hits = parseWindowsNetstatListeners(r.stdout, port);
    if (hits.length === 0) return { outcome: "answered", answer: { listening: false } };
    let processName: string | null = null;
    const t = await d.exec("tasklist", ["/V", "/FO", "CSV", "/NH", "/FI", `PID eq ${hits[0].pid}`]).catch(() => null);
    if (t && t.code === 0) processName = parseTasklistVerbose(t.stdout)[0]?.image ?? null;
    return { outcome: "answered", answer: { listening: true, process: processName, address: hits[0].address } };
  }
  if (d.platform === "darwin") {
    const r = await d.exec("lsof", ["-nP", "+c", "0", `-iTCP:${port}`, "-sTCP:LISTEN"]);
    // lsof sale con 1 cuando no encuentra nada, y también sin salida.
    if (r.code === 1 && !r.stdout.trim()) return { outcome: "answered", answer: { listening: false } };
    if (r.code !== 0) return fail(`lsof exited ${r.code}`);
    const rows = parseLsofListen(r.stdout);
    if (rows.length === 0) return { outcome: "answered", answer: { listening: false } };
    return { outcome: "answered", answer: { listening: true, process: rows[0].command, address: rows[0].address } };
  }
  if (d.platform === "linux") {
    const addrs: string[] = [];
    let readAny = false;
    for (const table of ["/proc/net/tcp", "/proc/net/tcp6"]) {
      try {
        addrs.push(...parseProcNetListeners(await d.readFile(table), port));
        readAny = true;
      } catch {
        /* sin IPv6 no hay tcp6 */
      }
    }
    if (!readAny) return fail("cannot read /proc/net/tcp");
    if (addrs.length === 0) return { outcome: "answered", answer: { listening: false } };
    const processName = d.listenerName ? await d.listenerName(port).catch(() => null) : null;
    return { outcome: "answered", answer: { listening: true, process: processName, address: addrs[0] } };
  }
  return { outcome: "unsupported" };
}

async function loggedOnUsersProbe(d: ProbeDeps): Promise<ProbeOutcome> {
  if (d.platform === "win32") {
    // Una sesión interactiva (consola o RDP) tiene su explorer.exe.
    const r = await d.exec("tasklist", ["/V", "/FO", "CSV", "/NH", "/FI", "IMAGENAME eq explorer.exe"]);
    if (r.code !== 0) return fail(`tasklist exited ${r.code}`);
    const users = [...new Set(parseTasklistVerbose(r.stdout).map((x) => x.user).filter((u): u is string => !!u))];
    return { outcome: "answered", answer: { users } };
  }
  const r = await d.exec("who", []);
  if (r.code !== 0) return fail(`who exited ${r.code}`);
  const users = [...new Set(r.stdout.split("\n").map((l) => l.trim().split(/\s+/)[0]).filter(Boolean))];
  return { outcome: "answered", answer: { users } };
}

export async function runProbe(d: ProbeDeps, q: LiveQuestion): Promise<ProbeOutcome> {
  try {
    switch (q.probe) {
      case "process":
        return await processProbe(d, q.params.name);
      case "service":
        return await serviceProbe(d, q.params.name);
      case "file":
        return await fileProbe(d, q.params.path);
      case "registry":
        return await registryProbe(d, q.params.key, q.params.value);
      case "port":
        return await portProbe(d, q.params.port);
      case "logged_on_users":
        return await loggedOnUsersProbe(d);
    }
  } catch (err: any) {
    return fail(err?.message || String(err));
  }
}
