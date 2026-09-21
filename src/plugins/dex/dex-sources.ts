// src/plugins/dex/dex-sources.ts
//
// ADR-0030 F2 — de dónde salen los eventos de estabilidad, la duración del
// arranque y la batería, por plataforma.
//
// Las mismas reglas que la consulta en vivo: execFile sin shell, nada de
// PowerShell, y NADA que empareje texto traducido. En Windows se lee el
// registro de eventos en XML (`wevtutil /f:xml`): los nombres de proveedor, los
// IDs y los campos de EventData no se traducen; el mensaje sí, y no se usa.
//
// ⚠️ «No pude leerlo» no es «no hubo»: cada fuente devuelve su scope
// (collected / unsupported / unavailable) y el backend no evalúa lo que no se
// pudo leer.

import path from "path";
import type { ExecFn } from "../live-query/probes";

export type StabilityKind = "app_crash" | "app_hang" | "os_crash" | "unexpected_shutdown";
export type StabilityEvent = { key: string; kind: StabilityKind; occurredAtUtc: string; app: string | null; detail: string | null };
export type Scope = "collected" | "unsupported" | "unavailable";

/**
 * Un cursor POR FUENTE (el registro Application, el System, cada directorio…):
 * con uno solo, una fuente que llega al tope de lectura vería su cursor saltar
 * por encima de lo que aún no leyó porque otra fuente tenía eventos más nuevos.
 */
export type Cursors = Record<string, string>;
export type EventsResult = { scope: Scope; events: StabilityEvent[]; cursors: Cursors };
export type BootResult = { scope: Scope; boot: { bootUtc: string; durationMs: number } | null };
export type BatteryResult = {
  scope: Scope;
  battery: { present: boolean; healthPct?: number | null; cycleCount?: number | null; designCapacityMwh?: number | null; fullChargeCapacityMwh?: number | null } | null;
};

export type SourceDeps = {
  platform: NodeJS.Platform;
  exec: ExecFn;
  readFile: (p: string) => Promise<string>;
  readDir: (p: string) => Promise<string[]>;
  stat: (p: string) => Promise<{ mtimeMs: number; isFile(): boolean }>;
  tmpFile: () => string;
  removeFile: (p: string) => Promise<void>;
  nowMs: () => number;
  uptimeSeconds: () => number;
};

/** Máximo de eventos por lectura: el backend no acepta más de 500 por mensaje. */
export const MAX_EVENTS_PER_READ = 400;
const bare = (p: string | null | undefined) => (p ? p.split(/[\\/]/).pop()!.slice(0, 128) || null : null);

// ── Windows: registro de eventos ─────────────────────────────────────

const decode = (s: string) =>
  s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");

export type WinEvent = { log: string; recordId: string; eventId: number; provider: string; timeUtc: string; data: string[]; named: Record<string, string> };

/** `wevtutil qe <log> /f:xml`: una secuencia de <Event>…</Event> sin raíz. */
export function parseWevtutilXml(xml: string, log: string): WinEvent[] {
  const out: WinEvent[] = [];
  for (const m of String(xml).matchAll(/<Event\b[\s\S]*?<\/Event>/g)) {
    const e = m[0];
    const eventId = Number(e.match(/<EventID\b[^>]*>(\d+)<\/EventID>/)?.[1]);
    const recordId = e.match(/<EventRecordID>(\d+)<\/EventRecordID>/)?.[1];
    const provider = e.match(/<Provider\b[^>]*\bName=['"]([^'"]+)['"]/)?.[1] ?? "";
    const time = e.match(/<TimeCreated\b[^>]*\bSystemTime=['"]([^'"]+)['"]/)?.[1];
    const t = time ? Date.parse(time) : NaN;
    if (!Number.isInteger(eventId) || !recordId || !Number.isFinite(t)) continue;
    const data: string[] = [];
    const named: Record<string, string> = {};
    for (const d of e.matchAll(/<Data(?:\s+Name=['"]([^'"]*)['"])?\s*(?:\/>|>([\s\S]*?)<\/Data>)/g)) {
      const value = decode(d[2] ?? "").trim();
      data.push(value);
      if (d[1]) named[d[1]] = value;
    }
    out.push({ log, recordId, eventId, provider, timeUtc: new Date(t).toISOString(), data, named });
  }
  return out;
}

/** De un evento de Windows a un evento de estabilidad (o null si no cuenta). */
export function toStabilityEvent(e: WinEvent): StabilityEvent | null {
  const key = `${e.log}:${e.recordId}`;
  if (e.log === "Application" && e.eventId === 1000 && /Application Error/i.test(e.provider)) {
    // Con nombres (Windows 11) o por posición: 0 = app, 6 = código de excepción.
    return { key, kind: "app_crash", occurredAtUtc: e.timeUtc, app: bare(e.named.AppName ?? e.data[0]), detail: e.named.ExceptionCode ?? e.data[6] ?? null };
  }
  if (e.log === "Application" && e.eventId === 1002 && /Application Hang/i.test(e.provider)) {
    return { key, kind: "app_hang", occurredAtUtc: e.timeUtc, app: bare(e.named.AppName ?? e.data[0]), detail: null };
  }
  if (e.log === "System" && e.eventId === 1001 && /WER-SystemErrorReporting/i.test(e.provider)) {
    // «0x0000009f (0x…, …)»: el código es el primer token.
    const raw = e.named.param1 ?? e.data[0] ?? "";
    return { key, kind: "os_crash", occurredAtUtc: e.timeUtc, app: null, detail: raw.split(/\s/)[0] || null };
  }
  if (e.log === "System" && e.eventId === 41 && /Kernel-Power/i.test(e.provider)) {
    // Un pantallazo azul también deja un 41, con su BugcheckCode: ya lo cuenta
    // el 1001. Sólo el 41 sin bugcheck es un apagado inesperado (corte, botón).
    const code = e.named.BugcheckCode ?? "0";
    if (code !== "0" && code !== "") return null;
    return { key, kind: "unexpected_shutdown", occurredAtUtc: e.timeUtc, app: null, detail: null };
  }
  return null;
}

const APP_QUERY = (since: string) =>
  `*[System[(EventID=1000 or EventID=1002) and TimeCreated[@SystemTime>'${since}']]]`;
const SYSTEM_QUERY = (since: string) =>
  `*[System[((Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and EventID=1001) or (Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41)) and TimeCreated[@SystemTime>'${since}']]]`;

async function windowsEvents(d: SourceDeps, cursors: Cursors, defaultSince: string): Promise<EventsResult> {
  const events: StabilityEvent[] = [];
  const next: Cursors = { ...cursors };
  let readAny = false;
  for (const log of ["Application", "System"] as const) {
    const since = cursors[log] ?? defaultSince;
    const query = log === "Application" ? APP_QUERY(since) : SYSTEM_QUERY(since);
    // Del más viejo al más nuevo: si hay más que el tope, la próxima lectura
    // sigue desde el último leído.
    const r = await d.exec("wevtutil", ["qe", log, `/q:${query}`, "/f:xml", `/c:${MAX_EVENTS_PER_READ}`]).catch(() => null);
    if (!r || r.code !== 0) continue;
    readAny = true;
    for (const w of parseWevtutilXml(r.stdout, log)) {
      if (!next[log] || w.timeUtc > next[log]) next[log] = w.timeUtc;
      const s = toStabilityEvent(w);
      if (s) events.push(s);
    }
  }
  return { scope: readAny ? "collected" : "unavailable", events, cursors: next };
}

async function windowsBoot(d: SourceDeps): Promise<BootResult> {
  // Diagnostics-Performance 100: «el arranque tardó BootTime ms». El más reciente.
  const r = await d
    .exec("wevtutil", ["qe", "Microsoft-Windows-Diagnostics-Performance/Operational", "/q:*[System[EventID=100]]", "/f:xml", "/c:1", "/rd:true"])
    .catch(() => null);
  if (!r || r.code !== 0) return { scope: "unavailable", boot: null };
  const e = parseWevtutilXml(r.stdout, "Diagnostics-Performance")[0];
  const ms = Number(e?.named.BootTime);
  if (!e || !Number.isFinite(ms) || ms < 0) return { scope: "collected", boot: null };
  // El evento se escribe cuando termina el arranque: el arranque empezó BootTime antes.
  return { scope: "collected", boot: { bootUtc: new Date(Date.parse(e.timeUtc) - ms).toISOString(), durationMs: Math.round(ms) } };
}

/** `powercfg /batteryreport /xml`: capacidad de diseño, carga completa y ciclos. XML sin traducir. */
export function parseBatteryReportXml(xml: string): BatteryResult["battery"] {
  const text = String(xml);
  const block = text.match(/<Battery>([\s\S]*?)<\/Battery>/)?.[1];
  if (!block) return { present: false };
  const num = (tag: string) => {
    const v = Number(block.match(new RegExp(`<${tag}>(\\d+)</${tag}>`))?.[1]);
    return Number.isFinite(v) ? v : null;
  };
  const design = num("DesignCapacity");
  const full = num("FullChargeCapacity");
  return {
    present: true,
    designCapacityMwh: design,
    fullChargeCapacityMwh: full,
    cycleCount: num("CycleCount"),
    healthPct: design && full !== null ? Math.round((full / design) * 10_000) / 100 : null,
  };
}

async function windowsBattery(d: SourceDeps): Promise<BatteryResult> {
  const file = d.tmpFile();
  try {
    const r = await d.exec("powercfg", ["/batteryreport", "/xml", "/output", file], { timeoutMs: 30_000 });
    if (r.code !== 0) return { scope: "unavailable", battery: null };
    return { scope: "collected", battery: parseBatteryReportXml(await d.readFile(file)) };
  } catch {
    return { scope: "unavailable", battery: null };
  } finally {
    await d.removeFile(file).catch(() => undefined);
  }
}

// ── macOS: DiagnosticReports ─────────────────────────────────────────

/** «2026-09-20 10:15:02.00 -0500» → ISO. Date.parse no garantiza ese formato. */
export function parseIpsTimestamp(v: unknown): string | null {
  const m = String(v ?? "").match(/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(\.\d+)? ([+-])(\d{2})(\d{2})$/);
  if (!m) return null;
  const t = Date.parse(`${m[1]}T${m[2]}${m[3] ?? ""}${m[4]}${m[5]}:${m[6]}`);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

/**
 * Un informe de DiagnosticReports. `.ips` lleva en su primera línea una
 * cabecera JSON con `bug_type`: 309/109 = crash de aplicación, 210/110 =
 * kernel panic. `.panic` es panic; `.hang`, cuelgue. El resto (Jetsam,
 * recursos, analítica) no es inestabilidad y se ignora.
 */
export function classifyMacReport(fileName: string, firstLine: string | null, mtimeMs: number): StabilityEvent | null {
  const ext = path.extname(fileName).toLowerCase();
  const fallbackApp = fileName.replace(/[-_]\d{4}-\d{2}-\d{2}[-_].*$/, "").replace(/\.[^.]+$/, "") || null;
  const at = new Date(mtimeMs).toISOString();
  if (ext === ".panic") return { key: fileName, kind: "os_crash", occurredAtUtc: at, app: null, detail: null };
  if (ext === ".hang") return { key: fileName, kind: "app_hang", occurredAtUtc: at, app: bare(fallbackApp), detail: null };
  if (ext !== ".ips" && ext !== ".crash") return null;
  let header: any = null;
  try {
    header = firstLine ? JSON.parse(firstLine) : null;
  } catch {
    header = null;
  }
  // ⚠️ `is_simulated`: macOS escribe informes de crash SIMULADOS (ExcUserFault_…,
  // bug_type 309) para su analítica; el proceso no murió. En un Mac de
  // desarrollo, 40 de 53 informes 309 eran simulados — contarlos pondría
  // «textunderstandingd ×35» como aplicación inestable en un equipo sano.
  if (header?.is_simulated === 1 || header?.is_simulated === true) return null;
  const bug = String(header?.bug_type ?? (ext === ".crash" ? "109" : ""));
  const when = parseIpsTimestamp(header?.timestamp) ?? at;
  if (bug === "309" || bug === "109") {
    return { key: fileName, kind: "app_crash", occurredAtUtc: when, app: bare(header?.app_name ?? header?.name ?? fallbackApp), detail: null };
  }
  if (bug === "210" || bug === "110") return { key: fileName, kind: "os_crash", occurredAtUtc: when, app: null, detail: null };
  return null;
}

async function macEvents(d: SourceDeps, cursors: Cursors, defaultSince: string): Promise<EventsResult> {
  const roots = ["/Library/Logs/DiagnosticReports"];
  try {
    for (const u of await d.readDir("/Users")) roots.push(`/Users/${u}/Library/Logs/DiagnosticReports`);
  } catch {
    /* sin /Users legible, sólo los del sistema */
  }
  // ⚠️ Y su `Retired/`: macOS mueve ahí cada informe en cuanto lo envía a Apple,
  // a veces en horas. En un Mac de desarrollo, los 4 crashes reales de la
  // semana estaban ya en Retired/ — sin esto, una lectura por hora los pierde.
  // La key es el nombre del fichero, que no cambia al moverse: visto antes y
  // después no cuenta dos veces.
  const dirs = roots.flatMap((r) => [r, `${r}/Retired`]);
  let readAny = false;
  const next: Cursors = { ...cursors };
  const events: StabilityEvent[] = [];
  for (const dir of dirs) {
    const sinceMs = Date.parse(cursors[dir] ?? defaultSince);
    let names: string[];
    try {
      names = await d.readDir(dir);
      readAny = true;
    } catch {
      continue;
    }
    for (const name of names) {
      if (events.length >= MAX_EVENTS_PER_READ) break;
      const full = `${dir}/${name}`;
      const st = await d.stat(full).catch(() => null);
      if (!st || !st.isFile() || st.mtimeMs <= sinceMs) continue;
      const iso = new Date(st.mtimeMs).toISOString();
      if (!next[dir] || iso > next[dir]) next[dir] = iso;
      const first = name.toLowerCase().endsWith(".ips") ? await d.readFile(full).then((t) => t.split("\n", 1)[0]).catch(() => null) : null;
      const ev = classifyMacReport(name, first, st.mtimeMs);
      if (ev) events.push(ev);
    }
  }
  return { scope: readAny ? "collected" : "unavailable", events, cursors: next };
}

/**
 * `ioreg -rn AppleSmartBattery`: capacidad de diseño y la máxima real, en mAh.
 *
 * ⚠️ La forma cambia entre versiones. En macOS reciente las cifras van dentro
 * del diccionario `BatteryData` y SIN espacios (`"DesignCapacity"=8579`), no
 * hay `AppleRawMaxCapacity`, y `MaxCapacity` es un % (100). La «capacidad
 * máxima» que enseña Ajustes es NominalChargeCapacity / DesignCapacity. En
 * Intel, MaxCapacity sí es mAh.
 */
export function parseIoregBattery(out: string): BatteryResult["battery"] {
  const text = String(out);
  if (!/AppleSmartBattery/.test(text)) return { present: false };
  const num = (k: string) => {
    const v = Number(text.match(new RegExp(`"${k}"\\s*=\\s*(\\d+)`))?.[1]);
    return Number.isFinite(v) ? v : null;
  };
  const design = num("DesignCapacity");
  const maxCap = num("MaxCapacity");
  const actual = num("AppleRawMaxCapacity") ?? num("NominalChargeCapacity") ?? num("FullChargeCapacity") ?? (maxCap !== null && maxCap > 100 ? maxCap : null);
  return {
    present: true,
    cycleCount: num("CycleCount"),
    healthPct: design && actual !== null ? Math.round((actual / design) * 10_000) / 100 : null,
  };
}

async function macBattery(d: SourceDeps): Promise<BatteryResult> {
  const r = await d.exec("ioreg", ["-rn", "AppleSmartBattery"]).catch(() => null);
  if (!r) return { scope: "unavailable", battery: null };
  // Sin batería, ioreg sale 0 con la salida vacía.
  if (r.code !== 0) return { scope: "unavailable", battery: null };
  return { scope: "collected", battery: parseIoregBattery(r.stdout) };
}

// ── Linux ────────────────────────────────────────────────────────────

/** `coredumpctl list --json=short`: [{ time (µs), pid, exe, sig }]. */
export function parseCoredumpctlJson(out: string): StabilityEvent[] {
  let rows: any[];
  try {
    rows = JSON.parse(String(out) || "[]");
  } catch {
    return [];
  }
  if (!Array.isArray(rows)) return [];
  return rows.flatMap((r) => {
    const us = Number(r?.time);
    if (!Number.isFinite(us) || !r?.pid) return [];
    return [{ key: `core:${us}:${r.pid}`, kind: "app_crash" as const, occurredAtUtc: new Date(Math.floor(us / 1000)).toISOString(), app: bare(r.exe), detail: r.sig ? `signal ${r.sig}` : null }];
  });
}

async function linuxEvents(d: SourceDeps, cursors: Cursors, defaultSince: string): Promise<EventsResult> {
  const sinceIso = cursors.coredump ?? defaultSince;
  const since = sinceIso.replace("T", " ").replace(/\.\d+Z$/, "").replace("Z", "") + " UTC";
  const r = await d.exec("coredumpctl", ["list", "--no-pager", "--json=short", `--since=${since}`]).catch(() => null);
  if (!r) return { scope: "unsupported", events: [], cursors };
  // 1 = «No coredumps found»: leído, y no hubo.
  if (r.code === 1 && !r.stdout.trim()) return { scope: "collected", events: [], cursors };
  if (r.code !== 0) return { scope: "unavailable", events: [], cursors };
  // `--since` es por segundo y el cursor va al milisegundo: el borde se filtra aquí.
  const events = parseCoredumpctlJson(r.stdout).filter((e) => e.occurredAtUtc > sinceIso).slice(0, MAX_EVENTS_PER_READ);
  const next: Cursors = { ...cursors };
  for (const e of events) if (!next.coredump || e.occurredAtUtc > next.coredump) next.coredump = e.occurredAtUtc;
  return { scope: "collected", events, cursors: next };
}

async function linuxBoot(d: SourceDeps): Promise<BootResult> {
  // FinishTimestampMonotonic: µs desde que arrancó el kernel hasta que systemd
  // terminó el arranque. Sin systemd, no aplica.
  const r = await d.exec("systemctl", ["show", "--property=FinishTimestampMonotonic"]).catch(() => null);
  if (!r) return { scope: "unsupported", boot: null };
  const us = Number(r.stdout.match(/FinishTimestampMonotonic=(\d+)/)?.[1]);
  if (r.code !== 0 || !Number.isFinite(us) || us <= 0) return { scope: "unavailable", boot: null };
  const bootMs = d.nowMs() - d.uptimeSeconds() * 1000;
  return { scope: "collected", boot: { bootUtc: new Date(Math.floor(bootMs / 60_000) * 60_000).toISOString(), durationMs: Math.round(us / 1000) } };
}

async function linuxBattery(d: SourceDeps): Promise<BatteryResult> {
  const base = "/sys/class/power_supply";
  let names: string[];
  try {
    names = (await d.readDir(base)).filter((n) => /^BAT/i.test(n));
  } catch {
    return { scope: "unavailable", battery: null };
  }
  if (names.length === 0) return { scope: "collected", battery: { present: false } };
  const read = async (f: string) => Number((await d.readFile(`${base}/${names[0]}/${f}`).catch(() => "")).trim());
  // energy_* en µWh; si no, charge_* en µAh (la proporción es la misma).
  let full = await read("energy_full");
  let design = await read("energy_full_design");
  if (!(design > 0)) {
    full = await read("charge_full");
    design = await read("charge_full_design");
  }
  const cycles = await read("cycle_count");
  return {
    scope: "collected",
    battery: {
      present: true,
      healthPct: design > 0 && full >= 0 ? Math.round((full / design) * 10_000) / 100 : null,
      cycleCount: Number.isFinite(cycles) && cycles > 0 ? cycles : null,
    },
  };
}

// ── Entrada ──────────────────────────────────────────────────────────

/** `defaultSince` sólo para una fuente sin cursor (la primera vez). */
export async function readStabilityEvents(d: SourceDeps, cursors: Cursors, defaultSince: string): Promise<EventsResult> {
  if (d.platform === "win32") return windowsEvents(d, cursors, defaultSince);
  if (d.platform === "darwin") return macEvents(d, cursors, defaultSince);
  if (d.platform === "linux") return linuxEvents(d, cursors, defaultSince);
  return { scope: "unsupported", events: [], cursors };
}

export async function readBoot(d: SourceDeps): Promise<BootResult> {
  if (d.platform === "win32") return windowsBoot(d);
  if (d.platform === "linux") return linuxBoot(d);
  // macOS no deja la duración del arranque en ningún sitio estable.
  return { scope: "unsupported", boot: null };
}

export async function readBattery(d: SourceDeps): Promise<BatteryResult> {
  if (d.platform === "win32") return windowsBattery(d);
  if (d.platform === "darwin") return macBattery(d);
  if (d.platform === "linux") return linuxBattery(d);
  return { scope: "unsupported", battery: null };
}
