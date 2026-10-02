// src/plugins/pmp/verification.ts
//
// ADR-0038 F1 — verificación post-cambio, niveles 1 y 2, en el equipo.
//
// «¿Quién valida que los servicios levantaron después del reboot?» (el usuario,
// 1-oct-2026). Un servidor parcheado y reiniciado sin incidencias puede no
// haber levantado un servicio; se descubría cuando un usuario abría el informe.
//
//   Nivel 1 — servicios que cayeron. Justo ANTES de instalar se fotografían los
//             servicios de arranque automático que están EN MARCHA; tras el
//             reinicio y el asentamiento se compara. Es el suelo, no el
//             veredicto: funciona sin configurar nada.
//   Nivel 2 — comprobaciones declaradas (servicio, proceso, puerto, TCP, HTTP),
//             que manda el control plane por grupo. Corren antes Y después:
//             lo que ya fallaba antes no es culpa del parche.
//
// ⚠️ Ruido. Si el primer mes da falsos positivos, el cliente lo apaga. Por eso:
//   · se excluyen los servicios que arrancan por desencadenador (TriggerInfo)
//     y una lista corta de los que paran solos (actualizadores, instalador…);
//   · una regresión cuenta sólo si falla en TODAS las muestras (dos, separadas).
//
// ⚠️ Sin PowerShell, como live-query (un EDR lo vigila de cerca) y sin texto
// traducible: `tasklist /svc /FO CSV /NH` dice qué servicios corren (sin
// cabecera, sin etiquetas), y `reg query …\Services /s /v Start` cuáles
// arrancan solos (REG_DWORD 0x2 no se traduce). En Linux, `systemctl`.
//
// «No pude mirarlo» no es «no»: si no se puede leer, el nivel queda
// `unsupported`/`error` con el motivo, nunca «0 regresiones».

import net from "net";
import http from "http";
import https from "https";
import { runProbe, type ProbeDeps } from "../live-query/probes";

// ── Nivel 1: servicios ───────────────────────────────────────────────────────

/** Servicios que paran solos por diseño (no son una regresión). Minúsculas. */
const WINDOWS_SELF_STOPPING = new Set([
  "trustedinstaller", "msiserver", "wuauserv", "usosvc", "waasmedicsvc", "dosvc", "bits",
  "sppsvc", "gupdate", "gupdatem", "edgeupdate", "edgeupdatem", "mapsbroker", "remoteregistry",
  "tabletinputservice", "wersvc", "diagtrack", "clipsvc", "appxsvc", "installservice", "tiledatamodelsvc",
]);
const LINUX_SELF_STOPPING = new Set([
  "packagekit.service", "fwupd.service", "apt-daily.service", "apt-daily-upgrade.service",
  "systemd-timedated.service", "systemd-hostnamed.service", "systemd-localed.service",
  "unattended-upgrades.service", "man-db.service", "e2scrub_reap.service",
]);

/** Nombres de servicio en marcha, de `tasklist /svc /FO CSV /NH`. PURO. */
export function parseTasklistServices(out: string): Set<string> {
  const running = new Set<string>();
  for (const line of out.split(/\r?\n/)) {
    const cols = [...line.matchAll(/"([^"]*)"/g)].map((m) => m[1]);
    if (cols.length < 3) continue;
    for (const svc of cols[2].split(",")) {
      const name = svc.trim();
      // «N/A» (y su traducción) no es un nombre de servicio: no lleva espacios
      // un servicio, pero sí puede llevar «/»; se filtra lo que no parece nombre.
      if (name && !/^n\/a$/i.test(name) && !/\s/.test(name)) running.add(name.toLowerCase());
    }
  }
  return running;
}

/**
 * De `reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v Start`: los
 * servicios de arranque AUTOMÁTICO (Start = 0x2), en minúsculas. Sólo la clave
 * directa de cada servicio. PURO.
 */
export function parseAutoStartServices(out: string): Set<string> {
  const auto = new Set<string>();
  let current: string | null = null;
  for (const raw of out.split(/\r?\n/)) {
    const line = raw.trimEnd();
    const key = /^HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\([^\\]+)$/i.exec(line.trim());
    if (key) {
      current = key[1].toLowerCase();
      continue;
    }
    if (/^HKEY_/i.test(line.trim())) {
      current = null; // subclave (Parameters, Enum…): su «Start» no es el del servicio
      continue;
    }
    const v = /^\s+Start\s+REG_DWORD\s+0x([0-9a-f]+)\s*$/i.exec(line);
    if (v && current && parseInt(v[1], 16) === 2) auto.add(current);
  }
  return auto;
}

/** De `reg query …\Services /s /f TriggerInfo /k`: servicios con arranque por desencadenador. PURO. */
export function parseTriggerStartServices(out: string): Set<string> {
  const trig = new Set<string>();
  for (const line of out.split(/\r?\n/)) {
    const m = /^HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\([^\\]+)\\TriggerInfo$/i.exec(line.trim());
    if (m) trig.add(m[1].toLowerCase());
  }
  return trig;
}

/** Primera columna de `systemctl list-units|list-unit-files … --no-legend --plain`. PURO. */
export function parseSystemctlNames(out: string): Set<string> {
  const names = new Set<string>();
  for (const line of out.split(/\r?\n/)) {
    const first = line.trim().split(/\s+/)[0];
    if (first && first.endsWith(".service")) names.add(first);
  }
  return names;
}

export type ServiceSnapshot =
  | { ok: true; services: string[] }
  | { ok: false; reason: string };

/** Los servicios automáticos en marcha AHORA, menos los que paran solos. */
export async function snapshotServices(d: ProbeDeps): Promise<ServiceSnapshot> {
  try {
    if (d.platform === "win32") {
      const [tl, reg, trig] = await Promise.all([
        d.exec("tasklist", ["/svc", "/FO", "CSV", "/NH"], { timeoutMs: 30_000 }),
        d.exec("reg", ["query", "HKLM\\SYSTEM\\CurrentControlSet\\Services", "/s", "/v", "Start"], { timeoutMs: 60_000 }),
        d.exec("reg", ["query", "HKLM\\SYSTEM\\CurrentControlSet\\Services", "/s", "/f", "TriggerInfo", "/k"], { timeoutMs: 60_000 }),
      ]);
      if (tl.code !== 0) return { ok: false, reason: `tasklist exited ${tl.code}` };
      if (reg.code !== 0) return { ok: false, reason: `reg query exited ${reg.code}` };
      const running = parseTasklistServices(tl.stdout);
      const auto = parseAutoStartServices(reg.stdout);
      // Sin la lista de desencadenadores se sigue: sólo se pierde una exclusión.
      const trigger = trig.code === 0 ? parseTriggerStartServices(trig.stdout) : new Set<string>();
      const services = [...running].filter((s) => auto.has(s) && !trigger.has(s) && !WINDOWS_SELF_STOPPING.has(s));
      return { ok: true, services: services.sort() };
    }
    if (d.platform === "linux") {
      const [run, en] = await Promise.all([
        d.exec("systemctl", ["list-units", "--type=service", "--state=running", "--no-legend", "--plain", "--no-pager"]),
        d.exec("systemctl", ["list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--plain", "--no-pager"]),
      ]);
      if (run.code !== 0) return { ok: false, reason: `systemctl list-units exited ${run.code}` };
      if (en.code !== 0) return { ok: false, reason: `systemctl list-unit-files exited ${en.code}` };
      const enabled = parseSystemctlNames(en.stdout);
      const services = [...parseSystemctlNames(run.stdout)].filter((s) => enabled.has(s) && !LINUX_SELF_STOPPING.has(s));
      return { ok: true, services: services.sort() };
    }
    return { ok: false, reason: `service baseline not supported on ${d.platform}` };
  } catch (err: any) {
    return { ok: false, reason: err?.message || String(err) };
  }
}

// ── Nivel 2: comprobaciones declaradas ───────────────────────────────────────

export type VerificationCheck =
  | { id: string; kind: "service"; name: string }
  | { id: string; kind: "process"; name: string }
  | { id: string; kind: "port"; port: number }
  | { id: string; kind: "tcp"; host: string; port: number; timeoutMs?: number }
  | { id: string; kind: "http"; url: string; expectStatus?: number[]; bodyContains?: string; tlsVerify?: boolean; timeoutMs?: number };

export type CheckOutcome = { id: string; ok: boolean; detail: string };

const MAX_CHECKS = 25;

/** Valida y limpia las comprobaciones que manda el control plane. PURO. */
export function parseChecks(raw: unknown): VerificationCheck[] {
  if (!Array.isArray(raw)) return [];
  const out: VerificationCheck[] = [];
  const name = (v: unknown) => (typeof v === "string" && /^[A-Za-z0-9._@:+-]{1,128}$/.test(v) ? v : null);
  const port = (v: unknown) => (Number.isInteger(v) && (v as number) > 0 && (v as number) < 65536 ? (v as number) : null);
  for (const c of raw.slice(0, MAX_CHECKS)) {
    if (!c || typeof c !== "object") continue;
    const id = typeof (c as any).id === "string" ? String((c as any).id).slice(0, 64) : String(out.length);
    const kind = (c as any).kind;
    if ((kind === "service" || kind === "process") && name((c as any).name)) out.push({ id, kind, name: (c as any).name });
    else if (kind === "port" && port((c as any).port)) out.push({ id, kind, port: (c as any).port });
    else if (kind === "tcp" && port((c as any).port) && typeof (c as any).host === "string" && /^[A-Za-z0-9.:\[\]-]{1,253}$/.test((c as any).host)) {
      out.push({ id, kind, host: (c as any).host, port: (c as any).port, timeoutMs: (c as any).timeoutMs });
    } else if (kind === "http" && typeof (c as any).url === "string" && /^https?:\/\/[^\s]{1,2000}$/.test((c as any).url)) {
      const st = Array.isArray((c as any).expectStatus) ? (c as any).expectStatus.filter((n: unknown) => Number.isInteger(n)) : undefined;
      out.push({
        id, kind, url: (c as any).url,
        expectStatus: st && st.length ? st : undefined,
        bodyContains: typeof (c as any).bodyContains === "string" ? String((c as any).bodyContains).slice(0, 200) : undefined,
        tlsVerify: (c as any).tlsVerify !== false,
        timeoutMs: (c as any).timeoutMs,
      });
    }
  }
  return out;
}

function clampTimeout(ms: unknown): number {
  const n = Number(ms);
  return Number.isFinite(n) ? Math.min(Math.max(n, 1000), 30_000) : 10_000;
}

function tcpCheck(host: string, port: number, timeoutMs: number): Promise<CheckOutcome["detail"] | null> {
  return new Promise((resolve) => {
    const s = net.createConnection({ host, port });
    const done = (err: string | null) => { s.destroy(); resolve(err); };
    s.setTimeout(timeoutMs, () => done(`no answer in ${timeoutMs} ms`));
    s.once("connect", () => done(null));
    s.once("error", (e: any) => done(e?.code || e?.message || "error"));
  });
}

function httpCheck(c: Extract<VerificationCheck, { kind: "http" }>): Promise<CheckOutcome> {
  return new Promise((resolve) => {
    const timeoutMs = clampTimeout(c.timeoutMs);
    const lib = c.url.startsWith("https:") ? https : http;
    const req = lib.get(c.url, { timeout: timeoutMs, rejectUnauthorized: c.tlsVerify !== false } as any, (res) => {
      const status = res.statusCode ?? 0;
      const okStatus = c.expectStatus ? c.expectStatus.includes(status) : status >= 200 && status < 400;
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { if (body.length < 64 * 1024) body += chunk; });
      res.on("end", () => {
        const okBody = c.bodyContains ? body.includes(c.bodyContains) : true;
        resolve({
          id: c.id,
          ok: okStatus && okBody,
          detail: `HTTP ${status}${okBody ? "" : `; body does not contain the expected text`}`,
        });
      });
    });
    req.on("timeout", () => { req.destroy(); resolve({ id: c.id, ok: false, detail: `no answer in ${timeoutMs} ms` }); });
    req.on("error", (e: any) => resolve({ id: c.id, ok: false, detail: e?.code || e?.message || "error" }));
  });
}

/** Una comprobación. Nunca lanza: lo que no se puede mirar es un fallo con motivo. */
export async function runCheck(d: ProbeDeps, c: VerificationCheck): Promise<CheckOutcome> {
  try {
    if (c.kind === "tcp") {
      const err = await tcpCheck(c.host, c.port, clampTimeout(c.timeoutMs));
      return { id: c.id, ok: err === null, detail: err === null ? `connected to ${c.host}:${c.port}` : err };
    }
    if (c.kind === "http") return await httpCheck(c);
    const probe =
      c.kind === "port"
        ? await runProbe(d, { probe: "port", params: { port: c.port } })
        : await runProbe(d, { probe: c.kind, params: { name: c.name } });
    if (probe.outcome !== "answered") {
      return { id: c.id, ok: false, detail: probe.outcome === "error" ? probe.error : `${c.kind} check not supported here` };
    }
    const a = probe.answer as any;
    if (c.kind === "service") return { id: c.id, ok: a.exists === true && a.state === "running", detail: a.exists === false ? "service not found" : `state ${a.state}` };
    if (c.kind === "process") return { id: c.id, ok: a.running === true, detail: a.running ? `${a.count} running` : "not running" };
    return { id: c.id, ok: a.listening === true, detail: a.listening ? `listening${a.process ? ` (${a.process})` : ""}` : "not listening" };
  } catch (err: any) {
    return { id: c.id, ok: false, detail: err?.message || String(err) };
  }
}

// ── El veredicto ─────────────────────────────────────────────────────────────

export interface VerificationBaseline {
  jobId: string;
  capturedAt: string;
  services: ServiceSnapshot;
  checks: VerificationCheck[];
  checksBefore: CheckOutcome[];
}

export interface VerificationResult {
  patchJobId: string;
  status: "passed" | "failed" | "no_baseline";
  baselineAt: string | null;
  services:
    | { level: 1; status: "compared"; watched: number; regressions: string[] }
    | { level: 1; status: "unavailable"; reason: string };
  checks: Array<{ id: string; kind: string; before: boolean | null; after: boolean; regression: boolean; alreadyFailing: boolean; detail: string }>;
  samples: number;
}

/**
 * Compara la foto previa con las muestras de después. PURO.
 * Una regresión cuenta sólo si se ve en TODAS las muestras.
 */
export function compareVerification(
  patchJobId: string,
  baseline: VerificationBaseline | null,
  afterServices: ServiceSnapshot[],
  checks: VerificationCheck[],
  afterChecks: CheckOutcome[][]
): VerificationResult {
  let services: VerificationResult["services"];
  if (!baseline || !baseline.services.ok) {
    services = { level: 1, status: "unavailable", reason: !baseline ? "no pre-install snapshot on this device" : (baseline.services as any).reason };
  } else if (afterServices.some((s) => !s.ok)) {
    const bad = afterServices.find((s) => !s.ok) as { ok: false; reason: string };
    services = { level: 1, status: "unavailable", reason: bad.reason };
  } else {
    const samples = afterServices.map((s) => new Set((s as { ok: true; services: string[] }).services));
    const regressions = baseline.services.services.filter((name) => samples.every((set) => !set.has(name)));
    services = { level: 1, status: "compared", watched: baseline.services.services.length, regressions };
  }

  const before = new Map((baseline?.checksBefore ?? []).map((c) => [c.id, c.ok]));
  const rows = checks.map((c) => {
    const outs = afterChecks.map((round) => round.find((o) => o.id === c.id)).filter(Boolean) as CheckOutcome[];
    const after = outs.some((o) => o.ok); // falla sólo si falla en TODAS las muestras
    const was = before.has(c.id) ? (before.get(c.id) as boolean) : null;
    return {
      id: c.id,
      kind: c.kind,
      before: was,
      after,
      // Sin dato previo (equipo sin foto) un fallo cuenta: no hay con qué excusarlo.
      regression: !after && was !== false,
      alreadyFailing: !after && was === false,
      detail: (outs[outs.length - 1]?.detail ?? "not run").slice(0, 200),
    };
  });

  const failed = (services.status === "compared" && services.regressions.length > 0) || rows.some((r) => r.regression);
  return {
    patchJobId,
    status: failed ? "failed" : !baseline && checks.length === 0 ? "no_baseline" : "passed",
    baselineAt: baseline?.capturedAt ?? null,
    services,
    checks: rows,
    samples: afterServices.length,
  };
}
