// src/plugins/dex/dex-windows.ts
//
// ADR-0030 F2 — muestreo de CPU y memoria y su resumen en ventanas de 15 min.
//
// Lógica pura: quien llama da la hora y las lecturas. Una muestra por minuto;
// cada ventana está alineada a su rejilla (10:00, 10:15…) — el backend alinea
// igual, así que dos versiones de la misma ventana chocan en vez de sumarse.
//
// ⚠️ Nunca se inventa una muestra. Un equipo suspendido o un agente que se
// reinicia deja la ventana con menos `samples`, y así viaja: el hueco es un
// dato, no algo que rellenar.

import os from "os";

export const WINDOW_MINUTES = 15;
const WINDOW_MS = WINDOW_MINUTES * 60_000;
/** Ventanas cerradas que se guardan sin enviar (24 h): más allá, el backend ya las habría tirado. */
export const MAX_PENDING_WINDOWS = 96;

export type CpuTimes = { idle: number; total: number };

/** Suma de los contadores de todos los núcleos (os.cpus()). Sin subprocesos. */
export function readCpuTimes(cpus: Array<{ times: Record<string, number> }> = os.cpus()): CpuTimes | null {
  if (!Array.isArray(cpus) || cpus.length === 0) return null;
  let idle = 0;
  let total = 0;
  for (const c of cpus) {
    const t = c?.times ?? {};
    for (const v of Object.values(t)) total += Number(v) || 0;
    idle += Number(t.idle) || 0;
  }
  return total > 0 ? { idle, total } : null;
}

/** % de CPU ocupada entre dos lecturas; null si no hay avance (reloj parado, contador reiniciado). */
export function cpuPercent(prev: CpuTimes | null, cur: CpuTimes | null): number | null {
  if (!prev || !cur) return null;
  const dTotal = cur.total - prev.total;
  const dIdle = cur.idle - prev.idle;
  if (dTotal <= 0 || dIdle < 0 || dIdle > dTotal) return null;
  return Math.round(((dTotal - dIdle) / dTotal) * 10_000) / 100;
}

export type ClosedWindow = {
  startUtc: string;
  minutes: number;
  samples: number;
  cpuAvgPct: number | null;
  cpuMaxPct: number | null;
  memAvgPct: number | null;
  memMaxPct: number | null;
};

type Acc = { start: number; samples: number; cpuSum: number; cpuN: number; cpuMax: number | null; memSum: number; memN: number; memMax: number | null };

const round2 = (v: number) => Math.round(v * 100) / 100;

function close(a: Acc): ClosedWindow {
  return {
    startUtc: new Date(a.start).toISOString(),
    minutes: WINDOW_MINUTES,
    samples: a.samples,
    cpuAvgPct: a.cpuN ? round2(a.cpuSum / a.cpuN) : null,
    cpuMaxPct: a.cpuMax,
    memAvgPct: a.memN ? round2(a.memSum / a.memN) : null,
    memMaxPct: a.memMax,
  };
}

export class DexWindowAggregator {
  private cur: Acc | null = null;
  private pending: ClosedWindow[] = [];

  constructor(initialPending: ClosedWindow[] = []) {
    this.pending = initialPending.slice(-MAX_PENDING_WINDOWS);
  }

  /** Añade una muestra; cierra la ventana anterior si ésta cae en otra. */
  add(atMs: number, cpuPct: number | null, memPct: number | null): void {
    const start = Math.floor(atMs / WINDOW_MS) * WINDOW_MS;
    if (this.cur && this.cur.start !== start) this.closeCurrent();
    if (!this.cur) this.cur = { start, samples: 0, cpuSum: 0, cpuN: 0, cpuMax: null, memSum: 0, memN: 0, memMax: null };
    const a = this.cur;
    a.samples += 1;
    if (cpuPct !== null) {
      a.cpuSum += cpuPct;
      a.cpuN += 1;
      a.cpuMax = a.cpuMax === null ? cpuPct : Math.max(a.cpuMax, cpuPct);
    }
    if (memPct !== null) {
      a.memSum += memPct;
      a.memN += 1;
      a.memMax = a.memMax === null ? memPct : Math.max(a.memMax, memPct);
    }
  }

  /** Cierra la ventana en curso si su cuarto de hora ya pasó (el equipo estuvo dormido). */
  closeElapsed(nowMs: number): void {
    if (this.cur && nowMs >= this.cur.start + WINDOW_MS) this.closeCurrent();
  }

  private closeCurrent() {
    if (this.cur && this.cur.samples > 0) {
      this.pending.push(close(this.cur));
      if (this.pending.length > MAX_PENDING_WINDOWS) this.pending.splice(0, this.pending.length - MAX_PENDING_WINDOWS);
    }
    this.cur = null;
  }

  /** Ventanas cerradas pendientes de envío (copia). */
  pendingWindows(): ClosedWindow[] {
    return this.pending.slice();
  }

  /** Quita las que ya salieron (por inicio): lo que llegó mientras tanto se queda. */
  acknowledge(sent: ClosedWindow[]): void {
    const done = new Set(sent.map((w) => w.startUtc));
    this.pending = this.pending.filter((w) => !done.has(w.startUtc));
  }
}

// ── Memoria ──────────────────────────────────────────────────────────

/**
 * % de memoria EN USO = 1 − disponible / total.
 *
 * Windows: os.freemem() es la memoria física disponible (GlobalMemoryStatusEx).
 * Linux: os.freemem() es MemAvailable (libuv ≥ 1.45), que cuenta la caché que
 * el kernel devuelve bajo presión. macOS: os.freemem() son sólo las páginas
 * LIBRES — sin la inactiva ni la purgable, así que un Mac sano parecería
 * siempre lleno. Allí se lee vm_stat (ver parseVmStat).
 */
export function memPercentFromFree(free: number, total: number): number | null {
  if (!(total > 0) || !(free >= 0) || free > total) return null;
  return Math.round((1 - free / total) * 10_000) / 100;
}

/** vm_stat: disponible = libres + inactivas + especulativas + purgables. */
export function parseVmStat(out: string): { availableBytes: number } | null {
  const text = String(out);
  const pageSize = Number(text.match(/page size of (\d+) bytes/)?.[1]);
  if (!(pageSize > 0)) return null;
  const pages = (label: string) => Number(text.match(new RegExp(`^${label}:\\s+(\\d+)\\.`, "m"))?.[1] ?? NaN);
  const parts = ["Pages free", "Pages inactive", "Pages speculative", "Pages purgeable"].map(pages);
  if (!Number.isFinite(parts[0]) || !Number.isFinite(parts[1])) return null;
  return { availableBytes: parts.reduce((s, n) => s + (Number.isFinite(n) ? n : 0), 0) * pageSize };
}
