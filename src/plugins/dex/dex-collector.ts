// src/plugins/dex/dex-collector.ts
//
// ADR-0030 F2 — el colector de experiencia del equipo.
//
//   · cada minuto: una muestra de CPU y memoria, sin subprocesos (salvo
//     vm_stat en macOS, ver dex-windows.ts), a la ventana de 15 min en curso;
//   · cada hora (con jitter, para que la flota no llegue a la vez): las
//     ventanas cerradas, los eventos de estabilidad nuevos, el arranque si
//     cambió y la batería una vez al día, en el namespace `dex`, solo, por el
//     outbox.
//
// El estado que tiene que sobrevivir a un reinicio (ventanas cerradas sin
// enviar, cursor de cada fuente de eventos, último arranque y última batería
// enviados) vive en agent.db. Un reinicio pierde, como mucho, la ventana en
// curso — y eso viaja como una ventana con menos muestras, no se inventa.

import os from "os";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { FACTS_SCHEMA_VERSION } from "../../update/update-source-report";
import { defaultExec, type ExecFn } from "../live-query/probes";
import { DexWindowAggregator, cpuPercent, memPercentFromFree, parseVmStat, readCpuTimes, type ClosedWindow, type CpuTimes } from "./dex-windows";
import { readBattery, readBoot, readStabilityEvents, type Cursors, type Scope, type SourceDeps } from "./dex-sources";

export const DEX_FACTS_NAMESPACE = "dex";
export const SAMPLE_MS = 60_000;
export const FLUSH_MS = 60 * 60_000;
export const FLUSH_JITTER_MS = 5 * 60_000;
export const BATTERY_EVERY_MS = 24 * 60 * 60_000;
/** Primera lectura de eventos: la última semana, lo que miran las señales. */
export const FIRST_LOOKBACK_MS = 7 * 24 * 60 * 60_000;

const KEY = { windows: "dex.pendingWindows", cursors: "dex.cursors", boot: "dex.lastBootSent", battery: "dex.lastBatteryAt" };

export type DexCollectorDeps = {
  enabled: () => boolean;
  nowMs: () => number;
  readCpu: () => CpuTimes | null;
  readMemPct: () => Promise<number | null>;
  sources: SourceDeps;
  getState: (k: string) => string | null;
  setState: (k: string, v: string) => void;
  enqueue: (payload: unknown) => number;
  logger?: { info?: (...a: any[]) => void; warn?: (...a: any[]) => void; debug?: (...a: any[]) => void };
};

function readJson<T>(raw: string | null, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export class DexCollector {
  private agg: DexWindowAggregator;
  private lastCpu: CpuTimes | null = null;
  private sampleTimer: NodeJS.Timeout | null = null;
  private flushTimer: NodeJS.Timeout | null = null;
  private flushing = false;
  private savedPending = 0;

  constructor(private readonly d: DexCollectorDeps) {
    this.agg = new DexWindowAggregator(readJson<ClosedWindow[]>(d.getState(KEY.windows), []));
    this.savedPending = this.agg.pendingWindows().length;
  }

  start(): void {
    this.stop();
    this.lastCpu = this.d.readCpu();
    this.sampleTimer = setInterval(() => void this.sample(), SAMPLE_MS);
    this.sampleTimer.unref?.();
    this.armFlush();
  }

  stop(): void {
    if (this.sampleTimer) clearInterval(this.sampleTimer);
    if (this.flushTimer) clearTimeout(this.flushTimer);
    this.sampleTimer = null;
    this.flushTimer = null;
  }

  private armFlush() {
    const delay = FLUSH_MS + Math.floor(Math.random() * FLUSH_JITTER_MS);
    this.flushTimer = setTimeout(() => {
      void this.flush().finally(() => this.armFlush());
    }, delay);
    this.flushTimer.unref?.();
  }

  /** Una muestra. Público para los tests. */
  async sample(): Promise<void> {
    if (!this.d.enabled()) {
      // Sin AMP no se mide, y la lectura de CPU se reinicia: la próxima muestra
      // no puede promediar las horas que estuvo apagado.
      this.lastCpu = null;
      return;
    }
    const now = this.d.nowMs();
    const cur = this.d.readCpu();
    const cpu = cpuPercent(this.lastCpu, cur);
    this.lastCpu = cur;
    const mem = await this.d.readMemPct().catch(() => null);
    this.agg.add(now, cpu, mem);
    this.persistPendingIfChanged();
  }

  private persistPendingIfChanged() {
    const pending = this.agg.pendingWindows();
    if (pending.length !== this.savedPending) {
      this.d.setState(KEY.windows, JSON.stringify(pending));
      this.savedPending = pending.length;
    }
  }

  /** El envío horario. Público para los tests. Devuelve el payload enviado, o null. */
  async flush(): Promise<Record<string, unknown> | null> {
    if (this.flushing || !this.d.enabled()) return null;
    this.flushing = true;
    try {
      const now = this.d.nowMs();
      this.agg.closeElapsed(now);
      const windows = this.agg.pendingWindows();

      const cursors = readJson<Cursors>(this.d.getState(KEY.cursors), {});
      const defaultSince = new Date(now - FIRST_LOOKBACK_MS).toISOString();
      const ev = await readStabilityEvents(this.d.sources, cursors, defaultSince).catch((err) => {
        this.d.logger?.warn?.("[dex] reading stability events failed", { err: err?.message || err });
        return { scope: "unavailable" as Scope, events: [], cursors };
      });

      const boot = await readBoot(this.d.sources).catch(() => ({ scope: "unavailable" as Scope, boot: null }));
      const lastBoot = this.d.getState(KEY.boot);
      const sendBoot = boot.boot && boot.boot.bootUtc !== lastBoot ? boot.boot : null;

      const lastBattery = Number(this.d.getState(KEY.battery) ?? 0);
      const batteryDue = !(lastBattery > 0) || now - lastBattery >= BATTERY_EVERY_MS;
      const bat = batteryDue ? await readBattery(this.d.sources).catch(() => ({ scope: "unavailable" as Scope, battery: null })) : null;

      const payload = {
        schema: 1,
        windows,
        events: ev.events,
        boot: sendBoot,
        battery: bat?.battery ?? null,
        scope: {
          resources: "collected",
          events: ev.scope,
          boot: boot.scope,
          // Si hoy no tocaba leerla, se repite lo último que se supo del scope.
          battery: bat ? bat.scope : this.d.getState("dex.lastBatteryScope") ?? "unavailable",
        },
      };

      this.d.enqueue({ schemaVersion: FACTS_SCHEMA_VERSION, namespaces: { [DEX_FACTS_NAMESPACE]: payload } });

      // Encolado en el outbox (persistente): ya no se pierde. Se da por enviado.
      this.agg.acknowledge(windows);
      this.persistPendingIfChanged();
      this.d.setState(KEY.cursors, JSON.stringify(ev.cursors));
      if (sendBoot) this.d.setState(KEY.boot, sendBoot.bootUtc);
      if (bat) {
        this.d.setState(KEY.battery, String(now));
        this.d.setState("dex.lastBatteryScope", bat.scope);
      }
      this.d.logger?.info?.("[dex] report queued", { windows: windows.length, events: ev.events.length, eventsScope: ev.scope, boot: Boolean(sendBoot), battery: Boolean(bat?.battery) });
      return payload;
    } finally {
      this.flushing = false;
    }
  }
}

// ── Dependencias reales ──────────────────────────────────────────────

export async function defaultMemPct(platform: NodeJS.Platform = os.platform(), exec: ExecFn = defaultExec): Promise<number | null> {
  if (platform === "darwin") {
    const r = await exec("vm_stat", []).catch(() => null);
    const vm = r && r.code === 0 ? parseVmStat(r.stdout) : null;
    return vm ? memPercentFromFree(vm.availableBytes, os.totalmem()) : null;
  }
  return memPercentFromFree(os.freemem(), os.totalmem());
}

export function defaultSourceDeps(): SourceDeps {
  return {
    platform: os.platform(),
    exec: defaultExec,
    readFile: (p) => fs.promises.readFile(p, "utf8"),
    readDir: (p) => fs.promises.readdir(p),
    stat: (p) => fs.promises.stat(p),
    tmpFile: () => path.join(os.tmpdir(), `tracenium-battery-${crypto.randomUUID()}.xml`),
    removeFile: (p) => fs.promises.rm(p, { force: true }),
    nowMs: () => Date.now(),
    uptimeSeconds: () => os.uptime(),
  };
}
