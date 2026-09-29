// test/plugins/pmp-os-update-nudge.test.ts
//
// Pedirle al usuario de un Mac que instale una actualización de macOS antes de
// una fecha (job `os_update_nudge`, 29-sep). En Apple silicon el agente no
// puede instalarla: pide la contraseña de un propietario (job e4689371).

import fs from "fs";
import os from "os";
import path from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  acceptNudge,
  labelsFromScan,
  loadNudges,
  parseNudgePayload,
  reconcileNudges,
  refreshNudgesAfterScan,
  trayRequestFrom,
  upsertNudge,
  type OsUpdateNudge,
} from "../../src/plugins/pmp/os-update-nudge";

const NOW = new Date("2026-09-29T15:00:00Z");
const nudge = (label: string, deadlineUtc: string, jobId = `job-${label}`): OsUpdateNudge => ({
  jobId, label, title: label.replace(/-.*$/, ""), deadlineUtc, requestedAtUtc: NOW.toISOString(),
});
const scan = (labels: string[], status = "updates_available") =>
  ({ overall: { status }, scan: { items: labels.map((hotFixId) => ({ hotFixId })) } }) as any;

describe("parseNudgePayload", () => {
  it("acepta lo que manda el portal", () => {
    const r = parseNudgePayload({ label: "macOS 27.0.1-26A434", title: "macOS 27.0.1", deadlineUtc: "2026-10-06T23:00:00.000Z" }, "j1", NOW);
    expect(r).toEqual({
      ok: true,
      nudge: { jobId: "j1", label: "macOS 27.0.1-26A434", title: "macOS 27.0.1", deadlineUtc: "2026-10-06T23:00:00.000Z", requestedAtUtc: NOW.toISOString() },
    });
  });

  it("⭐ una fecha ya vencida (equipo apagado días) se guarda igual: el aviso sale vencido", () => {
    expect(parseNudgePayload({ label: "macOS 27.0.1-26A434", deadlineUtc: "2026-09-01T00:00:00Z" }, "j1", NOW).ok).toBe(true);
  });

  it("rechaza lo que no se puede enseñar", () => {
    expect(parseNudgePayload({ label: " ", deadlineUtc: "2026-10-06T23:00:00Z" }, "j1").ok).toBe(false);
    expect(parseNudgePayload({ label: "macOS 27", deadlineUtc: "pronto" }, "j1").ok).toBe(false);
    expect(parseNudgePayload(null, "j1").ok).toBe(false);
  });
});

describe("reconcileNudges — cuándo deja de pedirse", () => {
  const list = [nudge("macOS 27.0.1-26A434", "2026-10-06T23:00:00Z"), nudge("macOS Tahoe 26.7.1-25G241", "2026-10-02T23:00:00Z")];

  it("🔴 la que el escaneo ya no lista está instalada y se retira", () => {
    expect(reconcileNudges(list, ["macOS Tahoe 26.7.1-25G241", "Safari27.0TahoeAuto-27.0"], NOW).map((n) => n.label))
      .toEqual(["macOS Tahoe 26.7.1-25G241"]);
  });

  it("⚠️ un escaneo fallido no da nada por instalado", () => {
    expect(labelsFromScan(scan([], "error"))).toBeNull();
    expect(reconcileNudges(list, null, NOW)).toEqual(list);
  });

  it("un escaneo limpio (nada pendiente) sí las retira todas", () => {
    expect(labelsFromScan(scan([], "healthy"))).toEqual([]);
    expect(reconcileNudges(list, [], NOW)).toEqual([]);
  });

  it("pasados 30 días de la fecha se deja de insistir", () => {
    const old = nudge("macOS 26.0-25A1", "2026-08-01T00:00:00Z");
    expect(reconcileNudges([old], ["macOS 26.0-25A1"], NOW)).toEqual([]);
    expect(reconcileNudges([old], null, NOW)).toEqual([]);
  });
});

describe("upsertNudge / trayRequestFrom", () => {
  it("otra petición sobre la misma etiqueta cambia la fecha, no duplica", () => {
    const a = nudge("macOS 27.0.1-26A434", "2026-10-06T23:00:00Z", "j1");
    const b = nudge("macOS 27.0.1-26A434", "2026-10-02T23:00:00Z", "j2");
    expect(upsertNudge([a], b)).toEqual([b]);
  });

  it("la bandeja enseña la de fecha más cercana y cuántas hay", () => {
    const list = [nudge("macOS 27.0.1-26A434", "2026-10-06T23:00:00Z"), nudge("macOS Tahoe 26.7.1-25G241", "2026-10-02T23:00:00Z")];
    expect(trayRequestFrom(list)).toEqual({
      label: "macOS Tahoe 26.7.1-25G241", title: "macOS Tahoe 26.7.1", deadlineUtc: "2026-10-02T23:00:00Z", pendingCount: 2,
    });
    expect(trayRequestFrom([])).toBeUndefined();
  });
});

describe("estado en disco y bandeja", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "nudge-"));
    process.env.TRACENIUM_STATE_DIR = dir;
  });
  afterEach(() => {
    delete process.env.TRACENIUM_STATE_DIR;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("⭐ guardar publica a la bandeja; instalarla la retira", () => {
    const setOsUpdateRequest = vi.fn();
    const ctx = { trayStatus: { setOsUpdateRequest } } as any;

    acceptNudge(ctx, nudge("macOS 27.0.1-26A434", "2026-10-06T23:00:00Z"));
    expect(loadNudges()).toHaveLength(1);
    expect(setOsUpdateRequest).toHaveBeenLastCalledWith(expect.objectContaining({ label: "macOS 27.0.1-26A434" }));

    // Un escaneo que aún la lista no toca nada.
    refreshNudgesAfterScan(ctx, scan(["macOS 27.0.1-26A434"]), NOW);
    expect(setOsUpdateRequest).toHaveBeenCalledTimes(1);

    // Instalada: el escaneo ya no la lista.
    refreshNudgesAfterScan(ctx, scan(["Safari27.0TahoeAuto-27.0"]), NOW);
    expect(loadNudges()).toEqual([]);
    expect(setOsUpdateRequest).toHaveBeenLastCalledWith(null);
  });

  it("sin peticiones, un escaneo no escribe nada", () => {
    const setOsUpdateRequest = vi.fn();
    refreshNudgesAfterScan({ trayStatus: { setOsUpdateRequest } } as any, scan([]), NOW);
    expect(setOsUpdateRequest).not.toHaveBeenCalled();
    expect(fs.existsSync(path.join(dir, "os-update-nudges.json"))).toBe(false);
  });
});
