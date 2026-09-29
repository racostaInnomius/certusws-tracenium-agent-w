// test/plugins/pmp-os-update-action.test.ts
//
// La acción para el usuario `os.update` (ADR-0036 D1): instalar una
// actualización de macOS que el agente no puede —en Apple silicon pide la
// contraseña de un propietario, job e4689371—. Era os_update_nudge (4fb0f20);
// los casos son los mismos, sobre el contrato genérico.

import fs from "fs";
import os from "os";
import path from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { labelsFromScan, osUpdateStillPending, refreshOsUpdateActionsAfterScan } from "../../src/plugins/pmp/os-update-action";
import { acceptUserActionJob, loadUserActions, parseUserActionPayload, type UserAction } from "../../src/user-actions/user-actions";

const NOW = new Date("2026-09-29T15:00:00Z");
const scan = (labels: string[], status = "updates_available") =>
  ({ overall: { status }, scan: { items: labels.map((hotFixId) => ({ hotFixId })) } }) as any;
const action = (label: string, deadlineUtc = "2026-10-06T23:00:00Z", expiresUtc = "2026-11-05T23:00:00Z"): UserAction => ({
  actionId: `act-${label.replace(/[^A-Za-z0-9]/g, "")}`.slice(0, 40),
  kind: "os.update",
  params: { label, title: label.replace(/-.*$/, "") },
  deadlineUtc,
  expiresUtc,
  jobId: "j1",
  requestedAtUtc: NOW.toISOString(),
});
const request = (label: string, extra: Record<string, unknown> = {}) =>
  parseUserActionPayload(
    { op: "request", actionId: `act-${label.replace(/[^A-Za-z0-9]/g, "")}`.slice(0, 40), kind: "os.update", params: { label }, deadlineUtc: "2026-10-06T23:00:00Z", expiresUtc: "2026-11-05T23:00:00Z", ...extra },
    "j1",
    NOW,
  ) as any;

describe("os.update — cuándo está hecha", () => {
  const list = [action("macOS 27.0.1-26A434"), action("macOS Tahoe 26.7.1-25G241", "2026-10-02T23:00:00Z")];

  it("🔴 la que el escaneo ya no lista está instalada", () => {
    const pending = osUpdateStillPending(["macOS Tahoe 26.7.1-25G241", "Safari27.0TahoeAuto-27.0"])!;
    expect(list.filter(pending).map((a) => a.params.label)).toEqual(["macOS Tahoe 26.7.1-25G241"]);
  });

  it("⚠️ un escaneo fallido no da nada por instalado", () => {
    expect(labelsFromScan(scan([], "error"))).toBeNull();
    expect(osUpdateStillPending(null)).toBeNull();
  });

  it("un escaneo limpio (nada pendiente) las da todas por hechas", () => {
    expect(labelsFromScan(scan([], "healthy"))).toEqual([]);
    expect(list.filter(osUpdateStillPending([])!)).toEqual([]);
  });
});

describe("estado en disco y bandeja", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "user-actions-"));
    process.env.TRACENIUM_STATE_DIR = dir;
  });
  afterEach(() => {
    delete process.env.TRACENIUM_STATE_DIR;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("⭐ guardar publica a la bandeja; instalarla la retira", () => {
    const setUserActions = vi.fn();
    const ctx = { trayStatus: { setUserActions } } as any;

    acceptUserActionJob(ctx, request("macOS 27.0.1-26A434"), NOW);
    expect(loadUserActions()).toHaveLength(1);
    expect(setUserActions).toHaveBeenLastCalledWith([
      expect.objectContaining({ kind: "os.update", title: "macOS 27.0.1-26A434", params: { label: "macOS 27.0.1-26A434" } }),
    ]);

    // Un escaneo que aún la lista no toca nada.
    refreshOsUpdateActionsAfterScan(ctx, scan(["macOS 27.0.1-26A434"]), NOW);
    expect(setUserActions).toHaveBeenCalledTimes(1);

    // Un escaneo fallido tampoco.
    refreshOsUpdateActionsAfterScan(ctx, scan([], "error"), NOW);
    expect(loadUserActions()).toHaveLength(1);

    // Instalada: el escaneo ya no la lista.
    refreshOsUpdateActionsAfterScan(ctx, scan(["Safari27.0TahoeAuto-27.0"]), NOW);
    expect(loadUserActions()).toEqual([]);
    expect(setUserActions).toHaveBeenLastCalledWith(null);
  });

  it("❗ pasada la caducidad que fija el servidor se deja de insistir, aunque siga sin instalar", () => {
    const setUserActions = vi.fn();
    const ctx = { trayStatus: { setUserActions }, logger: { info: vi.fn() } } as any;
    acceptUserActionJob(ctx, request("macOS 26.0-25A1"), NOW);
    refreshOsUpdateActionsAfterScan(ctx, scan(["macOS 26.0-25A1"]), new Date("2026-11-06T00:00:00Z"));
    expect(loadUserActions()).toEqual([]);
    expect(ctx.logger.info).toHaveBeenCalledWith("user action expired without being done", expect.objectContaining({ kind: "os.update" }));
  });

  it("sin acciones, un escaneo no escribe nada", () => {
    const setUserActions = vi.fn();
    refreshOsUpdateActionsAfterScan({ trayStatus: { setUserActions } } as any, scan([]), NOW);
    expect(setUserActions).not.toHaveBeenCalled();
    expect(fs.existsSync(path.join(dir, "user-actions.json"))).toBe(false);
  });
});
