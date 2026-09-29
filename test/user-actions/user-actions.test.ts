// test/user-actions/user-actions.test.ts
//
// ADR-0036 D1 — el contrato genérico de «acción para el usuario»: payload del
// job, alta/sustitución/cancelación, caducidad, orden para la bandeja y
// telemetría de la bandeja (que NUNCA cierra una acción).

import fs from "fs";
import os from "os";
import path from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  acceptUserActionJob,
  applyEvents,
  cancelAction,
  closeObserved,
  loadUserActions,
  parseUserActionPayload,
  partitionExpired,
  reconcileKind,
  trayActionsFrom,
  upsertAction,
  type UserAction,
} from "../../src/user-actions/user-actions";
import { consumeUserActionEvents, parseUserActionEvents } from "../../src/user-actions/user-action-events-watcher";

const NOW = new Date("2026-09-29T15:00:00Z");
const base = {
  op: "request",
  actionId: "0b6c2f0e-1111-2222-3333-444444444444",
  kind: "os.update",
  params: { label: "macOS 27.0.1-26A434", title: "macOS 27.0.1" },
  deadlineUtc: "2026-10-06T23:00:00.000Z",
  expiresUtc: "2026-11-05T23:00:00.000Z",
};
const act = (over: Partial<UserAction> = {}): UserAction => ({
  actionId: "act-00000001",
  kind: "os.update",
  params: { label: "macOS 27.0.1-26A434" },
  deadlineUtc: "2026-10-06T23:00:00Z",
  expiresUtc: "2026-11-05T23:00:00Z",
  jobId: "j1",
  requestedAtUtc: NOW.toISOString(),
  ...over,
});

describe("parseUserActionPayload", () => {
  it("acepta lo que manda el servidor (ya normalizado)", () => {
    const r = parseUserActionPayload(base, "j1", NOW);
    expect(r).toEqual({
      ok: true,
      op: "request",
      action: {
        actionId: base.actionId, kind: "os.update", params: { label: "macOS 27.0.1-26A434", title: "macOS 27.0.1" },
        deadlineUtc: base.deadlineUtc, expiresUtc: base.expiresUtc, jobId: "j1", requestedAtUtc: NOW.toISOString(),
      },
    });
  });

  it("⭐ una fecha ya vencida (equipo apagado días) se guarda igual: el aviso sale vencido", () => {
    expect(parseUserActionPayload({ ...base, deadlineUtc: "2026-09-01T00:00:00Z" }, "j1", NOW).ok).toBe(true);
  });

  it("❗ una acción ya caducada no se guarda", () => {
    expect(parseUserActionPayload({ ...base, expiresUtc: "2026-09-28T00:00:00Z" }, "j1", NOW)).toEqual({ ok: false, error: "user_action_expired" });
  });

  it("rechaza lo que no se puede enseñar ni cerrar", () => {
    expect(parseUserActionPayload({ ...base, params: { label: " " } }, "j1", NOW)).toMatchObject({ ok: false, error: "invalid_user_action_params" });
    expect(parseUserActionPayload({ ...base, kind: "profile.install" }, "j1", NOW)).toMatchObject({ ok: false, error: "unsupported_user_action_kind" });
    expect(parseUserActionPayload({ ...base, deadlineUtc: undefined }, "j1", NOW)).toMatchObject({ ok: false, error: "user_action_deadline_required" });
    expect(parseUserActionPayload({ ...base, actionId: "x" }, "j1", NOW).ok).toBe(false);
    expect(parseUserActionPayload(null, "j1", NOW).ok).toBe(false);
  });

  it("cancelar sólo necesita el actionId", () => {
    expect(parseUserActionPayload({ op: "cancel", actionId: base.actionId }, "j2", NOW)).toEqual({ ok: true, op: "cancel", actionId: base.actionId });
  });
});

describe("lista de acciones", () => {
  it("otra petición sobre la misma actualización sustituye (otra fecha), no duplica", () => {
    const a = act({ actionId: "act-aaaaaaaa", deadlineUtc: "2026-10-06T23:00:00Z" });
    const b = act({ actionId: "act-bbbbbbbb", deadlineUtc: "2026-10-02T23:00:00Z" });
    expect(upsertAction([a], b)).toEqual([b]);
  });

  it("cancelar la quita", () => {
    expect(cancelAction([act()], "act-00000001")).toEqual([]);
  });

  it("❗ la bandeja recibe todas, de la más urgente a la menos, y nunca las caducadas", () => {
    const later = act({ actionId: "act-later001", params: { label: "B" }, deadlineUtc: "2026-10-06T23:00:00Z" });
    const sooner = act({ actionId: "act-sooner01", params: { label: "A" }, deadlineUtc: "2026-10-02T23:00:00Z" });
    const gone = act({ actionId: "act-gone0001", params: { label: "C" }, expiresUtc: "2026-09-01T00:00:00Z" });
    expect(trayActionsFrom([later, gone, sooner], NOW).map((a) => a.actionId)).toEqual(["act-sooner01", "act-later001"]);
    expect(partitionExpired([later, gone], NOW).expired.map((a) => a.actionId)).toEqual(["act-gone0001"]);
  });
});

describe("telemetría de la bandeja", () => {
  it("suma enseñadas, pospuestas y cuándo abrió Ajustes; ignora acciones que ya no existen", () => {
    const out = applyEvents([act()], [
      { actionId: "act-00000001", event: "shown", atUtc: "2026-09-29T10:00:00.000Z" },
      { actionId: "act-00000001", event: "snoozed", atUtc: "2026-09-29T10:00:05.000Z" },
      { actionId: "act-00000001", event: "shown", atUtc: "2026-09-30T10:00:00.000Z" },
      { actionId: "act-00000001", event: "opened", atUtc: "2026-09-30T10:00:03.000Z" },
      { actionId: "act-otra0000", event: "shown", atUtc: "2026-09-30T10:00:00.000Z" },
    ]);
    expect(out).toEqual([
      expect.objectContaining({ shownCount: 2, snoozedCount: 1, lastShownAtUtc: "2026-09-30T10:00:00.000Z", openedAtUtc: "2026-09-30T10:00:03.000Z" }),
    ]);
  });

  it("⭐ «abrió Ajustes» NO cierra la acción: sólo lo observado", () => {
    const out = applyEvents([act()], [{ actionId: "act-00000001", event: "opened", atUtc: "2026-09-30T10:00:03.000Z" }]);
    expect(out).toHaveLength(1);
  });

  it("descarta lo malformado sin tirar el resto", () => {
    expect(
      parseUserActionEvents(JSON.stringify([
        { actionId: "a1", event: "shown", atUtc: "2026-09-29T10:00:00Z" },
        { actionId: "a1", event: "installed", atUtc: "2026-09-29T10:00:00Z" },
        { actionId: 5, event: "shown", atUtc: "x" },
      ])),
    ).toEqual([{ actionId: "a1", event: "shown", atUtc: "2026-09-29T10:00:00.000Z" }]);
    expect(parseUserActionEvents("no es json")).toEqual([]);
  });

  describe("consumo del fichero", () => {
    let dir: string;
    beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), "ua-events-")); });
    afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

    it("se lee una vez y se borra: el siguiente tick no lo cuenta otra vez", async () => {
      const file = path.join(dir, "user-action-events.json");
      fs.writeFileSync(file, JSON.stringify([{ actionId: "a1", event: "shown", atUtc: "2026-09-29T10:00:00Z" }]));
      expect(await consumeUserActionEvents(async () => file)).toHaveLength(1);
      expect(fs.existsSync(file)).toBe(false);
      expect(await consumeUserActionEvents(async () => file)).toEqual([]);
    });
  });
});

describe("reconcileKind — el cierre por observación", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "ua-state-"));
    process.env.TRACENIUM_STATE_DIR = dir;
  });
  afterEach(() => {
    delete process.env.TRACENIUM_STATE_DIR;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("❗ observación no fiable (null): no cierra nada", () => {
    const setUserActions = vi.fn();
    const ctx = { trayStatus: { setUserActions } } as any;
    acceptUserActionJob(ctx, parseUserActionPayload(base, "j1", NOW) as any, NOW);
    reconcileKind(ctx, "os.update", null, NOW);
    expect(loadUserActions()).toHaveLength(1);
  });

  it("❗ sólo cierra las de SU kind (una observación de os.update no toca otras acciones)", () => {
    const other = { ...act({ actionId: "act-other001" }), kind: "profile.install" } as unknown as UserAction;
    expect(closeObserved([act(), other], "os.update", () => false)).toEqual([other]);
    expect(closeObserved([act(), other], "os.update", null)).toHaveLength(2);
  });

  it("sólo cierra las de SU kind — con estado en disco", () => {
    const setUserActions = vi.fn();
    const ctx = { trayStatus: { setUserActions } } as any;
    acceptUserActionJob(ctx, parseUserActionPayload(base, "j1", NOW) as any, NOW);
    reconcileKind(ctx, "os.update", () => false, NOW);
    expect(loadUserActions()).toEqual([]);
  });
});
