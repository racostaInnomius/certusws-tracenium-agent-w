// test/plugins/asp/runner.test.ts
//
// ADR-0022 — una corrida entera en el agente, sin Windows ni gRPC: IPC falso con
// la forma de respuesta del PrivSvc, SQLite REAL en un fichero temporal y un
// outbox que captura lo encolado. Fija:
//   · la corrida se escribe en SQLite ANTES de encolar nada;
//   · los trozos y el cierre llevan exactamente lo que el backend exige
//     (seq contiguos, indicatorsTotal = catálogo despachado, chunksTotal);
//   · una corrida que no cabe en el presupuesto FALLA entera, sin subir nada;
//   · un colector que no arranca falla la corrida, no la convierte en 30
//     not_assessed que parecerían una corrida válida sin cobertura;
//   · reencolar es idempotente y un reinicio no pierde lo evaluado.

import { describe, it, expect, afterAll } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import catalog from "./fixtures/asp-ad-1.0.0.json";
import { AspRunStore } from "../../../src/plugins/asp/run-store";
import {
  ASP_COLLECT_METHOD,
  ASP_CHUNK_SIZE,
  buildUploadEvents,
  enqueueEvaluatedRun,
  planBatches,
  runAspAssessment,
  validateAssessPayload,
  type AspPrivCall
} from "../../../src/plugins/asp/runner";

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "asp-runner-"));
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

let n = 0;
function newStore() {
  return new AspRunStore(path.join(dir, `asp-${n++}.db`));
}

const RUN = "5b1f6a52-8d34-4c41-9a0e-1f6c2d3e4a5b";

/** Lo que el backend pone en el job: el catálogo sin remediación ni referencias. */
function jobPayload(overrides: Record<string, unknown> = {}) {
  return {
    runId: RUN,
    instanceId: 7,
    domain: "MOUNTAINSIDE-INVESTMENT.COM",
    catalogFamily: "asp-ad",
    catalogVersion: "1.0.0",
    budgetSeconds: 900,
    evidenceLimit: 200,
    trigger: "manual",
    indicators: (catalog.indicators as any[]).map((i) => ({
      controlId: i.controlId,
      severity: i.severity,
      requires: i.requires,
      query: i.query,
      derive: i.derive ?? [],
      predicate: i.predicate,
      onFail: i.onFail,
      whenMissing: i.whenMissing ?? "not_assessed"
    })),
    ...overrides
  };
}

/** Respuesta del PrivSvc para una tanda: todo "limpio", salvo FGPP como SYSTEM. */
function fakePriv(opts: { failBatch?: number; slowMs?: number; clock?: { t: number } } = {}): { call: AspPrivCall; calls: any[] } {
  const calls: any[] = [];
  const call: AspPrivCall = async (req) => {
    calls.push(req);
    if (opts.clock && opts.slowMs) opts.clock.t += opts.slowMs;
    if (opts.failBatch === req.params.batch) return { ok: false, error: { code: "collector_script_untrusted", message: "TRUST_E_NOSIGNATURE" } };
    const results: Record<string, unknown> = {};
    for (const q of req.params.queries as any[]) {
      if (q.id === "ASP-AD-CFG-007") {
        results[q.id] = { ok: false, error: { hresult: "0x8007200A", type: "DirectoryServicesCOMException", message: "no attribute" } };
      } else if (q.query.kind === "registry") {
        results[q.id] = { ok: true, data: { present: false, value: null } };
      } else if (q.query.kind === "ldap_object" || q.query.kind === "rootdse") {
        results[q.id] = { ok: true, data: { found: true, attributes: { pwdLastSet: "133000000000000000", "ms-DS-MachineAccountQuota": "0", minPwdLength: "14", forestFunctionality: "7", userAccountControl: "66050" } } };
      } else if (q.id === "ASP-AD-PRV-003") {
        results[q.id] = { ok: true, data: { found: true, count: 2, sample: ["CN=a", "CN=b"] } };
      } else if (q.id === "ASP-AD-CFG-005") {
        results[q.id] = { ok: true, data: { count: 1, sample: ["CN=ms-LAPS-Password,CN=Schema"] } };
      } else {
        results[q.id] = { ok: true, data: { count: 0, sample: [] } };
      }
    }
    return { ok: true, result: { collector: { host: "DC01", isDomainController: true, osBuild: 20348, ranAs: "NT AUTHORITY\\SYSTEM", psVersion: "5.1.20348" }, results } };
  };
  return { call, calls };
}

describe("validateAssessPayload", () => {
  it("normaliza el dominio a minúsculas y rechaza un predicado roto antes de ejecutar nada", () => {
    const ok = validateAssessPayload(jobPayload());
    expect(ok.ok && ok.payload.domain).toBe("mountainside-investment.com");
    const bad = jobPayload();
    (bad.indicators as any[])[0].predicate = { rule: "eval", path: "x" };
    expect(validateAssessPayload(bad)).toEqual({ ok: false, error: "bad_predicate:ASP-AD-KRB-001" });
  });
});

describe("planBatches", () => {
  it("las sondas de registro van juntas y el resto de a 8", () => {
    const p = validateAssessPayload(jobPayload());
    const batches = planBatches((p as any).payload.indicators);
    const registry = batches.find((b) => b.every((i) => i.query.kind === "registry"));
    expect(registry?.length).toBe(5);
    expect(batches.flat()).toHaveLength(30);
    for (const b of batches) expect(b.length).toBeLessThanOrEqual(8);
  });
});

describe("runAspAssessment — corrida completa", () => {
  it("⭐ evalúa, guarda en SQLite y encola trozos contiguos + cierre con lo que exige el backend", async () => {
    const store = newStore();
    const priv = fakePriv();
    const enqueued: any[] = [];
    const progress: number[] = [];
    const p = validateAssessPayload(jobPayload());
    if (!p.ok) throw new Error(p.error);

    const out = await runAspAssessment(
      { call: priv.call, store, enqueue: (x) => (enqueued.push(x), enqueued.length), meta: { tenantId: "111", deviceId: "dc" }, onProgress: (d) => progress.push(d) },
      { jobId: "job-1", payload: p.payload }
    );

    expect(out).toMatchObject({ status: "complete", indicators: 30, chunks: 3, notAssessed: 1 });
    expect(priv.calls.every((c) => c.method === ASP_COLLECT_METHOD)).toBe(true);
    expect(priv.calls.every((c) => c.params.budgetMs <= 300_000)).toBe(true);
    expect(progress[progress.length - 1]).toBe(30);

    // SQLite: la corrida entera, cerrada y encolada.
    expect(store.get(RUN)?.status).toBe("enqueued");
    expect(store.results(RUN)).toHaveLength(30);
    const fgpp = store.results(RUN).find((r) => r.controlId === "ASP-AD-CFG-007");
    expect(fgpp).toMatchObject({ status: "not_assessed", reason: "requires_privileged_read:0x8007200A" });

    // Outbox: 3 trozos (seq 0,1,2) + 1 cierre, todos solos en el namespace asp.
    expect(enqueued).toHaveLength(4);
    for (const e of enqueued) {
      expect(e.schemaVersion).toBe("1.0");
      expect(Object.keys(e.namespaces)).toEqual(["asp"]);
    }
    const chunks = enqueued.filter((e) => e.namespaces.asp.kind === "chunk");
    expect(chunks.map((c) => c.namespaces.asp.seq)).toEqual([0, 1, 2]);
    expect(chunks.flatMap((c) => c.namespaces.asp.results).map((r: any) => r.controlId).sort()).toEqual((catalog.indicators as any[]).map((i) => i.controlId).sort());
    const complete = enqueued.find((e) => e.namespaces.asp.kind === "complete").namespaces.asp;
    expect(complete).toMatchObject({ runId: RUN, indicatorsTotal: 30, chunksTotal: 3 });
    expect(complete.collectorNotes).toContain("is_dc:true");
  });

  it("⚠️ ningún resultado lleva un objeto de AD: sólo veredicto, recuento, muestra acotada y motivo", async () => {
    const store = newStore();
    const enqueued: any[] = [];
    const p = validateAssessPayload(jobPayload());
    await runAspAssessment({ call: fakePriv().call, store, enqueue: (x) => (enqueued.push(x), 1), meta: { tenantId: "1", deviceId: "d" } }, { jobId: "j", payload: (p as any).payload });
    for (const c of enqueued.filter((e) => e.namespaces.asp.kind === "chunk")) {
      for (const r of c.namespaces.asp.results) {
        expect(Object.keys(r).sort()).toEqual(["affectedCount", "controlId", "evidence", "reason", "severity", "status"]);
      }
    }
  });

  it("⭐ una corrida que no cabe en el presupuesto falla ENTERA y no encola nada", async () => {
    const store = newStore();
    const clock = { t: 1_000_000 };
    const priv = fakePriv({ clock, slowMs: 250_000 });
    const enqueued: any[] = [];
    const p = validateAssessPayload(jobPayload({ budgetSeconds: 600 }));
    const out = await runAspAssessment(
      { call: priv.call, store, enqueue: (x) => (enqueued.push(x), 1), meta: { tenantId: "1", deviceId: "d" }, now: () => clock.t },
      { jobId: "j", payload: (p as any).payload }
    );
    expect(out.status).toBe("failed");
    expect((out as any).reason).toMatch(/^budget_exceeded/);
    expect(enqueued).toHaveLength(0);
    expect(store.get(RUN)?.status).toBe("failed");
  });

  it("un colector que no arranca (script sin firma) falla la corrida con el código del PrivSvc", async () => {
    const store = newStore();
    const enqueued: any[] = [];
    const p = validateAssessPayload(jobPayload());
    const out = await runAspAssessment({ call: fakePriv({ failBatch: 1 }).call, store, enqueue: (x) => (enqueued.push(x), 1), meta: { tenantId: "1", deviceId: "d" } }, { jobId: "j", payload: (p as any).payload });
    expect(out).toEqual({ status: "failed", reason: "privsvc:collector_script_untrusted:TRUST_E_NOSIGNATURE" });
    expect(enqueued).toHaveLength(0);
  });

  it("un reinicio tras evaluar no pierde nada: lo evaluado se vuelve a encolar igual", async () => {
    const store = newStore();
    const p = validateAssessPayload(jobPayload());
    const first: any[] = [];
    await runAspAssessment({ call: fakePriv().call, store, enqueue: (x) => (first.push(x), 1), meta: { tenantId: "1", deviceId: "d" } }, { jobId: "j", payload: (p as any).payload });
    const again: any[] = [];
    enqueueEvaluatedRun(store, (x) => (again.push(x), 1), RUN);
    expect(JSON.stringify(again)).toBe(JSON.stringify(first));
  });

  it("abortRunning marca las corridas de un proceso muerto", () => {
    const store = newStore();
    store.start({ runId: RUN, instanceId: 1, domain: "d", jobId: "j", indicatorsTotal: 30, startedAt: new Date().toISOString() });
    expect(store.abortRunning()).toBe(1);
    expect(store.get(RUN)?.status).toBe("aborted");
    expect(store.running()).toBeNull();
  });
});

describe("buildUploadEvents", () => {
  it("un trozo no pasa de ASP_CHUNK_SIZE resultados", () => {
    const results = Array.from({ length: 23 }, (_, i) => ({ controlId: `ASP-AD-KRB-${String(i).padStart(3, "0")}`, status: "pass" as const, severity: "low" as const, affectedCount: 0, evidence: null, reason: null }));
    const events = buildUploadEvents(RUN, results, { durationMs: 1, collectorNotes: [] });
    const chunks = events.filter((e) => e.namespaces.asp.kind === "chunk");
    expect(chunks).toHaveLength(Math.ceil(23 / ASP_CHUNK_SIZE));
    expect(events[events.length - 1].namespaces.asp).toMatchObject({ kind: "complete", indicatorsTotal: 23, chunksTotal: 3 });
  });
});
