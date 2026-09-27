// test/plugins/evidence-job.test.ts
//
// ADR-0032 F2 — el job de captura de evidencia.
//
// Lo que se prueba es lo que decide el valor de un paquete: qué se recoge
// primero, qué pasa cuando algo falla, y que el manifiesto diga la verdad —
// incluida la hora del equipo, que es donde este caso estuvo a punto de
// torcerse.

import { describe, it, expect, vi } from "vitest";
import {
  EVIDENCE_FACTS_NAMESPACE,
  parseEvidenceJob,
  runEvidenceJob,
  utcOffsetMinutes,
  type EvidenceJobDeps,
} from "../../src/plugins/evidence/evidence-job";

const CAPTURE = "11111111-2222-3333-4444-555555555555";

/** Colectores de mentira: cada clave dice qué produce. */
function deps(over: Partial<EvidenceJobDeps> = {}, produced: Record<string, any[]> = {}): { d: EvidenceJobDeps; sent: any[]; uploaded: string[] } {
  const sent: any[] = [];
  const uploaded: string[] = [];
  const d: EvidenceJobDeps = {
    platform: "win32",
    collectorDeps: (workDir) => ({ platform: "win32", exec: vi.fn() as any, workDir }),
    upload: async (a) => { uploaded.push(a.name); },
    enqueue: (p) => { sent.push(p); return 1; },
    mkdtemp: async () => "/tmp/evidence-test",
    rm: async () => {},
    stat: async () => ({ size: 1024 }),
    hash: async () => "a".repeat(64),
    now: () => new Date("2026-09-23T12:52:00.000Z"),
    ...over,
  };
  // El runner real despacha por clave; aquí se intercepta con el mock del módulo.
  (globalThis as any).__evidenceProduced = produced;
  return { d, sent, uploaded };
}

vi.mock("../../src/plugins/evidence/collectors", async (orig) => {
  const actual = (await orig()) as any;
  return {
    ...actual,
    runCollector: vi.fn(async (_deps: any, key: string) => {
      const table = (globalThis as any).__evidenceProduced ?? {};
      if (table[key]) return table[key];
      return [{ name: `${key}.txt`, collector: key, status: "ok", filePath: `/tmp/${key}.txt` }];
    }),
  };
});

const manifestOf = (sent: any[]) => sent[0]?.namespaces?.[EVIDENCE_FACTS_NAMESPACE];

describe("parseEvidenceJob — la orden se revalida", () => {
  it("acepta una orden bien formada", () => {
    const r = parseEvidenceJob({ captureId: CAPTURE, collectors: ["sessions", "processes"], params: {} });
    expect(r).toMatchObject({ ok: true, value: { captureId: CAPTURE, collectors: ["sessions", "processes"] } });
  });

  it("🔴 sin captureId válido no se ejecuta nada", () => {
    for (const bad of [{}, { captureId: "no-uuid", collectors: ["sessions"] }, { captureId: CAPTURE }]) {
      expect(parseEvidenceJob(bad).ok).toBe(false);
    }
  });

  it("⭐ un colector que este agente no conoce se IGNORA, no tumba la captura", () => {
    // Un backend más nuevo puede pedir uno que esta versión no trae; lo útil
    // entonces es recoger el resto.
    const r = parseEvidenceJob({ captureId: CAPTURE, collectors: ["sessions", "memory_dump"] });
    expect(r).toMatchObject({ ok: true, value: { collectors: ["sessions"] } });
  });

  it("pero si NINGUNO se conoce, se rechaza con su motivo", () => {
    expect(parseEvidenceJob({ captureId: CAPTURE, collectors: ["memory_dump"] })).toMatchObject({
      ok: false,
      error: expect.stringContaining("no known collector"),
    });
  });
});

describe("utcOffsetMinutes", () => {
  it("🔴 invierte el signo de getTimezoneOffset: UTC-5 son -300, no +300", () => {
    const fake = { getTimezoneOffset: () => 300 } as Date; // Node: UTC-5 → +300
    expect(utcOffsetMinutes(fake)).toBe(-300);
  });
});

describe("runEvidenceJob", () => {
  it("⭐ sube cada artefacto y manda el manifiesto con hash, hora y desfase", async () => {
    const { d, sent, uploaded } = deps();
    const ack = await runEvidenceJob(d, { jobId: "j1", payload: { captureId: CAPTURE, collectors: ["sessions", "processes"] } });

    expect(ack.status).toBe(0);
    expect(uploaded).toEqual(["sessions.txt", "processes.txt"]);
    const m = manifestOf(sent);
    expect(m.captureId).toBe(CAPTURE);
    expect(m.capturedAtUtc).toBe("2026-09-23T12:52:00.000Z");
    expect(typeof m.utcOffsetMinutes).toBe("number");
    expect(m.artifacts).toHaveLength(2);
    expect(m.artifacts[0]).toMatchObject({ status: "ok", bytes: 1024, sha256: "a".repeat(64) });
  });

  it("⭐ lo VOLÁTIL primero: si el reinicio pilla la captura a medias, las sesiones ya están", async () => {
    const { d, uploaded } = deps();
    await runEvidenceJob(d, {
      jobId: "j1",
      payload: { captureId: CAPTURE, collectors: ["event_logs", "agent_self", "processes", "sessions"] },
    });
    expect(uploaded.slice(0, 2)).toEqual(["sessions.txt", "processes.txt"]);
    expect(uploaded[uploaded.length - 1]).toBe("agent_self.txt");
  });

  it("⭐ un colector que falla NO tira la captura: queda en el manifiesto con su motivo", async () => {
    const { d, sent, uploaded } = deps({}, {
      event_logs: [{ name: "security.evtx", collector: "event_logs", status: "failed", detail: "access denied" }],
    });
    const ack = await runEvidenceJob(d, { jobId: "j1", payload: { captureId: CAPTURE, collectors: ["sessions", "event_logs"] } });

    expect(ack.status).toBe(0);
    expect(ack.message).toContain("partial");
    expect(uploaded).toEqual(["sessions.txt"]);
    const m = manifestOf(sent);
    expect(m.artifacts).toContainEqual(expect.objectContaining({ name: "security.evtx", status: "failed", detail: "access denied" }));
  });

  it("🔴 un fallo al SUBIR se cuenta como artefacto fallido, y los demás siguen", async () => {
    const { d, sent } = deps({
      upload: async (a) => { if (a.name === "sessions.txt") throw new Error("storage answered 403"); },
    });
    await runEvidenceJob(d, { jobId: "j1", payload: { captureId: CAPTURE, collectors: ["sessions", "processes"] } });
    const m = manifestOf(sent);
    expect(m.artifacts[0]).toMatchObject({ name: "sessions.txt", status: "failed", detail: expect.stringContaining("403") });
    expect(m.artifacts[1]).toMatchObject({ name: "processes.txt", status: "ok" });
  });

  it("⭐ el manifiesto se manda AUNQUE todo falle: el silencio no es evidencia", async () => {
    const { d, sent } = deps({ upload: async () => { throw new Error("no network"); } });
    const ack = await runEvidenceJob(d, { jobId: "j1", payload: { captureId: CAPTURE, collectors: ["sessions"] } });
    expect(ack.status).toBe(2);
    expect(manifestOf(sent).artifacts).toHaveLength(1);
    expect(manifestOf(sent).artifacts[0].status).toBe("failed");
  });

  it("⚠️ agotado el presupuesto, se DICE qué colector se quedó fuera", async () => {
    let t = 0;
    const { d, sent } = deps({
      budgetMs: 10,
      stat: async () => { t += 100; return { size: 10 }; },
    });
    // El reloj del presupuesto usa Date.now; se avanza con una espera real corta.
    const spy = vi.spyOn(Date, "now");
    spy.mockReturnValueOnce(0).mockReturnValue(1000);
    await runEvidenceJob(d, { jobId: "j1", payload: { captureId: CAPTURE, collectors: ["sessions", "processes", "event_logs"] } });
    spy.mockRestore();
    const m = manifestOf(sent);
    expect(m.artifacts.some((a: any) => a.status === "failed" && /ran out of time/.test(a.detail ?? ""))).toBe(true);
  });

  it("🔴 la carpeta de trabajo se borra SIEMPRE: no se deja una copia en el disco del cliente", async () => {
    const rm = vi.fn(async () => {});
    const { d } = deps({ rm, upload: async () => { throw new Error("boom"); } });
    await runEvidenceJob(d, { jobId: "j1", payload: { captureId: CAPTURE, collectors: ["sessions"] } });
    expect(rm).toHaveBeenCalledWith("/tmp/evidence-test");
  });

  it("con AMP apagado no se captura nada", async () => {
    const { d, sent } = deps({ ampEnabled: () => false });
    const ack = await runEvidenceJob(d, { jobId: "j1", payload: { captureId: CAPTURE, collectors: ["sessions"] } });
    expect(ack).toMatchObject({ status: 2, message: expect.stringContaining("amp_disabled") });
    expect(sent).toHaveLength(0);
  });
});
