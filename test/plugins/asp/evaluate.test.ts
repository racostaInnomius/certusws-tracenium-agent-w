// test/plugins/asp/evaluate.test.ts
//
// ADR-0022 — la evaluación local, con el catálogo REAL (copia del backend en
// fixtures/) y salidas del colector con la forma que devuelve el .ps1. Fija las
// reglas de la fase 0: FGPP como SYSTEM = not_assessed por privilegios, valor de
// registro ausente = valor por defecto del SO, sonda de registro fuera de un DC
// = not_assessed, y el dominio del spike dice lo que dice la tabla del ADR.

import { describe, it, expect } from "vitest";
import catalog from "./fixtures/asp-ad-1.0.0.json";
import { absentValueFor, evaluateIndicator, fileTimeAgeDays, type AgentIndicator } from "../../../src/plugins/asp/evaluate";

const NOW = Date.parse("2026-09-13T12:00:00Z");
const DC = { isDomainController: true, osBuild: 20348, host: "MSIG-TSPDC" };

function indicator(id: string): AgentIndicator {
  const i = (catalog.indicators as any[]).find((x) => x.controlId === id);
  if (!i) throw new Error(id);
  return {
    controlId: i.controlId,
    severity: i.severity,
    requires: i.requires,
    query: i.query,
    derive: i.derive ?? [],
    predicate: i.predicate,
    onFail: i.onFail,
    whenMissing: i.whenMissing ?? "not_assessed"
  };
}

/** FILETIME de hace `days` días, como texto (así lo manda el colector). */
function fileTimeDaysAgo(days: number): string {
  return String((BigInt(NOW - days * 86_400_000) + 11644473600000n) * 10000n);
}

const opts = { evidenceLimit: 200, nowMs: NOW };

describe("evaluateIndicator — reglas de la fase 0", () => {
  it("⭐ FGPP leído como SYSTEM (0x8007200A) → not_assessed por privilegios, nunca error ni pass", () => {
    const r = evaluateIndicator(indicator("ASP-AD-CFG-007"), { ok: false, error: { hresult: "0x8007200A", type: "DirectoryServicesCOMException", message: "The requested attribute or value does not exist" } }, DC, opts);
    expect(r).toMatchObject({ status: "not_assessed", reason: "requires_privileged_read:0x8007200A", evidence: null });
  });

  it("un acceso denegado en un indicador que NO declaró privileged se dice tal cual", () => {
    const r = evaluateIndicator(indicator("ASP-AD-KRB-002"), { ok: false, error: { hresult: "0x80070005" } }, DC, opts);
    expect(r.reason).toBe("insufficient_rights:0x80070005");
  });

  it("acl_search: los trustees cuentan como afectados y la evidencia dice cuántos objetos se miraron", () => {
    const ind = { ...indicator("ASP-AD-PRV-006"), query: { kind: "acl_search", base: "{domainDn}", filter: "(adminCount=1)", rights: ["GenericAll"] } } as any;
    const r = evaluateIndicator(ind, { ok: true, data: { count: 1, sample: [{ sid: "S-1-5-21-1-1105", name: "D\\helpdesk", rights: "ExtendedRight", objects: 43 }], truncated: false, objectsScanned: 43 } }, DC, opts);
    expect(r).toMatchObject({ status: "fail", affectedCount: 1, evidence: { count: 1, objectsScanned: 43 } });
  });

  it("un error genérico del colector es not_assessed con el HRESULT", () => {
    const r = evaluateIndicator(indicator("ASP-AD-KRB-002"), { ok: false, error: { hresult: "0x8007203A", type: "COMException" } }, DC, opts);
    expect(r).toMatchObject({ status: "not_assessed", reason: "collector_error:0x8007203A", evidence: { collectorError: { hresult: "0x8007203A", type: "COMException", message: null } } });
  });

  it("⭐ el texto del error viaja en la evidencia: 0x80131501 solo no dice nada", () => {
    const message = "You cannot call a method on a null-valued expression.".padEnd(400, ".");
    const r = evaluateIndicator(indicator("ASP-AD-PRV-006"), { ok: false, error: { hresult: "0x80131501", type: "RuntimeException", message } }, DC, opts);
    expect(r.reason).toBe("collector_error:0x80131501");
    expect((r.evidence as any).collectorError.type).toBe("RuntimeException");
    expect((r.evidence as any).collectorError.message).toHaveLength(300);
  });

  it("⭐ una sonda de registro en un colector que no es DC → not_assessed", () => {
    const r = evaluateIndicator(indicator("ASP-AD-DC-001"), { ok: true, data: { present: true, value: 2 } }, { isDomainController: false }, opts);
    expect(r).toMatchObject({ status: "not_assessed", reason: "requires_dc_registry" });
  });

  it("⭐ LDAPServerIntegrity ausente = 1 (firma no exigida) → fail, con la ausencia en la evidencia", () => {
    const r = evaluateIndicator(indicator("ASP-AD-DC-001"), { ok: true, data: { present: false, value: null } }, DC, opts);
    expect(r).toMatchObject({ status: "fail", evidence: { present: false, value: 1, absent: true } });
  });

  it("⭐ SMB1 ausente depende del build: 2022 = deshabilitado (pass), 2016 = habilitado (fail)", () => {
    const q = indicator("ASP-AD-DC-003").query;
    expect(absentValueFor(q, 20348)).toBe(0);
    expect(absentValueFor(q, 14393)).toBe(1);
    expect(evaluateIndicator(indicator("ASP-AD-DC-003"), { ok: true, data: { present: false, value: null } }, DC, opts).status).toBe("pass");
    expect(evaluateIndicator(indicator("ASP-AD-DC-003"), { ok: true, data: { present: false, value: null } }, { ...DC, osBuild: 14393 }, opts).status).toBe("fail");
  });

  it("krbtgt: el FILETIME llega como texto y se deriva a días sin perder precisión", () => {
    expect(fileTimeAgeDays(fileTimeDaysAgo(2734), NOW)).toBe(2734);
    expect(fileTimeAgeDays("0", NOW)).toBeNull();
    const r = evaluateIndicator(indicator("ASP-AD-KRB-001"), { ok: true, data: { found: true, attributes: { pwdLastSet: fileTimeDaysAgo(2734) } } }, DC, opts);
    expect(r).toMatchObject({ status: "fail", severity: "critical", evidence: { pwdLastSetAgeDays: 2734 } });
  });

  it("dsHeuristics ausente se toma como vacío (el valor seguro por defecto) → pass", () => {
    const r = evaluateIndicator(indicator("ASP-AD-CFG-001"), { ok: true, data: { found: true, attributes: {} } }, DC, opts);
    expect(r.status).toBe("pass");
  });

  it("Protected Users sin el grupo (PDC antiguo) → not_applicable, no fail", () => {
    const r = evaluateIndicator(indicator("ASP-AD-PRV-003"), { ok: true, data: { found: false } }, DC, opts);
    expect(r).toMatchObject({ status: "not_applicable", reason: "not_present:count" });
  });

  it("AdminSDHolder con escritores no por defecto → needs_review, no fail (falso positivo caro)", () => {
    const r = evaluateIndicator(indicator("ASP-AD-PRV-005"), { ok: true, data: { count: 1, sample: [{ sid: "S-1-5-21-1-2-3-1109", name: "CORP\\Exchange Windows Permissions" }] } }, DC, opts);
    expect(r.status).toBe("needs_review");
  });

  it("⭐ la evidencia viaja acotada al tope aunque el colector mande más", () => {
    const sample = Array.from({ length: 500 }, (_, i) => `CN=u${i},DC=corp`);
    const r = evaluateIndicator(indicator("ASP-AD-ACC-001"), { ok: true, data: { count: 500, sample } }, DC, { evidenceLimit: 200, nowMs: NOW });
    expect((r.evidence as any).sample).toHaveLength(200);
    expect((r.evidence as any).truncated).toBe(true);
    expect(r.affectedCount).toBe(500);
  });

  it("un indicador sin resultado del colector → not_assessed, nunca pass", () => {
    expect(evaluateIndicator(indicator("ASP-AD-KRB-003"), undefined, DC, opts)).toMatchObject({ status: "not_assessed", reason: "collector_no_result" });
  });
});

describe("catálogo 1.1.0 — los tipos nuevos evalúan", () => {
  const cat110 = require("./fixtures/asp-ad-1.1.0.json");
  function ind110(id: string): AgentIndicator {
    const i = (cat110.indicators as any[]).find((x) => x.controlId === id);
    if (!i) throw new Error(id);
    return { controlId: i.controlId, severity: i.severity, requires: i.requires, query: i.query, derive: i.derive ?? [], predicate: i.predicate, onFail: i.onFail, whenMissing: i.whenMissing ?? "not_assessed" };
  }

  it("acl_search sin trustees no por defecto → pass (MSIG-DOMAIN01: 0 en PRV-007/008/009/010)", () => {
    for (const id of ["ASP-AD-PRV-007", "ASP-AD-PRV-008", "ASP-AD-PRV-009", "ASP-AD-PRV-010"]) {
      const r = evaluateIndicator(ind110(id), { ok: true, data: { count: 0, sample: [], objectsScanned: 5 } }, DC, opts);
      expect(r.status, id).toBe("pass");
    }
  });

  it("acl_search con un trustee no por defecto → needs_review, con los afectados", () => {
    const r = evaluateIndicator(ind110("ASP-AD-PRV-007"), { ok: true, data: { count: 1, sample: [{ sid: "S-1-5-21-1-1105", name: "D\\helpdesk", rights: "ExtendedRight", objects: 44 }], objectsScanned: 44 } }, DC, opts);
    expect(r).toMatchObject({ status: "needs_review", affectedCount: 1, evidence: { count: 1, objectsScanned: 44 } });
  });

  it("orphan de adminCount habilitado → fail; forest level 2008R2 < 2012 → fail; NoLMHash presente → pass", () => {
    expect(evaluateIndicator(ind110("ASP-AD-PRV-012"), { ok: true, data: { count: 13, sample: [] } }, DC, opts).status).toBe("fail");
    expect(evaluateIndicator(ind110("ASP-AD-CFG-010"), { ok: true, data: { found: true, attributes: { forestFunctionality: "4", domainFunctionality: "7" } } }, DC, opts).status).toBe("fail");
    expect(evaluateIndicator(ind110("ASP-AD-DC-007"), { ok: true, data: { present: true, value: 1 } }, DC, opts).status).toBe("pass");
  });

  it("lockout threshold 5 → pass (between 1..10); 0 (sin bloqueo) → fail", () => {
    expect(evaluateIndicator(ind110("ASP-AD-CFG-009"), { ok: true, data: { found: true, attributes: { lockoutThreshold: "5" } } }, DC, opts).status).toBe("pass");
    expect(evaluateIndicator(ind110("ASP-AD-CFG-009"), { ok: true, data: { found: true, attributes: { lockoutThreshold: "0" } } }, DC, opts).status).toBe("fail");
  });
});

describe("catálogo 1.2.0 — owner_search y el P1 de Purple Knight", () => {
  const cat120 = require("./fixtures/asp-ad-1.2.0.json");
  function ind120(id: string): AgentIndicator {
    const i = (cat120.indicators as any[]).find((x) => x.controlId === id);
    if (!i) throw new Error(id);
    return { controlId: i.controlId, severity: i.severity, requires: i.requires, query: i.query, derive: i.derive ?? [], predicate: i.predicate, onFail: i.onFail, whenMissing: i.whenMissing ?? "not_assessed" };
  }

  it("⭐ dueño no permitido → needs_review, con cuántos objetos posee cada uno", () => {
    const r = evaluateIndicator(
      ind120("ASP-AD-PRV-015"),
      { ok: true, data: { count: 1, sample: [{ sid: "S-1-5-21-1-1105", name: "D\\helpdesk", objects: 7, exampleDn: "CN=svc,DC=m" }], objectsScanned: 47 } },
      DC,
      opts
    );
    expect(r).toMatchObject({ status: "needs_review", affectedCount: 1, evidence: { count: 1, objectsScanned: 47 } });
    expect((r.evidence as any).sample[0].objects).toBe(7);
  });

  it("todos los dueños permitidos → pass", () => {
    expect(evaluateIndicator(ind120("ASP-AD-PRV-015"), { ok: true, data: { count: 0, sample: [], objectsScanned: 47 } }, DC, opts).status).toBe("pass");
  });

  it("⭐ escribir la delegación de krbtgt es fail crítico, no needs_review", () => {
    const r = evaluateIndicator(
      ind120("ASP-AD-PRV-013"),
      { ok: true, data: { count: 1, sample: [{ sid: "S-1-5-21-1-1106", name: "D\\backup", rights: "WriteProperty" }] } },
      DC,
      opts
    );
    expect(r).toMatchObject({ status: "fail", severity: "critical", affectedCount: 1 });
  });

  it("un objeto sin descriptor hace FALLAR la consulta, y eso es not_assessed, nunca pass", () => {
    const r = evaluateIndicator(
      ind120("ASP-AD-PRV-015"),
      { ok: false, error: { hresult: "0x80131501", type: "RuntimeException", message: "nTSecurityDescriptor not returned for CN=x,DC=m" } },
      DC,
      opts
    );
    expect(r.status).toBe("not_assessed");
    expect((r.evidence as any).collectorError.message).toContain("nTSecurityDescriptor not returned");
  });
});

describe("el dominio del spike (MSIG-TSPDC, ADR §Fase 0)", () => {
  const spike: Record<string, { data: any; expect: string }> = {
    "ASP-AD-KRB-002": { data: { count: 2, sample: ["CN=Administrator,CN=Users,DC=m", "CN=next gsys,OU=IT,DC=m"] }, expect: "fail" },
    "ASP-AD-CFG-001": { data: { found: true, attributes: { dSHeuristics: "0000002" } }, expect: "fail" },
    "ASP-AD-DC-002": { data: { present: false, value: null }, expect: "fail" },
    "ASP-AD-DC-004": { data: { present: true, value: 2 }, expect: "fail" },
    "ASP-AD-DC-005": { data: { present: false, value: null }, expect: "fail" },
    "ASP-AD-ACC-001": { data: { count: 38, sample: [] }, expect: "fail" },
    "ASP-AD-ACC-004": { data: { count: 26, sample: [] }, expect: "fail" },
    "ASP-AD-CFG-003": { data: { found: true, attributes: { forestFunctionality: "4", domainFunctionality: "7" } }, expect: "fail" },
    "ASP-AD-CFG-002": { data: { found: true, attributes: { "ms-DS-MachineAccountQuota": "10" } }, expect: "fail" },
    "ASP-AD-KRB-003": { data: { count: 0, sample: [] }, expect: "pass" },
    "ASP-AD-KRB-004": { data: { count: 0, sample: [] }, expect: "pass" },
    "ASP-AD-ACC-002": { data: { count: 0, sample: [] }, expect: "pass" },
    "ASP-AD-ACC-005": { data: { count: 0, sample: [] }, expect: "pass" },
    "ASP-AD-CFG-008": { data: { count: 0, sample: [] }, expect: "pass" }
  };
  for (const [id, c] of Object.entries(spike)) {
    it(`${id} → ${c.expect}`, () => {
      expect(evaluateIndicator(indicator(id), { ok: true, data: c.data }, DC, opts).status).toBe(c.expect);
    });
  }
});
