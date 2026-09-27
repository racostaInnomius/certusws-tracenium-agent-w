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

describe("catálogo 1.4.0 — «Recent changes» por metadata de replicación", () => {
  const cat140 = require("./fixtures/asp-ad-1.4.0.json");
  function ind140(id: string): AgentIndicator {
    const i = (cat140.indicators as any[]).find((x) => x.controlId === id);
    if (!i) throw new Error(id);
    return { controlId: i.controlId, severity: i.severity, requires: i.requires, query: i.query, derive: i.derive ?? [], predicate: i.predicate, onFail: i.onFail, whenMissing: i.whenMissing ?? "not_assessed" };
  }

  it("⭐ un alta reciente en un grupo privilegiado es needs_review, no fail", () => {
    const r = evaluateIndicator(
      ind140("ASP-AD-CHG-001"),
      { ok: true, data: { count: 1, sample: [{ attribute: "member", action: "added", changedAt: "2026-09-25T09:00:00.000Z", objectDn: "CN=tmpadm,OU=IT,DC=m", originatingDc: "MSIG-DOMAIN01" }], objectsScanned: 4, notFound: 0, unreadable: 0 } },
      DC,
      opts
    );
    // Un cambio reciente no es una configuración mala: es algo que mirar. Si
    // fuera `fail`, un alta legítima bajaría el score y se aprendería a ignorarlo.
    expect(r).toMatchObject({ status: "needs_review", severity: "high", affectedCount: 1 });
    expect((r.evidence as any).sample[0]).toMatchObject({ action: "added", originatingDc: "MSIG-DOMAIN01" });
  });

  it("sin cambios en la ventana → pass", () => {
    expect(evaluateIndicator(ind140("ASP-AD-CHG-001"), { ok: true, data: { count: 0, sample: [], objectsScanned: 4, notFound: 0, unreadable: 0 } }, DC, opts).status).toBe("pass");
  });

  it("🔴 si la metadata de ALGÚN objeto no se pudo leer, el 0 NO es pass: es not_assessed", () => {
    const r = evaluateIndicator(
      ind140("ASP-AD-CHG-001"),
      { ok: true, data: { count: 0, sample: [], objectsScanned: 4, notFound: 0, unreadable: 2, unreadableSample: ["<SID=S-1-5-32-544>"] } },
      DC,
      opts
    );
    // AD responde «no existe» a lo que no te deja leer, así que un 0 significa a
    // la vez «no hay nada» y «no pude mirar». Probado el 26-sep con las
    // plantillas de certificado: como SYSTEM se veían 2 de 38.
    expect(r.status).toBe("not_assessed");
    expect(r.reason).toBe("insufficient_read:2");
  });

  it("⚠️ ciego a medias pero CON hallazgo: el hallazgo gana, no se tapa con not_assessed", () => {
    const r = evaluateIndicator(
      ind140("ASP-AD-CHG-001"),
      { ok: true, data: { count: 1, sample: [{ attribute: "member", action: "removed", changedAt: "2026-09-26T10:00:00.000Z", objectDn: "CN=x,DC=m", originatingDc: "MSIG-DOMAIN01" }], objectsScanned: 4, notFound: 0, unreadable: 1 } },
      DC,
      opts
    );
    expect(r.status).toBe("needs_review");
  });

  it("🔴 un cero SIN `lastWrite` no prueba nada: es el verde de la habitación vacía", () => {
    // El spike del 27-sep salió con los cinco a 0 y `unreadable: 0`. Eso puede
    // ser «no cambió nada» o «no parseé ni una entrada», y las dos cosas se leen
    // igual. El colector lo separa: si el atributo vuelve con valores y no se
    // parsea ninguna entrada, ese objeto se cuenta como `unreadable`.
    const ciego = evaluateIndicator(
      ind140("ASP-AD-CHG-002"),
      { ok: true, data: { count: 0, sample: [], objectsScanned: 1, notFound: 0, unreadable: 1, entriesSeen: 0, lastWrite: {} } },
      DC,
      opts
    );
    expect(ciego.status).toBe("not_assessed");
    expect(ciego.reason).toBe("insufficient_read:1");
  });

  it("⭐ un cero CON `lastWrite` es un cero de verdad, y la fecha viaja en la evidencia", () => {
    // Control positivo: si el colector sabe decir CUÁNDO se escribió por última
    // vez, la cadena entera (petición, XML, nombre del atributo, fecha) funciona
    // y el 0 significa «no en la ventana». Y la fecha es útil por sí sola: «se
    // tocó por última vez en 2019» le dice algo a un auditor.
    const r = evaluateIndicator(
      ind140("ASP-AD-CHG-002"),
      { ok: true, data: { count: 0, sample: [], objectsScanned: 1, notFound: 0, unreadable: 0, entriesSeen: 61, lastWrite: { nTSecurityDescriptor: "2019-03-02T11:04:00.000Z" } } },
      DC,
      opts
    );
    expect(r.status).toBe("pass");
    expect((r.evidence as any).lastWrite.nTSecurityDescriptor).toBe("2019-03-02T11:04:00.000Z");
  });

  it("⚠️ `notFound` NO es ceguera: Enterprise Admins no existe en un dominio hijo y eso es normal", () => {
    const r = evaluateIndicator(
      ind140("ASP-AD-CHG-001"),
      { ok: true, data: { count: 0, sample: [], objectsScanned: 2, notFound: 2, unreadable: 0 } },
      DC,
      opts
    );
    expect(r.status).toBe("pass");
  });

  it("⭐ escribir en krbtgt o en el DACL del dominio es crítico", () => {
    for (const id of ["ASP-AD-CHG-003", "ASP-AD-CHG-004"]) {
      const r = evaluateIndicator(
        ind140(id),
        { ok: true, data: { count: 1, sample: [{ attribute: "nTSecurityDescriptor", action: "written", changedAt: "2026-09-20T08:00:00.000Z", objectDn: "DC=m", version: 7, originatingDc: "MSIG-DOMAIN01" }], objectsScanned: 1, notFound: 0, unreadable: 0 } },
        DC,
        opts
      );
      expect(r, id).toMatchObject({ status: "needs_review", severity: "critical", affectedCount: 1 });
    }
  });
});

describe("catálogo 1.5.0 — ADCS rehecho: explotabilidad y ceguera declarada", () => {
  const cat150 = require("./fixtures/asp-ad-1.5.0.json");
  function ind150(id: string): AgentIndicator {
    const i = (cat150.indicators as any[]).find((x) => x.controlId === id);
    if (!i) throw new Error(id);
    return { controlId: i.controlId, severity: i.severity, requires: i.requires, query: i.query, derive: i.derive ?? [], predicate: i.predicate, onFail: i.onFail, whenMissing: i.whenMissing ?? "not_assessed" };
  }

  it("🔴 el caso REAL del 26-sep: 2 plantillas resueltas de 16 publicadas → not_assessed, NO pass", () => {
    // Como SYSTEM en MSIG-DOMAIN01 se veían 2 de 38 plantillas y la CA publica
    // 16. El oráculo (lo que las CA dicen publicar vs lo que se resolvió) lo
    // convierte en ceguera declarada en vez de un cero mentiroso.
    const r = evaluateIndicator(
      ind150("ASP-AD-PKI-001"),
      { ok: true, data: { found: true, count: 0, sample: [], caCount: 1, objectsScanned: 2, publishedDeclared: 16, publishedResolved: 2, unreadable: 14 } },
      DC,
      opts
    );
    expect(r.status).toBe("not_assessed");
    expect(r.reason).toBe("insufficient_read:14");
  });

  it("⭐ viéndolo todo y sin plantilla explotable → pass, con la prueba de que miró", () => {
    const r = evaluateIndicator(
      ind150("ASP-AD-PKI-001"),
      { ok: true, data: { found: true, count: 0, sample: [], caCount: 1, objectsScanned: 38, publishedDeclared: 16, publishedResolved: 16, unreadable: 0 } },
      DC,
      opts
    );
    expect(r.status).toBe("pass");
    expect((r.evidence as any).objectsScanned).toBe(38);
  });

  it("⭐ un ESC4 dice a cuántas ediciones está de ser ESC1 — el caso real de PRTG_WebServer", () => {
    // En MSIG-DOMAIN01 (27-sep) la plantilla cumple ya 3 de las 4 condiciones de
    // ESC1 —sujeto a elección, sin aprobación, sin firmas— y sólo le falta una
    // EKU de autenticación, que la puede añadir justo quien tiene WriteDacl
    // sobre ella. Sin ese dato el hallazgo se lee como administrativo, y no lo es.
    const r = evaluateIndicator(
      ind150("ASP-AD-PKI-002"),
      { ok: true, data: { found: true, count: 1, caCount: 1, objectsScanned: 38, publishedDeclared: 16, publishedResolved: 16, unreadable: 0,
        sample: [{ template: "PRTG_WebServer", published: true, grantedTo: "S-1-5-21-1-1300", grantedRights: "WriteDacl, WriteOwner",
          nameFlag: 1, enrollFlag: 0, raSignature: 0, eku: ["1.3.6.1.5.5.7.3.1"], esc1ConditionsMet: 3, esc1Missing: ["authEku"] }] } },
      DC,
      opts
    );
    expect(r.status).toBe("needs_review");
    const hit = (r.evidence as any).sample[0];
    expect(hit.esc1ConditionsMet).toBe(3);
    expect(hit.esc1Missing).toEqual(["authEku"]);
    // Y quién, con qué derecho: sin esto un hallazgo no se puede auditar.
    expect(hit.grantedRights).toContain("WriteDacl");
  });

  it("⚠️ sin ninguna CA en el bosque es «no aplica», nunca «cumple»", () => {
    const r = evaluateIndicator(ind150("ASP-AD-PKI-005"), { ok: true, data: { found: false, caCount: 0 } }, DC, opts);
    expect(r.status).toBe("not_applicable");
  });

  it("⭐ una plantilla publicada y explotable sale con quién puede inscribirse", () => {
    const r = evaluateIndicator(
      ind150("ASP-AD-PKI-001"),
      { ok: true, data: { found: true, count: 1, caCount: 1, objectsScanned: 38, publishedDeclared: 16, publishedResolved: 16, unreadable: 0,
        sample: [{ template: "UserAuth", published: true, grantedTo: "S-1-5-21-1-513", nameFlag: 1, enrollFlag: 0, raSignature: 0, eku: ["1.3.6.1.5.5.7.3.2"] }] } },
      DC,
      opts
    );
    expect(r).toMatchObject({ status: "needs_review", severity: "critical", affectedCount: 1 });
    expect((r.evidence as any).sample[0]).toMatchObject({ template: "UserAuth", published: true, grantedTo: "S-1-5-21-1-513" });
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
