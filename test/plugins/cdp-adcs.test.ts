// test/plugins/cdp-adcs.test.ts
//
// Conector AD CS (fase 4): el parser del volcado de `certutil -view` y el
// provider con un PrivSvc falso. Etiquetas, disposiciones y plantillas del
// fixture son las que imprimio MSIG-RADIUS-CA (2026-09-07, en modo csv, que
// resulto inutil para el binario); la forma de las lineas «Row N:» es la
// del volcado documentado y se confirma con la primera lectura real. Si
// difiere, el parser dice que columnas no reconocio en vez de devolver
// cero en silencio.

import { describe, it, expect, vi, beforeEach } from "vitest";
import crypto from "crypto";
import { splitCertutilDump, parseCertutilDump } from "../../src/plugins/cdp/adcs-csv";
import { FIXTURE_CERT } from "./tls-fixture";

const cursors = new Map<string, number>();
vi.mock("../../src/domain/cdp-adcs-repo", () => ({
  readAdcsCursor: (k: string) => cursors.get(k) ?? 0,
  writeAdcsCursor: (k: string, v: number) => cursors.set(k, v)
}));

import { collectAdcs, hostMatches } from "../../src/plugins/cdp/providers/adcs";

// Volcado por filas de `certutil -view -out … ` (sin csv). Etiquetas en
// ingles y formato de disposicion/plantilla tal como los imprimio
// MSIG-RADIUS-CA en modo csv el 2026-09-07; la forma de las lineas
// «Row N:» / «  Etiqueta: valor» y el PEM sin comillas son el formato de
// volcado documentado, por confirmar con la primera lectura real.
const row = (id: number, disp: string, who: string, tpl: string, pem: string | null, labels = EN) =>
  [
    `Row ${id}:`,
    `  ${labels[0]}: 0x${id.toString(16)} (${id})`,
    `  ${labels[1]}: ${disp}`,
    `  ${labels[2]}: "${who}"`,
    `  ${labels[3]}: ${tpl === "EMPTY" ? "EMPTY" : `"${tpl}"`}`,
    `  ${labels[4]}:`,
    ...(pem === null ? ["EMPTY"] : pem === "garbage" ? ["-----BEGIN CERTIFICATE-----", "not-base64-at-all", "-----END CERTIFICATE-----"] : [pem.trimEnd()])
  ].join("\n");
const EN = ["Issued Request ID", "Request Disposition", "Requester Name", "Certificate Template", "Binary Certificate"];
const ES = ["Id. de solicitud emitida", "Disposición de la solicitud", "Nombre del solicitante", "Plantilla de certificado", "Certificado binario"];
const RDP = "1.3.6.1.4.1.311.21.8.9904716.11557025.2180029.13202864.4813877.207.10850930.7780789 RDP_Template";

const DUMP = [
  row(1, "0xf (15) -- CA Cert", "MOUNTAINSIDE\\MSIG-RADIUS$", "EMPTY", FIXTURE_CERT),
  row(3, "0x14 (20) -- Issued", "MOUNTAINSIDE\\MSIG-RADIUS$", "Machine", FIXTURE_CERT),
  row(4, "0x15 (21) -- Revoked", "MOUNTAINSIDE\\MSIG-QBOOKS$", RDP, FIXTURE_CERT),
  row(22, "0x1e (30) -- Error", "MOUNTAINSIDE\\MSIG-DOMAIN01$", "EMPTY", null),
  row(23, "0x14 (20) -- Issued", "MOUNTAINSIDE\\MSIG-DOMAIN01$", RDP, "garbage")
].join("\n") + "\n";

describe("splitCertutilDump", () => {
  it("una fila por «Row N:», campos en orden y el PEM aparte", () => {
    const rows = splitCertutilDump(DUMP);
    expect(rows.length).toBe(5);
    expect(rows[1].fields.map((f) => f.label)).toEqual(EN);
    expect(rows[1].pem).toContain("-----BEGIN CERTIFICATE-----");
    expect(rows[3].pem).toBeNull();
  });
});

describe("parseCertutilDump", () => {
  it("⭐ parsea el PEM y trae plantilla (nombre y OID), solicitante y disposicion", () => {
    const out = parseCertutilDump(DUMP, "MSIG-RADIUS-CA");
    expect(out.columnsFound).toEqual({ requestId: true, disposition: true, requester: true, template: true, rawCertificate: true, positional: false });
    expect(out.issued.map((i) => i.requestId)).toEqual([1, 3, 4]);
    expect(out.issued[0].disposition).toBe(15);
    expect(out.issued[0].template).toBeUndefined();
    expect(out.issued[1].template).toBe("Machine");
    expect(out.issued[1].templateOid).toBeUndefined();
    expect(out.issued[2]).toEqual(expect.objectContaining({ disposition: 21, requester: "MOUNTAINSIDE\\MSIG-QBOOKS$", template: "RDP_Template", templateOid: "1.3.6.1.4.1.311.21.8.9904716.11557025.2180029.13202864.4813877.207.10850930.7780789" }));
    expect(out.issued[2].source).toBe("adcs");
    expect(out.issued[2].hasPrivateKey).toBe(false);
    expect(out.lastRequestId).toBe(23);
    // 22 (error, sin cert) no cuenta como fallo; 23 (basura) si.
    expect(out.parseFailures).toBe(1);
  });

  it("⭐ etiquetas LOCALIZADAS → se lee por posicion (el orden de -out es fijo) y se dice", () => {
    const dump = row(9, "0x14 (20) -- Emitido", "CORP\\host09$", "Servidor RADIUS", FIXTURE_CERT, ES) + "\n";
    const out = parseCertutilDump(dump, "CA");
    expect(out.issued.length).toBe(1);
    expect(out.issued[0].requestId).toBe(9);
    expect(out.issued[0].template).toBe("Servidor RADIUS");
    expect(out.columnsFound.positional).toBe(true);
  });

  it("⭐ un volcado sin filas «Row» (p. ej. el CSV viejo) no emite nada y lo dice", () => {
    const out = parseCertutilDump(`"Issued Request ID","Binary Certificate"\n"2","1657 Bytes"\n`, "CA");
    expect(out.issued).toEqual([]);
    expect(out.columnsFound.requestId).toBe(false);
    expect(out.columnsFound.rawCertificate).toBe(false);
  });

  it("respeta el tope", () => {
    const dump = Array.from({ length: 5 }, (_, i) => row(i + 1, "0x14 (20) -- Issued", "w", "T", FIXTURE_CERT)).join("\n");
    expect(parseCertutilDump(dump, "CA", 2).issued.length).toBe(2);
  });
});

describe("collectAdcs", () => {
  beforeEach(() => cursors.clear());
  // La policy nombra los CA servers; este equipo se llama MSIG-RADIUS-CA.
  const HOSTS = ["msig-radius-ca"];
  const ctx = (enabled: boolean, log: any[] = [], hosts: string[] = HOSTS) =>
    ({
      logger: { info: (...a: any[]) => log.push(["info", ...a]), warn: (...a: any[]) => log.push(["warn", ...a]) },
      policyRuntime: { getCdpAdcs: () => ({ enabled, maxPerScan: 2000, hosts }) },
      enrollment: { tenantId: "T1", deviceId: "D1" }
    }) as any;
  const ME = { hostname: "MSIG-RADIUS-CA" };

  it("policy apagada → no llama al PrivSvc", async () => {
    let calls = 0;
    const r = await collectAdcs(ctx(false), { ...ME, call: async () => (calls++, { ok: true }) });
    expect(r).toBeUndefined();
    expect(calls).toBe(0);
  });

  it("⭐ este equipo no esta en la lista de CAs → ni se pregunta al PrivSvc", async () => {
    let calls = 0;
    const r = await collectAdcs(ctx(true, [], ["ca02.corp.example"]), { hostname: "WS-JPACHECO", call: async () => (calls++, { ok: true }) });
    expect(r).toBeUndefined();
    expect(calls).toBe(0);
  });

  it("el nombre casa en NetBIOS o FQDN, sin mayusculas", () => {
    expect(hostMatches(["msig-radius-ca"], "MSIG-RADIUS-CA.corp.example")).toBe(true);
    expect(hostMatches(["MSIG-RADIUS-CA.corp.example"], "msig-radius-ca")).toBe(true);
    expect(hostMatches(["ca02"], "msig-radius-ca")).toBe(false);
    expect(hostMatches([], "msig-radius-ca")).toBe(false);
  });

  it("no es CA → bloque isCa:false, sin emisiones", async () => {
    const r = await collectAdcs(ctx(true), { ...ME, call: async () => ({ ok: true, result: { isCa: false } }) });
    expect(r).toEqual(expect.objectContaining({ isCa: false, caName: null, issued: [] }));
  });

  it("⭐ incremental: manda el cursor y lo avanza al ultimo RequestID", async () => {
    cursors.set("*", 100);
    const params: any[] = [];
    const r = await collectAdcs(ctx(true), {
      ...ME,
      call: async (p) => (params.push(p), { ok: true, result: { isCa: true, caName: "MSIG-RADIUS-CA", dump: DUMP, rows: 5, truncated: false } })
    });
    expect(params[0]).toEqual({ sinceRequestId: 100, maxRows: 2000 });
    expect(r?.isCa).toBe(true);
    expect(r?.caName).toBe("MSIG-RADIUS-CA");
    expect(r?.sinceRequestId).toBe(100);
    expect(r?.lastRequestId).toBe(23);
    expect(r?.issued.length).toBe(3);
    expect(cursors.get("*")).toBe(23);
    expect(cursors.get("MSIG-RADIUS-CA")).toBe(23);
  });

  it("cabecera no reconocida → warn con la cabecera, cursor intacto", async () => {
    const log: any[] = [];
    const r = await collectAdcs(ctx(true, log), {
      ...ME,
      call: async () => ({ ok: true, result: { isCa: true, caName: "CA", csv: `"Foo","Bar"\n"1","2"\n`, stderr: "" } })
    });
    expect(r?.issued).toEqual([]);
    expect(log.some(([lvl, msg]) => lvl === "warn" && /cabecera/.test(msg))).toBe(true);
    expect(cursors.has("*")).toBe(false);
  });

  it("error del PrivSvc → undefined (fallo blando)", async () => {
    const r = await collectAdcs(ctx(true), { ...ME, call: async () => ({ ok: false, error: { code: "adcs_read_failed", message: "x" } }) });
    expect(r).toBeUndefined();
  });

  it("tope de policy acotado a [50, 5000]", async () => {
    const params: any[] = [];
    const c = { ...ctx(true), policyRuntime: { getCdpAdcs: () => ({ enabled: true, maxPerScan: 99999, hosts: HOSTS }) } };
    await collectAdcs(c, { ...ME, call: async (p) => (params.push(p), { ok: true, result: { isCa: false } }) });
    expect(params[0].maxRows).toBe(5000);
  });
});
