// test/plugins/cdp-adcs.test.ts
//
// Conector AD CS (fase 4): el parser del CSV de certutil y el provider
// con un PrivSvc falso. El CSV del fixture esta HECHO A MANO contra la
// documentacion de `certutil -view -csv`; la forma real de una CA se
// verifica en campo (MSIG-RADIUS-CA) y, si difiere, el parser dice que
// columnas no reconocio en vez de devolver cero en silencio.

import { describe, it, expect, vi, beforeEach } from "vitest";
import crypto from "crypto";
import { parseCsv, parseCertutilCsv } from "../../src/plugins/cdp/adcs-csv";
import { FIXTURE_CERT } from "./tls-fixture";

const cursors = new Map<string, number>();
vi.mock("../../src/domain/cdp-adcs-repo", () => ({
  readAdcsCursor: (ca: string) => cursors.get(ca) ?? 0,
  writeAdcsCursor: (ca: string, id: number) => cursors.set(ca, id)
}));

import { collectAdcs } from "../../src/plugins/cdp/providers/adcs";

const PEM_BODY = FIXTURE_CERT.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").trim();
const HEADER = `"Request ID","Request Disposition","Requester Name","Certificate Template","Binary Certificate"`;
const row = (id: number, disp: string, who: string, tpl: string, pem: string | null) =>
  `"${id}","${disp}","${who}","${tpl}","${pem === null ? "EMPTY" : `-----BEGIN CERTIFICATE-----\n${pem}\n-----END CERTIFICATE-----\n`}"`;

const CSV = [
  HEADER,
  row(101, "20 -- Issued", `CORP\\host01$`, "RADIUS Server", PEM_BODY),
  row(102, "21 -- Revoked", `CORP\\host02$`, "Workstation Authentication", PEM_BODY),
  row(103, "31 -- Denied", `CORP\\bob`, "User", null),
  row(104, "20 -- Issued", `CORP\\host03$`, "RADIUS Server", "not-base64-at-all")
].join("\r\n") + "\r\n";

describe("parseCsv", () => {
  it("campos entre comillas con saltos de linea y comillas escapadas", () => {
    const { header, rows } = parseCsv(`"a","b"\r\n"1","x\ny ""z"""\r\n"2","w"\r\n`);
    expect(header).toEqual(["a", "b"]);
    expect(rows).toEqual([["1", 'x\ny "z"'], ["2", "w"]]);
  });

  it("BOM y linea final vacia no rompen", () => {
    const { header, rows } = parseCsv(`﻿"a"\n"1"\n\n`);
    expect(header).toEqual(["a"]);
    expect(rows).toEqual([["1"]]);
  });
});

describe("parseCertutilCsv", () => {
  it("⭐ parsea el PEM multilinea y trae plantilla, solicitante y disposicion", () => {
    const out = parseCertutilCsv(CSV, "MSIG-RADIUS-CA");
    expect(out.columnsFound).toEqual({ requestId: true, disposition: true, requester: true, template: true, rawCertificate: true });
    expect(out.issued.map((i) => i.requestId)).toEqual([101, 102]);
    const first = out.issued[0];
    expect(first.source).toBe("adcs");
    expect(first.hasPrivateKey).toBe(false);
    expect(first.store).toEqual({ id: "adcs/MSIG-RADIUS-CA", name: "MSIG-RADIUS-CA", scope: "network" });
    expect(first.template).toBe("RADIUS Server");
    expect(first.requester).toBe("CORP\\host01$");
    expect(first.disposition).toBe(20);
    expect(out.issued[1].disposition).toBe(21);
    const expected = crypto.createHash("sha256").update(new crypto.X509Certificate(FIXTURE_CERT).raw).digest("hex");
    expect(first.fingerprint256.toLowerCase().replace(/:/g, "")).toBe(expected);
  });

  it("denegadas sin certificado no cuentan como fallo; basura si", () => {
    const out = parseCertutilCsv(CSV, "CA");
    expect(out.parseFailures).toBe(1);
    // El cursor avanza tambien sobre las filas sin certificado: si no,
    // una denegada al final se releeria en cada escaneo.
    expect(out.lastRequestId).toBe(104);
  });

  it("acepta los nombres internos de columna (RequestID, Request.Disposition, RawCertificate)", () => {
    const csv = `"RequestID","Request.Disposition","Request.RequesterName","CertificateTemplate","RawCertificate"\n` + row(7, "20", "x", "T", PEM_BODY) + "\n";
    const out = parseCertutilCsv(csv, "CA");
    expect(out.issued.length).toBe(1);
    expect(out.issued[0].disposition).toBe(20);
  });

  it("⭐ cabecera desconocida → nada emitido, pero se DICE que columnas faltan", () => {
    const out = parseCertutilCsv(`"Foo","Bar"\n"1","2"\n`, "CA");
    expect(out.issued).toEqual([]);
    expect(out.columnsFound.requestId).toBe(false);
    expect(out.columnsFound.rawCertificate).toBe(false);
    expect(out.header).toEqual(["Foo", "Bar"]);
    expect(out.parseFailures).toBe(1);
  });

  it("respeta el tope", () => {
    const csv = [HEADER, ...Array.from({ length: 5 }, (_, i) => row(i + 1, "20", "w", "T", PEM_BODY))].join("\n");
    expect(parseCertutilCsv(csv, "CA", 2).issued.length).toBe(2);
  });
});

describe("collectAdcs", () => {
  beforeEach(() => cursors.clear());
  const ctx = (enabled: boolean, log: any[] = []) =>
    ({
      logger: { info: (...a: any[]) => log.push(["info", ...a]), warn: (...a: any[]) => log.push(["warn", ...a]) },
      policyRuntime: { getCdpAdcs: () => ({ enabled, maxPerScan: 2000 }) },
      enrollment: { tenantId: "T1", deviceId: "D1" }
    }) as any;

  it("policy apagada → no llama al PrivSvc", async () => {
    let calls = 0;
    const r = await collectAdcs(ctx(false), { call: async () => (calls++, { ok: true }) });
    expect(r).toBeUndefined();
    expect(calls).toBe(0);
  });

  it("no es CA → bloque isCa:false, sin emisiones", async () => {
    const r = await collectAdcs(ctx(true), { call: async () => ({ ok: true, result: { isCa: false } }) });
    expect(r).toEqual(expect.objectContaining({ isCa: false, caName: null, issued: [] }));
  });

  it("⭐ incremental: manda el cursor y lo avanza al ultimo RequestID", async () => {
    cursors.set("*", 100);
    const params: any[] = [];
    const r = await collectAdcs(ctx(true), {
      call: async (p) => (params.push(p), { ok: true, result: { isCa: true, caName: "MSIG-RADIUS-CA", csv: CSV, rows: 4, truncated: false } })
    });
    expect(params[0]).toEqual({ sinceRequestId: 100, maxRows: 2000 });
    expect(r?.isCa).toBe(true);
    expect(r?.caName).toBe("MSIG-RADIUS-CA");
    expect(r?.sinceRequestId).toBe(100);
    expect(r?.lastRequestId).toBe(104);
    expect(r?.issued.length).toBe(2);
    expect(cursors.get("*")).toBe(104);
    expect(cursors.get("MSIG-RADIUS-CA")).toBe(104);
  });

  it("cabecera no reconocida → warn con la cabecera, cursor intacto", async () => {
    const log: any[] = [];
    const r = await collectAdcs(ctx(true, log), {
      call: async () => ({ ok: true, result: { isCa: true, caName: "CA", csv: `"Foo","Bar"\n"1","2"\n`, stderr: "" } })
    });
    expect(r?.issued).toEqual([]);
    expect(log.some(([lvl, msg]) => lvl === "warn" && /cabecera/.test(msg))).toBe(true);
    expect(cursors.has("*")).toBe(false);
  });

  it("error del PrivSvc → undefined (fallo blando)", async () => {
    const r = await collectAdcs(ctx(true), { call: async () => ({ ok: false, error: { code: "adcs_read_failed", message: "x" } }) });
    expect(r).toBeUndefined();
  });

  it("tope de policy acotado a [50, 5000]", async () => {
    const params: any[] = [];
    const c = { ...ctx(true), policyRuntime: { getCdpAdcs: () => ({ enabled: true, maxPerScan: 99999 }) } };
    await collectAdcs(c, { call: async (p) => (params.push(p), { ok: true, result: { isCa: false } }) });
    expect(params[0].maxRows).toBe(5000);
  });
});
