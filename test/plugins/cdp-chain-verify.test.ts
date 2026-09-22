// test/plugins/cdp-chain-verify.test.ts
//
// Ola 1.3a — cadena de los certificados de ALMACÉN.
//
// Jerarquía real generada con openssl: raíz → intermedia → hoja, más una
// raíz «privada» que no está en el almacén de raíces, y una hoja cuyo
// emisor dice ser la intermedia pero la firmó otra clave (mismo DN, firma
// que no casa: lo que se ve con una CA reemitida o un certificado
// manipulado).

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { parseCertToItem, parsedDerRegistry, resetParsedDerRegistry } from "../../src/plugins/cdp/parse-cert";
import { annotateStoreChains } from "../../src/plugins/cdp/chain-verify";
import type { CdpCertItem, CdpStoreInfo } from "../../src/domain/cdp-types";
import { OPENSSL } from "../privsvc/openssl-compat";

let dir: string;
const pem: Record<string, string> = {};

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-chain-"));
  const o = (...a: string[]) => execFileSync(OPENSSL, a, { cwd: dir, stdio: "pipe" });
  fs.writeFileSync(path.join(dir, "ca.ext"), "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n");
  fs.writeFileSync(path.join(dir, "leaf.ext"), "basicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n");
  const key = (n: string) => o("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", `${n}.key`);
  for (const n of ["root", "inter", "leaf", "priv", "privleaf", "impostor", "orphan"]) key(n);
  o("req", "-x509", "-key", "root.key", "-out", "root.pem", "-subj", "/CN=Test Root", "-days", "30",
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign");
  const issue = (n: string, cn: string, caKey: string, caPem: string, ext: string) => {
    o("req", "-new", "-key", `${n}.key`, "-out", `${n}.csr`, "-subj", `/CN=${cn}`);
    o("x509", "-req", "-in", `${n}.csr`, "-CA", caPem, "-CAkey", caKey, "-CAcreateserial", "-out", `${n}.pem`, "-days", "20", "-extfile", ext);
  };
  issue("inter", "Test Intermediate", "root.key", "root.pem", "ca.ext");
  issue("leaf", "leaf.example", "inter.key", "inter.pem", "leaf.ext");
  o("req", "-x509", "-key", "priv.key", "-out", "priv.pem", "-subj", "/CN=Private Root", "-days", "30",
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign");
  issue("privleaf", "privleaf.example", "priv.key", "priv.pem", "leaf.ext");
  // Impostor: una «intermedia» con el MISMO DN pero otra clave, que firma una hoja.
  o("req", "-x509", "-key", "impostor.key", "-out", "impostor-ca.pem", "-subj", "/CN=Test Intermediate", "-days", "30",
    "-addext", "basicConstraints=critical,CA:TRUE");
  // Firmada por el impostor pero SIN AKI, para que checkIssued no la
  // descarte por identificador y la firma sea lo que decide.
  fs.writeFileSync(path.join(dir, "noaki.ext"), "basicConstraints=CA:FALSE\nsubjectKeyIdentifier=none\nauthorityKeyIdentifier=none\n");
  issue("orphan", "forged.example", "impostor.key", "impostor-ca.pem", "noaki.ext");
  for (const n of ["root", "inter", "leaf", "priv", "privleaf", "orphan"]) pem[n] = fs.readFileSync(path.join(dir, `${n}.pem`), "utf8");
});

afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

const roots: CdpStoreInfo = { id: "lm/root", name: "LocalMachine\\Root", scope: "system-roots" };
const ca: CdpStoreInfo = { id: "lm/ca", name: "LocalMachine\\CA", scope: "machine" };
const my: CdpStoreInfo = { id: "lm/my", name: "LocalMachine\\My", scope: "machine" };

function scan(entries: Array<[string, CdpStoreInfo, CdpCertItem["source"]?]>): CdpCertItem[] {
  resetParsedDerRegistry();
  const items = entries.map(([n, store, source]) => ({ ...parseCertToItem(pem[n], { store })!, source: source ?? "store" }));
  return annotateStoreChains(items, parsedDerRegistry());
}
const byCn = (items: CdpCertItem[], cn: string) => items.find((i) => i.subjectCN === cn)!;

describe("annotateStoreChains", () => {
  it("⭐ cadena completa hasta una raíz del SO: emisor, firma y confianza", () => {
    const items = scan([["root", roots], ["inter", ca], ["leaf", my]]);
    expect(byCn(items, "leaf.example").chain).toEqual({ issuerFound: true, signatureValid: true, trusted: true });
    expect(byCn(items, "Test Intermediate").chain).toEqual({ issuerFound: true, signatureValid: true, trusted: true });
    // Una raíz autofirmada no tiene veredicto: no hay emisor que buscar.
    expect(byCn(items, "Test Root").chain).toBeUndefined();
  });

  it("⭐ intermedia ausente del equipo: issuerFound false, sin inventar confianza", () => {
    const items = scan([["root", roots], ["leaf", my]]);
    expect(byCn(items, "leaf.example").chain).toEqual({ issuerFound: false });
  });

  it("cadena que acaba en una raíz que NO es del almacén del SO: trusted false", () => {
    const items = scan([["priv", ca], ["privleaf", my]]);
    expect(byCn(items, "privleaf.example").chain).toEqual({ issuerFound: true, signatureValid: true, trusted: false });
  });

  it("los cacerts de Java no son la confianza del equipo", () => {
    const items = scan([["priv", roots, "java-store"], ["privleaf", my]]);
    expect(byCn(items, "privleaf.example").chain?.trusted).toBe(false);
  });

  it("⭐ emisor con el mismo DN pero otra clave: signatureValid false", () => {
    const items = scan([["root", roots], ["inter", ca], ["orphan", my]]);
    expect(byCn(items, "forged.example").chain).toEqual({ issuerFound: true, signatureValid: false, trusted: false });
  });

  it("listeners y sondas no se evalúan aquí (su cadena la juzga el handshake)", () => {
    const items = scan([["root", roots], ["inter", ca], ["leaf", my, "listener"]]);
    expect(byCn(items, "leaf.example").chain).toBeUndefined();
  });

  it("sin DER registrado no hay veredicto (ausencia, no «falso»)", () => {
    const items = scan([["root", roots], ["leaf", my]]);
    resetParsedDerRegistry();
    const leaf = { ...byCn(items, "leaf.example"), chain: undefined };
    annotateStoreChains([leaf], parsedDerRegistry());
    expect(leaf.chain).toBeUndefined();
  });
});

describe("caIssuerUrls (ola 1.7)", () => {
  it("se extraen solo las http:// del AIA caIssuers", () => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-aia-"));
    try {
      const o = (...a: string[]) => execFileSync(OPENSSL, a, { cwd: d, stdio: "pipe" });
      o("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "k.pem", "-out", "c.pem",
        "-subj", "/CN=aia", "-days", "5",
        "-addext", "authorityInfoAccess=caIssuers;URI:http://pki.example/ca.crt,caIssuers;URI:https://pki.example/ca.crt,OCSP;URI:http://ocsp.example");
      const item = parseCertToItem(fs.readFileSync(path.join(d, "c.pem"), "utf8"), { store: my })!;
      expect(item.caIssuerUrls).toEqual(["http://pki.example/ca.crt"]);
      expect(item.ocspUrls).toEqual(["http://ocsp.example"]);
    } finally {
      fs.rmSync(d, { recursive: true, force: true });
    }
  });
});
