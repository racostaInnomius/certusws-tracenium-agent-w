// test/plugins/cdp-macos-trust-anchor.test.ts
//
// trustAnchor (2-oct-2026): en macOS estar en System.keychain NO da
// confianza; la dan los trust settings. Se contaba cualquier raíz del
// llavero como «en el trust store»: la «Tracenium Root CA» de este agente
// (sin confianza, CSSMERR_TP_NOT_TRUSTED) y la de mkcert tras
// `mkcert -uninstall`, que sólo quita la confianza.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import {
  MAX_TRUST_CHECKS,
  annotateTrustAnchors,
  isTrustAnchorCandidate,
  trustAnchorFromVerify,
  verifyCertWithSecurity
} from "../../src/plugins/cdp/providers/macos";
import { parseCertToItem, parsedDerRegistry, resetParsedDerRegistry } from "../../src/plugins/cdp/parse-cert";
import { annotateStoreChains } from "../../src/plugins/cdp/chain-verify";
import type { CdpCertItem, CdpStoreInfo } from "../../src/domain/cdp-types";
import { OPENSSL } from "../privsvc/openssl-compat";

const SYSTEM: CdpStoreInfo = { id: "keychain/system", name: "System.keychain", scope: "machine" };
const SYSTEM_ROOTS: CdpStoreInfo = { id: "keychain/system-roots", name: "SystemRootCertificates.keychain", scope: "system-roots" };
const LOGIN: CdpStoreInfo = { id: "keychain/login/ana", name: "login.keychain (ana)", scope: "user" };

const item = (over: Partial<CdpCertItem> = {}): CdpCertItem =>
  ({ id: "x", fingerprint256: "aa", store: SYSTEM, source: "store", isCA: true, selfSigned: true, ...over }) as CdpCertItem;

describe("trustAnchorFromVerify", () => {
  it("⭐ verifica → true; CSSMERR_TP_NOT_TRUSTED → false", () => {
    expect(trustAnchorFromVerify({ ok: true, output: "...certificate verification successful.\n" })).toBe(true);
    expect(trustAnchorFromVerify({ ok: false, output: "Cert Verify Result: CSSMERR_TP_NOT_TRUSTED\n" })).toBe(false);
  });

  it("❗ cualquier otro fallo, o sin respuesta, queda SIN veredicto (se juzga por presencia)", () => {
    expect(trustAnchorFromVerify({ ok: false, output: "Cert Verify Result: CSSMERR_TP_CERT_EXPIRED\n" })).toBeUndefined();
    expect(trustAnchorFromVerify({ ok: false, output: "" })).toBeUndefined();
    expect(trustAnchorFromVerify(null)).toBeUndefined();
  });
});

describe("isTrustAnchorCandidate", () => {
  it("sólo las raíces (CA autofirmada) de System.keychain", () => {
    expect(isTrustAnchorCandidate(item())).toBe(true);
    expect(isTrustAnchorCandidate(item({ selfSigned: false }))).toBe(false); // intermedia
    expect(isTrustAnchorCandidate(item({ isCA: false }))).toBe(false); // hoja autofirmada
    // El bundle de Apple: estar ahí sí es la confianza (157 de 158 medidos).
    expect(isTrustAnchorCandidate(item({ store: SYSTEM_ROOTS }))).toBe(false);
    // Login keychain: verify-cert corre como root y no vería la confianza de esa persona.
    expect(isTrustAnchorCandidate(item({ store: LOGIN }))).toBe(false);
  });
});

describe("annotateTrustAnchors", () => {
  it("⭐ anota el veredicto; sin veredicto, el campo NO aparece (ausente ≠ false)", async () => {
    const roots = ["ok", "denied", "expired", "boom"].map((pem) => ({ item: item({ id: pem }), pem }));
    await annotateTrustAnchors(roots, async (pem) => {
      if (pem === "boom") throw new Error("spawn failed");
      if (pem === "ok") return { ok: true, output: "" };
      return { ok: false, output: pem === "denied" ? "CSSMERR_TP_NOT_TRUSTED" : "CSSMERR_TP_CERT_EXPIRED" };
    });
    expect(roots.map(({ item }) => item.trustAnchor)).toEqual([true, false, undefined, undefined]);
    expect(roots[2].item).not.toHaveProperty("trustAnchor");
  });

  it("tiene tope: por encima, sin veredicto", async () => {
    const roots = Array.from({ length: MAX_TRUST_CHECKS + 3 }, (_, i) => ({ item: item({ id: String(i) }), pem: String(i) }));
    let calls = 0;
    await annotateTrustAnchors(roots, async () => {
      calls += 1;
      return { ok: false, output: "CSSMERR_TP_NOT_TRUSTED" };
    });
    expect(calls).toBe(MAX_TRUST_CHECKS);
    expect(roots.at(-1)!.item.trustAnchor).toBeUndefined();
  });
});

// ── Certificados reales: la cadena y el propio macOS ────────────────────

let dir: string;
const pem: Record<string, string> = {};

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-trust-"));
  const o = (...a: string[]) => execFileSync(OPENSSL, a, { cwd: dir, stdio: "pipe" });
  for (const n of ["corp", "leaf"]) o("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", `${n}.key`);
  o("req", "-x509", "-key", "corp.key", "-out", "corp.pem", "-subj", "/CN=Corp Root CA", "-days", "30",
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign");
  fs.writeFileSync(path.join(dir, "leaf.ext"), "basicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n");
  o("req", "-new", "-key", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=app.corp.example");
  o("x509", "-req", "-in", "leaf.csr", "-CA", "corp.pem", "-CAkey", "corp.key", "-CAcreateserial", "-out", "leaf.pem", "-days", "20", "-extfile", "leaf.ext");
  for (const n of ["corp", "leaf"]) pem[n] = fs.readFileSync(path.join(dir, `${n}.pem`), "utf8");
});

afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

describe("cadena: una CA de empresa en System.keychain", () => {
  const scan = (trustAnchor: boolean | undefined) => {
    resetParsedDerRegistry();
    const root = { ...parseCertToItem(pem.corp, { store: SYSTEM })!, source: "store" as const };
    if (trustAnchor !== undefined) root.trustAnchor = trustAnchor;
    const leaf = { ...parseCertToItem(pem.leaf, { store: { id: "keychain/login/ana", name: "login", scope: "user" } })!, source: "store" as const };
    annotateStoreChains([root, leaf], parsedDerRegistry());
    return leaf.chain;
  };

  it("⭐ si macOS confía en la raíz, la hoja que firma llega a una raíz de confianza", () => {
    expect(scan(true)).toEqual({ issuerFound: true, signatureValid: true, trusted: true });
  });

  it("sin confianza, o sin veredicto, no", () => {
    expect(scan(false)?.trusted).toBe(false);
    expect(scan(undefined)?.trusted).toBe(false);
  });
});

describe.runIf(process.platform === "darwin")("verifyCertWithSecurity — el macOS de verdad", () => {
  it("⭐ una raíz del bundle de Apple: true; una autofirmada que nadie instaló: false", async () => {
    const apple = execFileSync("/usr/bin/security", [
      "find-certificate", "-c", "Apple Root CA - G3", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain"
    ]).toString();
    expect(trustAnchorFromVerify(await verifyCertWithSecurity(apple))).toBe(true);
    expect(trustAnchorFromVerify(await verifyCertWithSecurity(pem.corp))).toBe(false);
  });

  it("⭐ collectMacosCdp anota las raíces de System.keychain y nada más", async () => {
    const { collectMacosCdp } = await import("../../src/plugins/cdp/providers/macos");
    const { items } = await collectMacosCdp();
    const roots = items.filter(isTrustAnchorCandidate);
    // En un Mac con el agente instalado está la «Tracenium Root CA», que
    // macOS no trata como ancla (medido 2-oct-2026). Sin raíces en el
    // llavero no hay nada que comprobar aquí.
    for (const r of roots) expect(typeof r.trustAnchor, r.subjectCN).toBe("boolean");
    const tracenium = roots.find((r) => r.subjectCN === "Tracenium Root CA");
    if (tracenium) expect(tracenium.trustAnchor).toBe(false);
    expect(items.filter((i) => !isTrustAnchorCandidate(i) && "trustAnchor" in i)).toEqual([]);
  }, 60_000);

  it("no deja ficheros temporales", async () => {
    const before = fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith("tracenium-cdp-trust-"));
    await verifyCertWithSecurity(pem.corp);
    const after = fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith("tracenium-cdp-trust-"));
    expect(after).toEqual(before);
  });
});
