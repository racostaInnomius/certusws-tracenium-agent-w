// test/plugins/cdp-pkcs12.test.ts
//
// PKCS#12 (.p12/.pfx) en `cdp.certFilePaths`.
//
// Hasta ahora el escaneo listaba `.p12`/`.pfx` entre las extensiones y el
// comentario decía que se abrían con contraseña vacía, pero el parser
// devolvía [] para ellos: el PFX de un IIS o de un Tomcat no existía para
// CDP, y uno con contraseña tampoco se decía — silencio en los dos casos.
//
// Los PFX se generan en el test con el `openssl` del sistema (igual que
// dp-peer-cas.test.ts): así se prueban las variantes REALES que emite una
// herramienta de terceros, no las que nuestro propio código sabría escribir.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "child_process";
import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import { readPkcs12Certificates, rc2DecryptEcbBlock, Pkcs12Error } from "../../src/plugins/cdp/pkcs12";
import { collectCertFiles } from "../../src/plugins/cdp/providers/cert-files";
import { OPENSSL } from "../privsvc/openssl-compat";

let dir: string;
let legacyOk = false;
const ossl = (...args: string[]) => execFileSync(OPENSSL, args, { cwd: dir, stdio: "pipe" });
const read = (name: string) => fs.readFileSync(path.join(dir, "pfx", name));
const cnOf = (der: Buffer) => new crypto.X509Certificate(der).subject;

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-pkcs12-"));
  fs.mkdirSync(path.join(dir, "pfx"));
  ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.pem",
    "-subj", "/CN=pfx-leaf", "-days", "30");
  ossl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
    "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=pfx-ca", "-days", "30");

  // Contraseña vacía + clave + un certificado de cadena sin clave.
  ossl("pkcs12", "-export", "-in", "leaf.pem", "-inkey", "leaf.key", "-certfile", "ca.pem",
    "-passout", "pass:", "-out", "pfx/empty-with-key.pfx");
  // Con contraseña que no conocemos.
  ossl("pkcs12", "-export", "-in", "leaf.pem", "-inkey", "leaf.key",
    "-passout", "pass:no-la-sabemos", "-out", "pfx/protected.p12");
  // Solo certificados, sin clave.
  ossl("pkcs12", "-export", "-nokeys", "-in", "ca.pem", "-passout", "pass:", "-out", "pfx/cert-only.p12");
  // Sin MAC: la contraseña la decide el descifrado. Con `-nomac` OpenSSL
  // deja los certificados EN CLARO salvo que se pida `-certpbe`.
  ossl("pkcs12", "-export", "-in", "leaf.pem", "-inkey", "leaf.key", "-nomac",
    "-passout", "pass:no-la-sabemos", "-out", "nomac-plain-certs.p12");
  ossl("pkcs12", "-export", "-in", "leaf.pem", "-inkey", "leaf.key", "-nomac", "-certpbe", "AES-256-CBC",
    "-passout", "pass:no-la-sabemos", "-out", "nomac-protected.p12");
  // El formato de OpenSSL 1.x / exportaciones viejas (RC2-40 + 3DES). El
  // proveedor legacy puede faltar en el openssl del runner: si falta, ese
  // test se salta en vez de mentir.
  try {
    ossl("pkcs12", "-export", "-legacy", "-in", "leaf.pem", "-inkey", "leaf.key", "-certfile", "ca.pem",
      "-passout", "pass:", "-out", "legacy.p12");
    legacyOk = true;
  } catch {
    legacyOk = false;
  }
  // Un .pfx que no es PKCS#12 en absoluto.
  fs.writeFileSync(path.join(dir, "pfx", "garbage.pfx"), "esto no es un pfx");
});

afterAll(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("RC2 (RFC 2268) — vectores del RFC", () => {
  // RC2 se implementa en JS porque el OpenSSL 3 de Node no lo carga; sin
  // él los PFX de OpenSSL 1.x serían ilegibles.
  it.each([
    ["0000000000000000", 63, "0000000000000000", "ebb773f993278eff"],
    ["ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"],
    ["3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"],
    ["88", 64, "0000000000000000", "61a8a244adacccf0"]
  ])("clave %s / %d bits", (key, bits, plain, cipher) => {
    const out = rc2DecryptEcbBlock(Buffer.from(key, "hex"), bits, Buffer.from(cipher, "hex"));
    expect(out.toString("hex")).toBe(plain);
  });
});

describe("readPkcs12Certificates", () => {
  it("contraseña vacía + clave: todos los certificados, hasPrivateKey solo en el de la clave", () => {
    const certs = readPkcs12Certificates(read("empty-with-key.pfx"));
    const byCn = Object.fromEntries(certs.map((c) => [cnOf(c.der), c.hasPrivateKey]));
    expect(byCn).toEqual({ "CN=pfx-leaf": true, "CN=pfx-ca": false });
  });

  it("contraseña desconocida: lanza con razón, NO devuelve vacío", () => {
    expect(() => readPkcs12Certificates(read("protected.p12"))).toThrow(Pkcs12Error);
    expect(() => readPkcs12Certificates(read("protected.p12"))).toThrow(/password required/);
  });

  it("bolsa solo de certificados: se leen, ninguno con clave", () => {
    const certs = readPkcs12Certificates(read("cert-only.p12"));
    expect(certs.map((c) => cnOf(c.der))).toEqual(["CN=pfx-ca"]);
    expect(certs.every((c) => c.hasPrivateKey === false)).toBe(true);
  });

  it("sin MAC: certificados en claro se leen; cifrados con contraseña real se reportan", () => {
    // La clave sigue cifrada con una contraseña que no tenemos, y da
    // igual: de su bolsa solo se lee el localKeyId.
    expect(readPkcs12Certificates(fs.readFileSync(path.join(dir, "nomac-plain-certs.p12"))).map((c) => c.hasPrivateKey))
      .toEqual([true]);
    expect(() => readPkcs12Certificates(fs.readFileSync(path.join(dir, "nomac-protected.p12"))))
      .toThrow(/password required/);
  });

  it("formato legacy (RC2-40 + 3DES de OpenSSL 1.x)", (ctx) => {
    if (!legacyOk) ctx.skip();
    const certs = readPkcs12Certificates(fs.readFileSync(path.join(dir, "legacy.p12")));
    expect(certs.map((c) => [cnOf(c.der), c.hasPrivateKey]).sort()).toEqual([
      ["CN=pfx-ca", false],
      ["CN=pfx-leaf", true]
    ]);
  });

  it("un PFX truncado lanza Pkcs12Error, no otra cosa", () => {
    const buf = read("empty-with-key.pfx");
    expect(() => readPkcs12Certificates(buf.subarray(0, buf.length - 40))).toThrow(Pkcs12Error);
  });

  it("nunca devuelve bytes de clave: cada blob es un certificado X.509", () => {
    // El DER de la clave no puede colarse como "certificado": todo lo
    // devuelto debe parsear como X.509.
    for (const c of readPkcs12Certificates(read("empty-with-key.pfx"))) {
      expect(() => new crypto.X509Certificate(c.der)).not.toThrow();
    }
  });
});

describe("collectCertFiles con PKCS#12", () => {
  it("emite los certificados del PFX con hasPrivateKey y fuente `file`", async () => {
    const r = await collectCertFiles([path.join(dir, "pfx")]);
    const all = r.items
      .map((i) => [path.basename(i.store.name), i.subjectCN, i.hasPrivateKey, i.source])
      .sort((a, b) => String(a).localeCompare(String(b)));
    expect(all).toEqual([
      ["cert-only.p12", "pfx-ca", false, "file"],
      ["empty-with-key.pfx", "pfx-ca", false, "file"],
      ["empty-with-key.pfx", "pfx-leaf", true, "file"]
    ]);
  });

  it("un PFX con contraseña es un almacén ILEGIBLE con razón, no un fichero vacío", async () => {
    const r = await collectCertFiles([path.join(dir, "pfx")]);
    const protectedPath = path.join(dir, "pfx", "protected.p12");
    expect(r.unreadableFiles).toContain(protectedPath);
    expect(r.unreadableReasons[protectedPath]).toMatch(/^pkcs12: password required/);
    expect(r.unreadable).toBe(1);
  });

  it("un .pfx que no es PKCS#12 no se reporta como ilegible (como un .crt basura)", async () => {
    const r = await collectCertFiles([path.join(dir, "pfx")]);
    expect(r.unreadableFiles.some((f) => f.endsWith("garbage.pfx"))).toBe(false);
  });
});
