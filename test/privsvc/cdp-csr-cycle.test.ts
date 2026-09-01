// test/privsvc/cdp-csr-cycle.test.ts
//
// ADR-0011 FASE 2 — el ciclo completo contra herramientas REALES.
//
// El contrato de nombres se prueba aparte (cdp-keys-contract.test.ts);
// aquí se prueba que lo que sale es un CSR que una CA aceptaría, que la
// clave se destruye en toda salida terminal (decisión 9.c) y que una
// huérfana aparece en el inventario (9.d).
//
// ⚠️ Nada de mocks de OpenSSL ni del llavero. Un CSR se codifica en DER
// y un DER mal armado pasa cualquier aserción sobre cadenas: quien tiene
// que dar el visto bueno es OpenSSL, que es quien lo va a leer de verdad
// en la CA.

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync, spawnSync } from "child_process";

const req = (method: string, params: any) => ({ v: 1 as const, id: "t1", method, params });

/** OpenSSL da el veredicto de -verify por STDERR, no por stdout. */
// ⚠️ `/usr/bin/openssl` NO es el mismo binario en todas partes, y el formato
// del subject depende de cuál sea: LibreSSL (el que trae macOS) imprime
// `Subject: CN=web01.corp, O=Acme`, y OpenSSL 3.x —el del ubuntu-latest del
// CI— mete espacios: `Subject: CN = web01.corp, O = Acme`.
//
// El CSR es idéntico y correcto en ambos casos; sólo cambia cómo se imprime.
// Por eso las aserciones sobre el DN van con regex tolerante a los espacios
// y no con `toContain`, que ataba el test al openssl de quien lo escribió.
function verificaCsr(pem: string, dir: string) {
  const f = path.join(dir, `req-${Math.abs(hash(pem))}.pem`);
  fs.writeFileSync(f, pem);
  const v = spawnSync("/usr/bin/openssl", ["req", "-in", f, "-noout", "-verify"], {
    encoding: "utf8"
  });
  const texto = execFileSync("/usr/bin/openssl", ["req", "-in", f, "-noout", "-text"], {
    encoding: "utf8"
  });
  return { status: v.status, salida: `${v.stdout}${v.stderr}`, texto };
}
function hash(s: string) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}

// ── Linux: clave en fichero, directorio restringido ────────────────

describe("cdp.csr.generate — Linux (openssl real)", () => {
  let lin: any;
  let raiz: string;

  beforeAll(async () => {
    raiz = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-lin-"));
    process.env.TRACENIUM_PRIVSVC_CONFIG_DIR = raiz;
    lin = await import("../../privsvc/linux/src/cdp-keys");
  });

  afterAll(() => {
    try {
      fs.rmSync(raiz, { recursive: true, force: true });
    } catch {}
    delete process.env.TRACENIUM_PRIVSVC_CONFIG_DIR;
  });

  it("emite un CSR que OpenSSL da por bueno, con lo pedido dentro", async () => {
    const r: any = await lin.handleCdpCsrGenerate(
      req("cdp.csr.generate", {
        keyId: "web01",
        subject: "CN=web01.corp,O=Acme,OU=IT",
        dnsNames: ["web01.corp", "web01"],
        uris: ["spiffe://acme/web01"],
        eku: "serverAuth",
        requestId: "req-abc"
      })
    );
    expect(r.ok).toBe(true);
    expect(r.result.keyStore).toBe("file-restricted");

    const v = verificaCsr(r.result.csrPem, raiz);
    expect(v.status).toBe(0);
    expect(v.salida).toMatch(/verify OK/i);
    expect(v.texto).toMatch(/CN\s*=\s*web01\.corp/);
    expect(v.texto).toContain("TLS Web Server Authentication");
    expect(v.texto).toContain("DNS:web01.corp, DNS:web01");
    expect(v.texto).toContain("URI:spiffe://acme/web01");
  }, 30_000);

  it("la clave queda 0600 en un directorio 0700, y NO donde la del agente", () => {
    const p = lin.cdpKeyPath("web01");
    expect(fs.existsSync(p)).toBe(true);
    expect(fs.statSync(p).mode & 0o777).toBe(0o600);
    expect(fs.statSync(path.dirname(p)).mode & 0o777).toBe(0o700);
    // La identidad del agente vive un nivel más arriba y sigue intacta
    // (aquí ni siquiera existe, que es lo correcto: no se ha tocado).
    expect(fs.existsSync(path.join(raiz, "certs", "client.key.pem"))).toBe(false);
  });

  it("no deja residuo: la config y el .csr temporales se van", () => {
    const dir = lin.cdpKeyDir();
    const sobra = fs.readdirSync(dir).filter((f) => f.endsWith(".cnf") || f.endsWith(".csr"));
    expect(sobra).toEqual([]);
  });

  it("9.d — la clave sin certificado sale como huérfana, con su edad", async () => {
    const r: any = await lin.handleCdpKeyList(req("cdp.key.list", {}));
    expect(r.ok).toBe(true);
    const k = r.result.keys.find((x: any) => x.keyId === "web01");
    expect(k).toBeTruthy();
    expect(k.orphan).toBe(true);
    expect(k.subject).toBe("CN=web01.corp,O=Acme,OU=IT");
    // Lo que convierte la huérfana en accionable: de qué solicitud salió.
    expect(k.requestId).toBe("req-abc");
    expect(k.ageDays).toBe(0);
  });

  it("deja de ser huérfana cuando el certificado llega", async () => {
    lin.markCertInstalled("web01");
    const r: any = await lin.handleCdpKeyList(req("cdp.key.list", {}));
    expect(r.result.keys.find((x: any) => x.keyId === "web01").orphan).toBe(false);
  });

  it("rechaza un subject con atributo desconocido en vez de emitirlo sin él", async () => {
    // ⚠️ Sin esta validación openssl NO falla: avisa y DESCARTA el
    // atributo —«Subject Attribute ZZ has no known NID, skipped»— y
    // emite el CSR sin él. Medido en LibreSSL 3.3.6 y OpenSSL 3.6.3.
    // O sea: el llamante pide un sujeto y la CA firma otro.
    const r: any = await lin.handleCdpCsrGenerate(
      req("cdp.csr.generate", { keyId: "raro01", subject: "CN=x,ZZ=no-existe" })
    );
    expect(r.ok).toBe(false);
    expect(r.error.message).toMatch(/ZZ/);
    expect(fs.existsSync(lin.cdpKeyPath("raro01"))).toBe(false);
  });

  it("destruir verifica el resultado y limpia el registro", async () => {
    const r: any = await lin.handleCdpKeyDestroy(req("cdp.key.destroy", { keyId: "web01" }));
    expect(r.ok).toBe(true);
    expect(r.result.destroyed).toBe(1);
    expect(fs.existsSync(lin.cdpKeyPath("web01"))).toBe(false);

    const lista: any = await lin.handleCdpKeyList(req("cdp.key.list", {}));
    expect(lista.result.keys).toEqual([]);
  });

  it("un keyId que escapa se rechaza ANTES de tocar nada", async () => {
    for (const malo of ["../client", "Web01", "a b", ""]) {
      const r: any = await lin.handleCdpCsrGenerate(
        req("cdp.csr.generate", { keyId: malo, subject: "CN=x" })
      );
      expect(r.ok).toBe(false);
      expect(r.error.code).toBe("bad_request");
    }
    // Y la clave del agente sigue sin existir: no se creó ni se tocó.
    expect(fs.existsSync(path.join(raiz, "certs", "client.key.pem"))).toBe(false);
  });

  it("rechaza eku y algoritmo no soportados en vez de emitir algo distinto", async () => {
    const eku: any = await lin.handleCdpCsrGenerate(
      req("cdp.csr.generate", { keyId: "x1", subject: "CN=x", eku: "codeSigning" })
    );
    expect(eku.ok).toBe(false);
    const alg: any = await lin.handleCdpCsrGenerate(
      req("cdp.csr.generate", { keyId: "x2", subject: "CN=x", keyAlgorithm: "ECDSA_P256" })
    );
    expect(alg.ok).toBe(false);
    // Ninguno de los dos llegó a crear clave.
    expect(fs.existsSync(lin.cdpKeyPath("x1"))).toBe(false);
    expect(fs.existsSync(lin.cdpKeyPath("x2"))).toBe(false);
  });
});

// ── 9.c: la destrucción en una salida terminal REAL ────────────────
//
// Se aísla en su propio bloque porque necesita otro `OPENSSL_BIN`, y esa
// ruta es un `const` de módulo.

describe("⭐ 9.c — un fallo de FIRMA no deja material de clave huérfano", () => {
  let lin: any;
  let raiz: string;

  beforeAll(async () => {
    raiz = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-9c-"));
    process.env.TRACENIUM_PRIVSVC_CONFIG_DIR = raiz;

    // ⚠️ Un openssl que genera bien y FALLA AL FIRMAR. El matiz es todo
    // el test: un `/usr/bin/false` a secas hace fallar ya el `genpkey`,
    // la clave no llega a existir, y entonces esto pasaría en verde sin
    // probar nada de la destrucción. (Se escribió así primero.)
    //
    // «Fallo de firma» es la primera de las salidas terminales que
    // enumera la decisión 9.c, y este envoltorio la reproduce exacta:
    // cuando el handler llama a `req`, la clave YA está en disco.
    const falso = path.join(raiz, "openssl-que-no-firma");
    fs.writeFileSync(
      falso,
      `#!/bin/sh\n[ "$1" = "req" ] && { echo "boom" >&2; exit 1; }\nexec /usr/bin/openssl "$@"\n`,
      { mode: 0o755 }
    );
    process.env.OPENSSL_BIN = falso;
    vi.resetModules();
    lin = await import("../../privsvc/linux/src/cdp-keys");
  });

  afterAll(() => {
    delete process.env.OPENSSL_BIN;
    delete process.env.TRACENIUM_PRIVSVC_CONFIG_DIR;
    try {
      fs.rmSync(raiz, { recursive: true, force: true });
    } catch {}
  });

  it("la clave se destruye en el mismo camino de código que la creó", async () => {
    const r: any = await lin.handleCdpCsrGenerate(
      req("cdp.csr.generate", { keyId: "fallo01", subject: "CN=x" })
    );
    expect(r.ok).toBe(false);

    // Lo que importa: NADA queda atrás. Ni la clave, ni la entrada del
    // registro, ni el .csr a medias. Una clave sin certificado tiene
    // «utilidad cero y responsabilidad no-cero».
    expect(fs.existsSync(lin.cdpKeyPath("fallo01"))).toBe(false);
    const lista: any = await lin.handleCdpKeyList(req("cdp.key.list", {}));
    expect(lista.result.keys).toEqual([]);
    const sobra = fs.readdirSync(lin.cdpKeyDir()).filter((f: string) => f !== "ledger.json");
    expect(sobra).toEqual([]);
  }, 30_000);
});

// ── macOS: clave en el llavero, no extraíble ───────────────────────

const enMac = os.platform() === "darwin";
let haySwift = false;
try {
  execFileSync("/usr/bin/which", ["swiftc"], { stdio: "ignore" });
  haySwift = true;
} catch {
  /* sin swiftc no hay helper */
}

describe.runIf(enMac && haySwift)("cdp.csr.generate — macOS (llavero real)", () => {
  let mac: any;
  let dir: string;
  let kc: string;

  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-mac-"));
    kc = path.join(dir, "prueba.keychain-db");
    const bin = path.join(dir, "tracenium-keystore");
    execFileSync("/usr/bin/swiftc", [
      "-O",
      path.join(__dirname, "../../privsvc/macos/helpers/keystore/main.swift"),
      "-o",
      bin
    ]);
    execFileSync("/usr/bin/security", ["create-keychain", "-p", "test", kc]);
    execFileSync("/usr/bin/security", ["unlock-keychain", "-p", "test", kc]);
    process.env.TRACENIUM_KEYSTORE_BIN = bin;
    process.env.TRACENIUM_PRIVSVC_DATA_DIR = path.join(dir, "data");
    // El llavero temporal en vez del de la máquina. Va antes del import
    // porque `SYSTEM_KEYCHAIN` es un `const` de módulo.
    process.env.TRACENIUM_KEYCHAIN = kc;
    mac = await import("../../privsvc/macos/src/cdp-keys");
  }, 120_000);

  afterAll(() => {
    try {
      execFileSync("/usr/bin/security", ["delete-keychain", kc]);
    } catch {}
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {}
    delete process.env.TRACENIUM_KEYSTORE_BIN;
    delete process.env.TRACENIUM_PRIVSVC_DATA_DIR;
    delete process.env.TRACENIUM_KEYCHAIN;
  });

  it("emite un CSR firmado por una clave que NO sale del llavero", async () => {
    const r: any = await mac.handleCdpCsrGenerate(
      req("cdp.csr.generate", {
        keyId: "web01",
        subject: "CN=web01.corp,O=Acme",
        dnsNames: ["web01.corp"],
        eku: "serverAuth",
        requestId: "req-xyz"
      })
    );
    expect(r.ok).toBe(true);
    expect(r.result.keyStore).toBe("keychain-nonextractable");

    const v = verificaCsr(r.result.csrPem, dir);
    expect(v.status).toBe(0);
    expect(v.salida).toMatch(/verify OK/i);
    expect(v.texto).toMatch(/CN\s*=\s*web01\.corp/);
    expect(v.texto).toContain("TLS Web Server Authentication");
    expect(v.texto).toContain("DNS:web01.corp");
  }, 60_000);

  it("⭐ la clave emitida tampoco es extraíble — la propiedad de 9.b", () => {
    const out = path.join(dir, "robada.p12");
    const r = spawnSync(
      "/usr/bin/security",
      ["export", "-k", kc, "-t", "privKeys", "-f", "pkcs12", "-P", "xyz", "-o", out],
      { encoding: "utf8" }
    );
    expect(r.status).not.toBe(0);
    // El MOTIVO, no solo el fallo: con clave extraíble `security` aborta
    // por el ACL con «User canceled», que no es lo mismo.
    expect(`${r.stdout}${r.stderr}`).toMatch(/cannot be retrieved/i);
  });

  it("9.d — sale como huérfana con su solicitud, y destruir la quita", async () => {
    const lista: any = await mac.handleCdpKeyList(req("cdp.key.list", {}));
    const k = lista.result.keys.find((x: any) => x.keyId === "web01");
    expect(k?.orphan).toBe(true);
    expect(k?.requestId).toBe("req-xyz");

    const d: any = await mac.handleCdpKeyDestroy(req("cdp.key.destroy", { keyId: "web01" }));
    expect(d.ok).toBe(true);
    // Los DOS ítems del par RSA.
    expect(d.result.destroyed).toBe(2);

    const tras: any = await mac.handleCdpKeyList(req("cdp.key.list", {}));
    expect(tras.result.keys).toEqual([]);
  }, 30_000);
});
