// test/privsvc/macos-keystore.test.ts
//
// ADR-0011 decisión 9.b — el almacén de claves no extraíbles de macOS.
//
// Dos bloques con propósitos distintos, y conviene no confundirlos:
//
//   · El primero prueba el ENVOLTORIO con un helper falso. Ese falso es
//     un script real invocado por execFile, no un `vi.mock`: la forma
//     que importa aquí es «un proceso que escribe una línea y sale con
//     un código», y un mock de la función no la reproduce.
//
//   · El segundo COMPILA el helper de verdad y comprueba la propiedad
//     sobre un llavero real. Es el único que puede afirmar que la clave
//     no sale, y por eso existe: la vía barata (`security import -x`)
//     pasaba todos los tests de forma que se imaginen sin tocar el
//     Security framework, y no hace nada.

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync, spawnSync } from "child_process";

import {
  createKey,
  keyInfo,
  generateCsr,
  deleteKey,
  keystoreAvailable,
  SYSTEM_KEYCHAIN
} from "../../privsvc/macos/src/keystore";

// ── Bloque 1: el envoltorio ────────────────────────────────────────

describe("keystore: envoltorio del helper", () => {
  let dir: string;
  let bin: string;

  /** Escribe un helper falso que registra sus argumentos y responde. */
  function fakeHelper(body: string) {
    fs.writeFileSync(
      bin,
      `#!/bin/sh\nprintf '%s\\n' "$@" > "${dir}/args.txt"\n${body}\n`,
      { mode: 0o755 }
    );
    process.env.TRACENIUM_KEYSTORE_BIN = bin;
  }

  const args = () =>
    fs.readFileSync(path.join(dir, "args.txt"), "utf8").trim().split("\n");

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "ks-wrap-"));
    bin = path.join(dir, "helper");
  });

  afterAll(() => {
    delete process.env.TRACENIUM_KEYSTORE_BIN;
  });

  it("sin helper instalado no revienta: devuelve helper_missing", async () => {
    process.env.TRACENIUM_KEYSTORE_BIN = path.join(dir, "no-existe");
    expect(keystoreAvailable()).toBe(false);
    const r = await createKey("x");
    expect(r.ok).toBe(false);
    expect(r.code).toBe("helper_missing");
  });

  it("un ok:false llega ENTERO aunque el helper salga con código != 0", async () => {
    // La regresión concreta que se quiere impedir: quedarse con el
    // mensaje genérico de execFile pierde el `code` estable, que es lo
    // único sobre lo que el llamante puede ramificar. Ya pasó una vez en
    // el guard de Linux.
    fakeHelper(`echo '{"ok":false,"code":"key_not_found","message":"no hay clave"}'\nexit 1`);
    const r = await generateCsr("etq", "CN=a");
    expect(r.ok).toBe(false);
    expect(r.code).toBe("key_not_found");
    expect(r.message).toBe("no hay clave");
  });

  it("una salida que no es JSON se reporta como tal, no como éxito", async () => {
    fakeHelper(`echo 'dyld: Library not loaded'\nexit 1`);
    const r = await keyInfo("etq");
    expect(r.ok).toBe(false);
    expect(r.code).toBe("helper_bad_output");
    expect(r.message).toContain("dyld");
  });

  it("apunta al llavero de la máquina si no se dice otra cosa", async () => {
    fakeHelper(`echo '{"ok":true}'`);
    await createKey("etq");
    expect(args()).toEqual(["create", "--label", "etq", "--keychain", SYSTEM_KEYCHAIN]);
  });

  it("solo pasa las opciones que se le dan", async () => {
    fakeHelper(`echo '{"ok":true}'`);
    await generateCsr("etq", "CN=a,O=b", { uri: "tracenium://x", eku: "serverAuth" });
    const a = args();
    expect(a).toContain("--uri");
    expect(a).toContain("serverAuth");
    // Sin --dns: una extensión SAN con un dNSName vacío sería un
    // certificado distinto del pedido.
    expect(a).not.toContain("--dns");
  });

  it("delete devuelve el recuento del helper", async () => {
    fakeHelper(`echo '{"ok":true,"deleted":2}'`);
    const r = await deleteKey("etq");
    expect(r.ok).toBe(true);
    expect(r.deleted).toBe(2);
  });
});

// ── Bloque 2: la propiedad, contra un llavero real ─────────────────

const enMac = os.platform() === "darwin";
let haySwift = false;
try {
  execFileSync("/usr/bin/which", ["swiftc"], { stdio: "ignore" });
  haySwift = true;
} catch {
  /* sin swiftc no se puede compilar el helper */
}

describe.runIf(enMac && haySwift)("keystore: la clave NO sale (llavero real)", () => {
  let dir: string;
  let kc: string;
  const etiqueta = "prueba-no-extraible";

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "ks-real-"));
    kc = path.join(dir, "prueba.keychain-db");
    const bin = path.join(dir, "tracenium-keystore");
    // Solo la arquitectura del anfitrión: el universal lo hace el
    // empaquetado, y aquí duplicar la compilación solo cuesta tiempo.
    execFileSync("/usr/bin/swiftc", [
      "-O",
      path.join(__dirname, "../../privsvc/macos/helpers/keystore/main.swift"),
      "-o",
      bin
    ]);
    execFileSync("/usr/bin/security", ["create-keychain", "-p", "test", kc]);
    execFileSync("/usr/bin/security", ["unlock-keychain", "-p", "test", kc]);
    process.env.TRACENIUM_KEYSTORE_BIN = bin;
  }, 120_000);

  afterAll(() => {
    try {
      execFileSync("/usr/bin/security", ["delete-keychain", kc]);
    } catch {}
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {}
    delete process.env.TRACENIUM_KEYSTORE_BIN;
  });

  it("crea la clave, y crear otra vez no la regenera", async () => {
    const a = await createKey(etiqueta, { keychain: kc });
    expect(a.ok).toBe(true);
    expect(a.created).toBe(true);

    // Idempotencia: regenerar en silencio invalidaría el certificado que
    // ya estuviera usando esa clave.
    const b = await createKey(etiqueta, { keychain: kc });
    expect(b.ok).toBe(true);
    expect(b.created).toBe(false);
  });

  it("la API de extracción la deniega", async () => {
    const r = await keyInfo(etiqueta, kc);
    expect(r.exists).toBe(true);
    expect(r.extractable).toBe(false);
  });

  it("⭐ `security export` tampoco la saca, y falla POR NO SER EXTRAÍBLE", () => {
    // ESTE es el test que justifica el binario nativo. El camino barato
    // —`security import -x`, que el propio `usage` anuncia como «private
    // keys are non-extractable after being imported»— pasa por aquí
    // devolviendo la clave: se midió el 2026-08-31 que el módulo RSA que
    // sale es idéntico al que entró, con `-x`, con `-x -A` y sin nada.
    //
    // ⚠️ Y se comprueba el MOTIVO, no solo que falle. Escrito como «que
    // no salga la clave», este test pasaba también con una clave
    // extraíble — porque `security` choca antes con el ACL y aborta con
    // «User canceled the operation», que en un proceso sin sesión
    // gráfica es lo que devuelve un diálogo que nadie contesta. Dos
    // defensas distintas, y solo una es la que este fichero afirma
    // tener; el ACL además lo puede cambiar root, y la extraibilidad no.
    //
    //   no extraíble  -> "The contents of this item cannot be retrieved"
    //   extraíble+ACL -> "User canceled the operation"
    const out = path.join(dir, "robada.p12");
    const r = spawnSync(
      "/usr/bin/security",
      ["export", "-k", kc, "-t", "privKeys", "-f", "pkcs12", "-P", "xyz", "-o", out],
      { encoding: "utf8" }
    );

    expect(r.status).not.toBe(0);
    expect(fs.existsSync(out) && fs.statSync(out).size > 0).toBe(false);
    expect(`${r.stdout}${r.stderr}`).toMatch(/cannot be retrieved/i);
  });

  it("firma un CSR que OpenSSL da por bueno", async () => {
    const r = await generateCsr(etiqueta, "CN=tracenium-agent-abc,O=Tracenium,OU=T111", {
      dns: "mac-prueba.local",
      uri: "tracenium://tenant/T111/device/abc",
      keychain: kc
    });
    expect(r.ok).toBe(true);
    expect(r.csrPem).toContain("BEGIN CERTIFICATE REQUEST");

    // Se delega en OpenSSL en vez de comprobar el PEM a ojo: el PKCS#10
    // se codifica a mano en el helper (la clave no sale, así que
    // `openssl req` no puede firmarla), y un DER mal armado es
    // exactamente el fallo que un `toContain` no vería.
    const req = path.join(dir, "req.pem");
    fs.writeFileSync(req, r.csrPem);

    // ⚠️ `spawnSync` y no `execFileSync`: openssl escribe el veredicto de
    // -verify en STDERR, y execFileSync solo devuelve stdout. Con
    // execFileSync la comprobación se apoyaba en una cadena vacía.
    const verif = spawnSync("/usr/bin/openssl", ["req", "-in", req, "-noout", "-verify"], {
      encoding: "utf8"
    });
    expect(verif.status).toBe(0);
    expect(`${verif.stdout}${verif.stderr}`).toMatch(/verify OK/i);

    const texto = execFileSync("/usr/bin/openssl", ["req", "-in", req, "-noout", "-text"], {
      encoding: "utf8"
    });
    expect(texto).toContain("CN=tracenium-agent-abc");
    expect(texto).toContain("O=Tracenium");
    expect(texto).toContain("Digital Signature");
    expect(texto).toContain("TLS Web Client Authentication");
    expect(texto).toContain("DNS:mac-prueba.local");
    expect(texto).toContain("URI:tracenium://tenant/T111/device/abc");
  }, 30_000);

  it("borra los DOS ítems del par, y lo verifica", async () => {
    // Un par RSA deja dos ítems con la misma etiqueta. Una sola llamada
    // a SecItemDelete devuelve éxito habiéndose llevado uno —midido— y
    // dejando la clave privada dentro. `deleted: 2` es lo que distingue
    // la destrucción real del falso verde.
    const r = await deleteKey(etiqueta, kc);
    expect(r.ok).toBe(true);
    expect(r.deleted).toBe(2);

    const tras = await keyInfo(etiqueta, kc);
    expect(tras.exists).toBe(false);
  });
});
