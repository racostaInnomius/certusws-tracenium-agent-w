// test/privsvc/gateway-key.test.ts
//
// ADR-0013 — la creación real del material del gateway, ejecutando openssl.
//
// No es un test de humo. Hay dos afirmaciones del diseño que solo se sostienen
// si se ejecutan, y las dos se rompen en silencio:
//
//   `-addext` — esta máquina trae LibreSSL, que es el extremo arriesgado del
//   rango que se encuentra en campo. Si no lo soportara, la creación fallaría
//   en macOS y no en Linux, y nadie lo vería hasta tener un gateway macOS.
//
//   La huella — es el AAD del GCM. Una huella calculada de forma distinta a
//   como la calcula el navegador no da un error de huella: da un fallo de
//   autenticación del sobre, que apunta a cualquier otro sitio.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

let mod: typeof import("../../privsvc/linux/src/gateway-key");
let tmpDir: string;

beforeAll(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gwkey-"));
  // Las rutas se resuelven al importar el módulo, así que el entorno tiene que
  // estar puesto ANTES del import dinámico. Van TODAS: `ensurePrivSvcDirs`
  // crea también /run y /var/lib, y en esta máquina eso es un ENOENT.
  process.env.TRACENIUM_PRIVSVC_CONFIG_DIR = path.join(tmpDir, "etc");
  process.env.TRACENIUM_PRIVSVC_DATA_DIR = path.join(tmpDir, "lib");
  process.env.TRACENIUM_PRIVSVC_LOG_DIR = path.join(tmpDir, "log");
  process.env.TRACENIUM_PRIVSVC_SOCKET_PATH = path.join(tmpDir, "run", "privsvc.sock");
  mod = await import("../../privsvc/linux/src/gateway-key");
});

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  for (const k of [
    "TRACENIUM_PRIVSVC_CONFIG_DIR",
    "TRACENIUM_PRIVSVC_DATA_DIR",
    "TRACENIUM_PRIVSVC_LOG_DIR",
    "TRACENIUM_PRIVSVC_SOCKET_PATH",
  ]) delete process.env[k];
});

const DEVICE = "eb40471c-763e-4151-9285-c97ece893179";

describe("crear el material", () => {
  it("produce un certificado que se puede parsear y una clave 0600", async () => {
    const material = await mod.ensureGatewayKey(DEVICE);

    const cert = new crypto.X509Certificate(material.certPem);
    expect(cert.subject).toContain("Tracenium Gateway Credential Key");
    expect(cert.subject).toContain(DEVICE);

    const paths = mod.gatewayKeyPaths();
    // En un daemon de sistema el modo del fichero ES la frontera.
    expect(fs.statSync(paths.key).mode & 0o777).toBe(0o600);
  });

  it("⭐ la clave descifra lo que su propia pública cifra, con OAEP-SHA256", async () => {
    // El fallo que originó todo ADR-0013 fue exactamente esto fallando en
    // Windows: la clave de enrolamiento no podía descifrar. Si esta tampoco
    // pudiera, el arreglo no arreglaría nada.
    const material = await mod.ensureGatewayKey(DEVICE);
    const cert = new crypto.X509Certificate(material.certPem);
    const keyPem = mod.readGatewayPrivateKeyPem()!;

    const secreto = Buffer.from("una contraseña de vSphere");
    const sellado = crypto.publicEncrypt(
      { key: cert.publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      secreto
    );
    const abierto = crypto.privateDecrypt(
      { key: crypto.createPrivateKey(keyPem), padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      sellado
    );

    expect(abierto.toString()).toBe(secreto.toString());
  });

  it("la huella es la del DER, en minúsculas y sin separadores", async () => {
    // La forma exacta que el navegador usa como AAD. Calculada aquí de forma
    // independiente, no llamando a la misma función que se está probando.
    const material = await mod.ensureGatewayKey(DEVICE);
    const der = new crypto.X509Certificate(material.certPem).raw;
    const esperada = crypto.createHash("sha256").update(der).digest("hex");

    expect(material.fingerprintSha256).toBe(esperada);
    expect(material.fingerprintSha256).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("idempotencia", () => {
  it("⭐ devuelve el mismo material en la segunda llamada", async () => {
    // La sincronización de políticas llama a esto cada vez que ve el bloque.
    // Si generase material nuevo cada vez, invalidaría la credencial ya
    // sellada en cada sincronización — el gateway dejaría de funcionar sin
    // que nadie hubiese tocado nada.
    const primera = await mod.ensureGatewayKey(DEVICE);
    const segunda = await mod.ensureGatewayKey(DEVICE);

    expect(segunda.fingerprintSha256).toBe(primera.fingerprintSha256);
  });

  it("readGatewayKey coincide con lo que devolvió ensure", async () => {
    const material = await mod.ensureGatewayKey(DEVICE);
    expect(mod.readGatewayKey()?.fingerprintSha256).toBe(material.fingerprintSha256);
  });
});

describe("destruir", () => {
  it("se lleva las dos mitades y deja readGatewayKey en null", async () => {
    await mod.ensureGatewayKey(DEVICE);
    mod.destroyGatewayKey();

    const paths = mod.gatewayKeyPaths();
    expect(fs.existsSync(paths.key)).toBe(false);
    expect(fs.existsSync(paths.cert)).toBe(false);
    expect(mod.readGatewayKey()).toBeNull();
  });

  it("destruir dos veces no es un error", () => {
    mod.destroyGatewayKey();
    expect(() => mod.destroyGatewayKey()).not.toThrow();
  });

  it("media pareja no cuenta como material", async () => {
    // Un intento a medias deja una mitad suelta. Publicar un certificado cuya
    // clave no está sería prometer algo que no se cumple.
    await mod.ensureGatewayKey(DEVICE);
    fs.rmSync(mod.gatewayKeyPaths().key, { force: true });

    expect(mod.readGatewayKey()).toBeNull();
    mod.destroyGatewayKey();
  });
});

describe("el deviceId entra en un DN", () => {
  it("rechaza lo que abriría un componente nuevo del sujeto", () => {
    // Llega del llamante. Un sujeto silenciosamente distinto del pedido es
    // peor que un error.
    for (const malo of ["a/b", "a\\b", "a\nb", "", "   "]) {
      expect(() => mod.opensslSubject(malo)).toThrow();
    }
  });

  it("acepta un uuid normal", () => {
    expect(mod.opensslSubject(DEVICE)).toBe(
      `/CN=Tracenium Gateway Credential Key/OU=${DEVICE}`
    );
  });
});
