// test/privsvc/hybrid-csr-wiring.test.ts
//
// ADR-0015 punto 7 — EL CABLEADO, no las piezas.
//
// ⚠️ POR QUÉ ESTE FICHERO EXISTE APARTE DE `hybrid-csr.test.ts`.
//
// Aquél prueba `buildCsr` y `loadOrCreateAltKey` llamándolos
// directamente. Éste llama a `handleGenerateCsr`, que es lo que el
// enrolamiento invoca de verdad por el IPC. Las piezas pueden estar
// perfectas y el cableado mal —un `altKeyAlgorithm` que se lee y no se
// usa, una clave que se genera y no se pasa— y la otra suite seguiría
// entera en verde.
//
// Es el modo de fallo con nombre propio en este producto: «las 3 listas
// de un job», donde un método existía, estaba probado, y no lo invocaba
// nadie. Aquí las listas son tres otra vez —agent-core, el router del
// privsvc y el handler— y esta suite cubre la tercera.
//
// Se prueban LAS DOS PLATAFORMAS en el mismo fichero a propósito.
// `privsvc/macos` y `privsvc/linux` son árboles duplicados: la forma de
// que diverjan es que cada uno tenga su suite y una se olvide.

import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

const raiz = fs.mkdtempSync(path.join(os.tmpdir(), "privsvc-wiring-"));

// Las rutas se fijan ANTES de importar: los módulos de `paths` leen el
// entorno al cargarse.
process.env.TRACENIUM_PRIVSVC_DATA_DIR = path.join(raiz, "data");
process.env.TRACENIUM_PRIVSVC_CONFIG_DIR = path.join(raiz, "etc");
process.env.TRACENIUM_PRIVSVC_LOG_DIR = path.join(raiz, "log");
process.env.TRACENIUM_PRIVSVC_SOCKET_PATH = path.join(raiz, "privsvc.sock");

const OPENSSL = process.env.OPENSSL_BIN || "openssl";
const TENANT = "1";
const DEVICE = "11111111-2222-3333-4444-555555555555";

type Handler = (req: any) => Promise<any>;

const plataformas: Array<{ nombre: string; cargar: () => Promise<Handler>; certDir: () => string }> = [
  {
    nombre: "macOS",
    cargar: async () => (await import("../../privsvc/macos/src/crypto-store")).handleGenerateCsr,
    certDir: () => path.join(raiz, "data", "certs")
  },
  {
    nombre: "Linux",
    cargar: async () => (await import("../../privsvc/linux/src/crypto-store")).handleGenerateCsr,
    certDir: () => path.join(raiz, "etc", "certs")
  }
];

function peticion(extra: Record<string, unknown> = {}) {
  return {
    v: 1,
    id: "t1",
    method: "crypto.csr.generate",
    params: { tenantId: TENANT, deviceId: DEVICE, reuseExistingKey: false, ...extra },
    meta: { tenantId: TENANT, deviceId: DEVICE }
  };
}

afterAll(() => {
  try { fs.rmSync(raiz, { recursive: true, force: true }); } catch {}
});

for (const plat of plataformas) {
  describe(`handleGenerateCsr — ${plat.nombre}`, () => {
    let handle: Handler;

    beforeEach(async () => {
      handle = await plat.cargar();
      try { fs.rmSync(plat.certDir(), { recursive: true, force: true }); } catch {}
    });

    it("sin altKeyAlgorithm emite CLÁSICO, igual que antes", async () => {
      // Lo que hace desplegable este agente antes de que exista una
      // Issuing híbrida: un agente nuevo contra el backend de hoy enrola
      // exactamente igual que el viejo.
      const r = await handle(peticion());
      expect(r.ok).toBe(true);
      expect(r.result.altKeyAlgorithm).toBeNull();
      expect(r.result.csrPem).toContain("BEGIN CERTIFICATE REQUEST");
      expect(fs.existsSync(path.join(plat.certDir(), "client.alt-key.pem"))).toBe(false);
    });

    it("⚠️ con altKeyAlgorithm ML_DSA_65 el CSR sale HÍBRIDO de verdad", async () => {
      // La comprobación del cableado. Que el handler ACEPTE el parámetro
      // no basta: hay que ver la extensión en el CSR que devuelve.
      const r = await handle(peticion({ altKeyAlgorithm: "ML_DSA_65" }));
      expect(r.ok).toBe(true);
      expect(r.result.altKeyAlgorithm).toBe("ML_DSA_65");

      const p = path.join(raiz, `${plat.nombre}.csr.pem`);
      fs.writeFileSync(p, r.result.csrPem);
      const texto = execFileSync(OPENSSL, ["req", "-in", p, "-text", "-noout"], { encoding: "utf8" });
      expect(texto).toContain("X509v3 Subject Alternative Public Key Info");
      expect(texto).toContain("X509v3 Alternative Signature Value");
    });

    it("⚠️ y la clave alternativa queda en disco con 0600", async () => {
      // El permiso es la única protección de este fichero: no se cifra,
      // por las razones que explica alt-key.ts. Un 0644 lo dejaría
      // legible por cualquier proceso del equipo.
      await handle(peticion({ altKeyAlgorithm: "ML_DSA_65" }));
      const alt = path.join(plat.certDir(), "client.alt-key.pem");
      expect(fs.existsSync(alt)).toBe(true);
      expect(fs.statSync(alt).mode & 0o777).toBe(0o600);
    });

    it("⚠️ EC_P384 sale con la curva POR NOMBRE, no con parámetros explícitos", async () => {
      // ⚠️ ESTO LO DESTAPÓ EL TEST, y es la razón de que la clave EC la
      // genere Node y no `openssl`.
      //
      // El `openssl` del privsvc de macOS es /usr/bin/openssl, o sea
      // LibreSSL 3.3.6, y su `genpkey -algorithm EC -pkeyopt
      // ec_paramgen_curve:P-384` escribe los PARÁMETROS EXPLÍCITOS de la
      // curva —primo, cofactor, semilla— en vez del OID. Es DER legal, y
      // por eso no falla nada al generarla; lo que pasa es que muchos
      // verificadores rechazan esas claves, y la SPKI engorda de 120 a
      // 464 bytes en un certificado al que ya le estamos añadiendo 5,3 KB.
      //
      // Se comprueba por el TAMAÑO además de por el texto: el número
      // separa las dos codificaciones sin depender de cómo las rotule la
      // versión de openssl que corra el test.
      const r = await handle(peticion({ keyAlgorithm: "EC_P384" }));
      expect(r.ok).toBe(true);
      expect(r.result.keyAlgorithm).toBe("EC_P384");

      const keyPath = path.join(plat.certDir(), "client.key.pem");
      const texto = execFileSync(OPENSSL, ["pkey", "-in", keyPath, "-noout", "-text"], {
        encoding: "utf8"
      });
      expect(texto).toMatch(/P-384|secp384r1/);
      // Con parámetros explícitos aparecen estos campos y el OID no.
      expect(texto).not.toMatch(/Cofactor:/);

      const spki = execFileSync(OPENSSL, ["pkey", "-in", keyPath, "-pubout", "-outform", "der"]);
      expect(spki.length).toBe(120); // 464 si fueran explícitos
    });

    it("⚠️ pasar de RSA a EC_P384 REGENERA la clave aunque se pida reutilizar", async () => {
      // El fallo latente del contrato viejo. `reuseExistingKey` sólo
      // miraba «¿hay una RSA de 2048?», así que un equipo ya enrolado
      // habría reutilizado su RSA para siempre y nunca habría llegado a
      // P-384: la migración se queda en el papel y nada falla.
      await handle(peticion({ keyAlgorithm: "RSA_2048" }));
      const r = await handle(peticion({ keyAlgorithm: "EC_P384", reuseExistingKey: true }));
      expect(r.ok).toBe(true);
      const texto = execFileSync(
        OPENSSL,
        ["pkey", "-in", path.join(plat.certDir(), "client.key.pem"), "-noout", "-text"],
        { encoding: "utf8" }
      );
      expect(texto).toMatch(/P-384|secp384r1/);
    });

    it("un algoritmo desconocido falla RUIDOSAMENTE, no en silencio", async () => {
      // Producir otro algoritmo sin decirlo es lo que rompió el
      // enrolamiento de Windows en su día.
      const a = await handle(peticion({ keyAlgorithm: "RSA_4096" }));
      expect(a.ok).toBe(false);
      const b = await handle(peticion({ altKeyAlgorithm: "ML_DSA_87" }));
      expect(b.ok).toBe(false);
    });

    it("⚠️ el CSR híbrido sigue verificando con openssl req -verify", async () => {
      // Un verificador que no sepa nada de catalyst tiene que seguir
      // aceptándolo. Si esto fallara, el formato híbrido rompería el
      // enrolamiento en vez de ampliarlo.
      const r = await handle(peticion({ keyAlgorithm: "EC_P384", altKeyAlgorithm: "ML_DSA_65" }));
      const p = path.join(raiz, `${plat.nombre}-verify.csr.pem`);
      fs.writeFileSync(p, r.result.csrPem);
      const out = execFileSync(OPENSSL, ["req", "-in", p, "-verify", "-noout"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      });
      expect(`${out}`).toMatch(/verify OK|self-signature verify OK/i);
    });

    it("reutilizar conserva la MISMA clave alternativa", async () => {
      // Cambiarla en cada renovación obligaría a reemitir por un motivo
      // que no existe, y dejaría certificados vivos nombrando una clave
      // que el equipo ya no tiene.
      await handle(peticion({ altKeyAlgorithm: "ML_DSA_65" }));
      const antes = fs.readFileSync(path.join(plat.certDir(), "client.alt-key.pem"), "utf8");
      await handle(peticion({ altKeyAlgorithm: "ML_DSA_65", reuseExistingKey: true }));
      const despues = fs.readFileSync(path.join(plat.certDir(), "client.alt-key.pem"), "utf8");
      expect(despues).toBe(antes);
    });
  });
}
