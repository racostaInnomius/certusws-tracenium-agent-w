// test/privsvc/hybrid-renewal.test.ts
//
// ADR-0015 — LA RENOVACIÓN, que es la vía por la que rota la flota.
//
// ⚠️ POR QUÉ ESTE FICHERO EXISTE APARTE DE `hybrid-csr-wiring.test.ts`.
//
// Aquél cubre `handleGenerateCsr`, o sea el ENROLAMIENTO. Éste cubre
// `handleRenewCert`, que es otro camino entero — y el que de verdad usa
// la rotación de ADR-0015, porque un equipo ya enrolado no vuelve a
// enrolarse: se renueva.
//
// El bloque 2 migró el primero a `buildCsr` y dejó el segundo con su
// `openssl genpkey RSA` + `openssl req -config`. Resultado: el CSR
// híbrido llegaba al enrolamiento y NUNCA a la renovación, así que un
// equipo podía enrolar híbrido y volverse clásico en su primera
// renovación, en silencio y para siempre. Se descubrió en producción el
// 2026-09-08, en el primer anillo del corte a la Issuing G2.
//
// Es «las 3 listas de un job» otra vez: dos caminos hacia el mismo
// contrato y sólo uno migrado. Por eso el test no mira `buildCsr` —eso
// ya está probado— sino EL CSR QUE SALE POR EL CABLE.
//
// ⚠️ Ese cable ya no es HTTPS. La renovación se movió a `rpc RenewCert`
// sobre el canal gRPC que el equipo ya tiene autenticado, porque la ruta
// REST llevaba rota para toda la flota desde el 2026-09-01: el ingress
// dejó de reenviar el certificado de cliente y respondía 401. Aquí eso
// simplifica el arnés — el transporte se INYECTA, así que capturar el
// CSR es una función de una línea en vez de un servidor de verdad.

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { execFileSync } from "child_process";
import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import { loadOrCreateAltKey } from "../../privsvc/shared/alt-key";

const raiz = fs.mkdtempSync(path.join(os.tmpdir(), "renew-hibrido-"));

process.env.TRACENIUM_PRIVSVC_DATA_DIR = path.join(raiz, "data");
process.env.TRACENIUM_PRIVSVC_CONFIG_DIR = path.join(raiz, "etc");
process.env.TRACENIUM_PRIVSVC_LOG_DIR = path.join(raiz, "log");
process.env.TRACENIUM_PRIVSVC_SOCKET_PATH = path.join(raiz, "privsvc.sock");

const OPENSSL = process.env.OPENSSL_BIN || "openssl";
const TENANT = "1";
const DEVICE = "11111111-2222-3333-4444-555555555555";

const plataformas = [
  {
    nombre: "macOS",
    cargar: async () => await import("../../privsvc/macos/src/crypto-store"),
    certDir: () => path.join(raiz, "data", "certs")
  },
  {
    nombre: "Linux",
    cargar: async () => await import("../../privsvc/linux/src/crypto-store"),
    certDir: () => path.join(raiz, "etc", "certs")
  }
];

/** Una CA de juguete: sólo se usa como bundle de respuesta. */
let ca: { certPem: string; keyPath: string; certPath: string };

beforeAll(() => {
  const caKey = path.join(raiz, "ca.key");
  const caCrt = path.join(raiz, "ca.crt");
  execFileSync(OPENSSL, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", caKey]);
  execFileSync(OPENSSL, [
    "req", "-x509", "-new", "-key", caKey, "-days", "2", "-subj", "/CN=CA de prueba",
    "-addext", "basicConstraints=critical,CA:TRUE", "-out", caCrt
  ]);
  ca = { certPem: fs.readFileSync(caCrt, "utf8"), keyPath: caKey, certPath: caCrt };
});

afterAll(() => {
  try { fs.rmSync(raiz, { recursive: true, force: true }); } catch {}
});

/** Una hoja cualquiera, autofirmada. Sirve como certificado YA INSTALADO:
 *  de él sólo se lee la forma, nunca se valida. */
function hojaDeMentira(): string {
  const k = path.join(raiz, `hoja-${Math.random().toString(36).slice(2)}.key`);
  const c = `${k}.crt`;
  execFileSync(OPENSSL, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", k]);
  execFileSync(OPENSSL, ["req", "-x509", "-new", "-key", k, "-days", "2", "-subj", "/CN=hoja", "-out", c]);
  return fs.readFileSync(c, "utf8");
}

/**
 * Lo que devuelve un servidor SANO: la hoja emitida A PARTIR DEL CSR y
 * firmada por la CA cuyo certificado viaja en el bundle.
 *
 * ⚠️ Antes se devolvía una hoja autofirmada al azar y los tests pasaban,
 * porque el handler no miraba lo que instalaba. Eso hacía que este arnés
 * fuera incapaz de distinguir un servidor sano de uno que devuelve
 * basura — que es exactamente la avería que hubo en campo.
 */
function emitirDesdeCsr(csrPem: string): string {
  const base = path.join(raiz, `emitida-${Math.random().toString(36).slice(2)}`);
  fs.writeFileSync(`${base}.csr`, csrPem);
  execFileSync(OPENSSL, [
    "x509", "-req", "-in", `${base}.csr`,
    "-CA", ca.certPath, "-CAkey", ca.keyPath, "-CAcreateserial",
    "-days", "2", "-out", `${base}.crt`
  ], { stdio: "pipe" });
  return fs.readFileSync(`${base}.crt`, "utf8");
}

/**
 * Una hoja YA CADUCADA, firmada por la CA buena.
 *
 * ⚠️ Va por `openssl ca` y no por `openssl x509 -req -not_before/-not_after`
 * porque esas dos opciones no existen hasta OpenSSL 3.4: en el 3.1 de CI
 * el test reventaría por la herramienta y no por la propiedad. Es la
 * tercera vez que esta diferencia de versión muerde en este repo, así
 * que se comprobó en un contenedor antes de escribirlo, no después.
 */
function emitirCaducada(csrPem: string): string {
  const dir = fs.mkdtempSync(path.join(raiz, "caducada-"));
  const csr = path.join(dir, "req.csr");
  const crt = path.join(dir, "out.crt");
  fs.writeFileSync(csr, csrPem);
  fs.writeFileSync(path.join(dir, "index.txt"), "");
  fs.writeFileSync(path.join(dir, "index.txt.attr"), "unique_subject = no\n");
  fs.writeFileSync(path.join(dir, "serial"), "01\n");
  fs.writeFileSync(
    path.join(dir, "ca.cnf"),
    [
      "[ca]", "default_ca = CA_default", "[CA_default]",
      `dir = ${dir}`,
      "database = $dir/index.txt", "serial = $dir/serial",
      "new_certs_dir = $dir",
      `certificate = ${ca.certPath}`, `private_key = ${ca.keyPath}`,
      "default_md = sha256", "policy = pol", "email_in_dn = no",
      "[pol]", "commonName = optional", "countryName = optional",
      "organizationName = optional", ""
    ].join("\n")
  );
  execFileSync(OPENSSL, [
    "ca", "-batch", "-config", path.join(dir, "ca.cnf"),
    "-in", csr, "-out", crt, "-notext",
    "-startdate", "20200101000000Z", "-enddate", "20200102000000Z"
  ], { stdio: "pipe" });
  return fs.readFileSync(crt, "utf8");
}

/**
 * El transporte, doblado. CAPTURA el CSR que el handler manda, que es el
 * punto entero del fichero: lo que importa no es lo que devuelva, sino
 * lo que sale del equipo.
 *
 * `respuesta` permite sustituir lo que contesta el servidor para poder
 * reproducir un backend averiado sin tocar el handler.
 */
function transporte(
  respuesta?: (csrPem: string) => { clientCertPem: string; caBundlePem: string; status?: string }
) {
  let visto: string | null = null;
  const enviar = async (csrPem: string) => {
    visto = csrPem;
    if (respuesta) return respuesta(csrPem);
    return { clientCertPem: emitirDesdeCsr(csrPem), caBundlePem: ca.certPem, status: "pending" };
  };
  return { enviar, visto: () => visto };
}

/** Los OIDs catalyst, leídos del DER y no de cómo los rotule un openssl. */
function extensionesCatalyst(csrPem: string): number {
  const der = Buffer.from(
    csrPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
    "base64"
  ).toString("hex");
  return ["0603551d48", "0603551d49", "0603551d4a"].filter((o) => der.includes(o)).length;
}

for (const plat of plataformas) {
  describe(`handleRenewCert — ${plat.nombre}`, () => {
    let mod: any;

    beforeEach(async () => {
      mod = await plat.cargar();
      try { fs.rmSync(plat.certDir(), { recursive: true, force: true }); } catch {}
      fs.mkdirSync(plat.certDir(), { recursive: true, mode: 0o700 });
    });

    /** Deja una identidad instalada como la que tendría un equipo real. */
    function identidadInstalada(conAlt: boolean) {
      const dir = plat.certDir();
      const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
      fs.writeFileSync(
        path.join(dir, "client.key.pem"),
        privateKey.export({ format: "pem", type: "pkcs8" }) as string,
        { mode: 0o600 }
      );
      fs.writeFileSync(path.join(dir, "client.crt.pem"), hojaDeMentira(), { mode: 0o600 });
      fs.writeFileSync(path.join(dir, "ca-bundle.crt.pem"), ca.certPem, { mode: 0o644 });
      if (conAlt) {
        // La misma función que usa el enrolamiento: si divergiera, la
        // renovación no encontraría la clave que el equipo sí tiene.
        loadOrCreateAltKey(path.join(dir, "client.key.pem"), { reuse: false });
      }
    }

    async function renovar(t: ReturnType<typeof transporte>, extra: Record<string, unknown> = {}) {
      return mod.handleRenewCert(
        {
          v: 1,
          id: "r1",
          method: "crypto.cert.renew",
          params: { tenantId: TENANT, deviceId: DEVICE, ...extra },
          meta: { tenantId: TENANT, deviceId: DEVICE }
        },
        t.enviar
      );
    }

    it("⚠️ un equipo con clave alternativa se renueva HÍBRIDO, sin que nadie se lo pida", async () => {
      // El corazón del fallo. La rotación no manda `altKeyAlgorithm`: el
      // equipo tiene que conservar su forma solo, o la primera renovación
      // lo degrada a clásico y nadie se entera.
      identidadInstalada(true);
      const s = transporte();
      {
        const r = await renovar(s);
        expect(r.ok, JSON.stringify(r.error || {})).toBe(true);
        expect(r.result.altKeyAlgorithm).toBe("ML_DSA_65");

        const csr = s.visto();
        expect(csr, "el servidor no recibió ningún CSR").toBeTruthy();
        expect(extensionesCatalyst(csr!)).toBe(3);
      }
    });

    it("⚠️ un equipo clásico se renueva CLÁSICO: nada cambia para la flota de hoy", async () => {
      identidadInstalada(false);
      const s = transporte();
      {
        const r = await renovar(s);
        expect(r.ok, JSON.stringify(r.error || {})).toBe(true);
        expect(r.result.altKeyAlgorithm).toBeNull();
        expect(extensionesCatalyst(s.visto()!)).toBe(0);
      }
    });

    it("⚠️ el CSR de la renovación lleva el SAN URI del equipo autenticado", async () => {
      // Es lo que el backend exige en renovación (`requireSanFor`): sin
      // este SAN la emisión se rechaza y la rotación no avanzaría, con el
      // CSR bien formado y todo.
      identidadInstalada(false);
      const s = transporte();
      {
        await renovar(s);
        const f = path.join(raiz, `san-${plat.nombre}.csr`);
        fs.writeFileSync(f, s.visto()!);
        const texto = execFileSync(OPENSSL, ["req", "-in", f, "-text", "-noout"], { encoding: "utf8" });
        expect(texto).toContain(`tracenium://tenant/${TENANT}/device/${DEVICE}`);
      }
    });

    it("un altKeyAlgorithm desconocido falla RUIDOSAMENTE", async () => {
      identidadInstalada(false);
      const s = transporte();
      {
        const r = await renovar(s, { altKeyAlgorithm: "ML_DSA_87" });
        expect(r.ok).toBe(false);
        expect(s.visto(), "no debió llegar a mandar nada").toBeNull();
      }
    });

    // ── El certificado que llega NO se instala a ciegas ────────────────
    //
    // ⚠️ ESTO ES EL LADRILLAZO DE 2026-09-10, y la razón por la que un
    // error de configuración DEL SERVIDOR costó un equipo en campo.
    //
    // El backend emitió una hoja que declaraba «Tracenium Issuing CA G2»
    // firmada con la clave RSA de la G1. El agente la escribió encima de
    // la que funcionaba: el único control era que el texto contuviera
    // «BEGIN CERTIFICATE», y lo contenía. Sólo se enteró en el siguiente
    // handshake, cuando ya no tenía canal por el que pedir ayuda.
    //
    // Lo que estos tests sostienen es la asimetría que hace el fallo
    // recuperable: RECHAZAR una renovación deja al equipo con su
    // certificado viejo y alcanzable —se arregla por red—; ACEPTARLA a
    // ciegas puede dejarlo inalcanzable para siempre.

    /** Lo que quedó instalado tras el intento. */
    function instalado() {
      const f = path.join(plat.certDir(), "client.crt.pem");
      return fs.existsSync(f) ? fs.readFileSync(f, "utf8") : null;
    }

    it("⚠️ una hoja firmada por OTRA CA no llega a instalarse", async () => {
      identidadInstalada(false);
      const previo = instalado();

      // El caso de campo: firmada por una CA que no está en el bundle.
      const otraKey = path.join(raiz, `impostora-${plat.nombre}.key`);
      const otraCrt = `${otraKey}.crt`;
      execFileSync(OPENSSL, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", otraKey]);
      execFileSync(OPENSSL, [
        "req", "-x509", "-new", "-key", otraKey, "-days", "2",
        "-subj", "/CN=CA de prueba", // MISMO sujeto: el DN no distingue
        "-addext", "basicConstraints=critical,CA:TRUE", "-out", otraCrt
      ]);

      const s = transporte((csrPem) => {
        const base = path.join(raiz, `impostor-${Math.random().toString(36).slice(2)}`);
        fs.writeFileSync(`${base}.csr`, csrPem);
        execFileSync(OPENSSL, [
          "x509", "-req", "-in", `${base}.csr`,
          "-CA", otraCrt, "-CAkey", otraKey, "-CAcreateserial",
          "-days", "2", "-out", `${base}.crt`
        ], { stdio: "pipe" });
        return {
          clientCertPem: fs.readFileSync(`${base}.crt`, "utf8"),
          caBundlePem: ca.certPem,
          status: "pending"
        };
      });

      const r = await renovar(s);
      expect(r.ok, "debió rechazarse").toBe(false);
      expect(JSON.stringify(r.error)).toMatch(/no verifica contra ninguna|cert_renew_failed/);
      expect(instalado(), "el certificado que funcionaba se conservó").toBe(previo);
    });

    it("⚠️ una hoja que no corresponde a nuestra clave no llega a instalarse", async () => {
      identidadInstalada(false);
      const previo = instalado();

      // Firmada por la CA buena, pero para OTRA clave: sería el
      // certificado de otro equipo.
      const s = transporte(() => {
        const k = path.join(raiz, `ajena-${Math.random().toString(36).slice(2)}.key`);
        const c = `${k}.csr`;
        execFileSync(OPENSSL, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", k]);
        execFileSync(OPENSSL, ["req", "-new", "-key", k, "-subj", "/CN=ajena", "-out", c]);
        execFileSync(OPENSSL, [
          "x509", "-req", "-in", c, "-CA", ca.certPath, "-CAkey", ca.keyPath,
          "-CAcreateserial", "-days", "2", "-out", `${c}.crt`
        ], { stdio: "pipe" });
        return {
          clientCertPem: fs.readFileSync(`${c}.crt`, "utf8"),
          caBundlePem: ca.certPem,
          status: "pending"
        };
      });

      const r = await renovar(s);
      expect(r.ok, "debió rechazarse").toBe(false);
      expect(instalado(), "el certificado que funcionaba se conservó").toBe(previo);
    });

    it("⚠️ una hoja ya caducada no llega a instalarse", async () => {
      identidadInstalada(false);
      const previo = instalado();

      const s = transporte((csrPem) => ({
        clientCertPem: emitirCaducada(csrPem),
        caBundlePem: ca.certPem,
        status: "pending"
      }));

      const r = await renovar(s);
      expect(r.ok, "debió rechazarse").toBe(false);
      expect(instalado(), "el certificado que funcionaba se conservó").toBe(previo);
    });

    it("⚠️ una hoja que NOMBRA a una CA del bundle y la firmó OTRA del bundle no se instala", async () => {
      // El descuadre del 2026-09-10 tal como llega DE VERDAD: durante la
      // rotación el bundle trae la G2 Y la Issuing vieja. La hoja declaraba
      // la G2 y venía firmada con la clave de la vieja. Comprobar la firma
      // contra CUALQUIER CA del bundle la daba por buena —la vieja está
      // ahí— y el TLS la habría rechazado igual. El test anterior metía una
      // sola CA en el bundle y por eso no lo veía.
      identidadInstalada(false);
      const previo = instalado();

      const bKey = path.join(raiz, `caB-${plat.nombre}.key`);
      const bCrt = `${bKey}.crt`;
      execFileSync(OPENSSL, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", bKey]);
      execFileSync(OPENSSL, [
        "req", "-x509", "-new", "-key", bKey, "-days", "2", "-subj", "/CN=CA B",
        "-addext", "basicConstraints=critical,CA:TRUE", "-out", bCrt
      ]);
      // Con el NOMBRE de la CA buena y la clave de B: así openssl firma con
      // B poniendo como emisor a la buena, que es la forma exacta del fallo.
      const disfraz = `${bKey}.disfraz.crt`;
      execFileSync(OPENSSL, [
        "req", "-x509", "-new", "-key", bKey, "-days", "2", "-subj", "/CN=CA de prueba",
        "-addext", "basicConstraints=critical,CA:TRUE", "-out", disfraz
      ]);
      const bundleConLasDos = ca.certPem + fs.readFileSync(bCrt, "utf8");

      const s = transporte((csrPem) => {
        const base = path.join(raiz, `mezcla-${Math.random().toString(36).slice(2)}`);
        fs.writeFileSync(`${base}.csr`, csrPem);
        execFileSync(OPENSSL, [
          "x509", "-req", "-in", `${base}.csr`,
          "-CA", disfraz, "-CAkey", bKey, "-CAcreateserial",
          "-days", "2", "-out", `${base}.crt`
        ], { stdio: "pipe" });
        return {
          clientCertPem: fs.readFileSync(`${base}.crt`, "utf8"),
          caBundlePem: bundleConLasDos,
          status: "pending"
        };
      });

      const r = await renovar(s);
      expect(r.ok, "debió rechazarse").toBe(false);
      expect(instalado(), "el certificado que funcionaba se conservó").toBe(previo);
    });

    it("la hoja BUENA sí se instala: el guard no bloquea el camino sano", async () => {
      identidadInstalada(false);
      const previo = instalado();
      const s = transporte();

      const r = await renovar(s);
      expect(r.ok, JSON.stringify(r.error || {})).toBe(true);
      expect(instalado()).not.toBe(previo);
      expect(instalado()).toContain("BEGIN CERTIFICATE");
    });
  });
}

// ── El transporte, que dejó de ser HTTPS ─────────────────────────────
//
// ⚠️ Se comprueba sobre la fuente porque `grpc-bridge` abre un canal real
// al importarse. Lo que hay que sostener es estructural —"ya no queda un
// camino HTTPS por el que renovar"— y eso no se demuestra ejecutando un
// camino, se demuestra mirándolos todos.
//
// Importa porque el POST mTLS que había NO fallaba de forma visible:
// desde el 2026-09-01 el ingress dejó de reenviar el certificado de
// cliente y devolvía 401 para toda la flota, sin que nadie pudiera
// notarlo — no caduca ningún certificado hasta abril de 2027. Dejar la
// función viva sería dejar puesto el camino que ya nos engañó una vez.
describe("la renovación ya no habla HTTPS", () => {
  const fs = require("fs");
  const path = require("path");

  for (const plat of ["macos", "linux"]) {
    it(`⚠️ ${plat}: no queda ningún POST de renovación en el crypto-store`, () => {
      const src = fs.readFileSync(
        path.join(__dirname, "..", "..", "privsvc", plat, "src", "crypto-store.ts"),
        "utf8"
      );
      expect(src).not.toContain("postJsonMtls");
      expect(src).not.toMatch(/certificates\/renew/);
    });

    it(`⚠️ ${plat}: el transporte se INYECTA, no se importa`, () => {
      // Si se importara, `crypto-store` → `grpc-bridge` → `crypto-store`
      // cerraría un ciclo. Lo compone el router, que es quien puede.
      const store = fs.readFileSync(
        path.join(__dirname, "..", "..", "privsvc", plat, "src", "crypto-store.ts"),
        "utf8"
      );
      const router = fs.readFileSync(
        path.join(__dirname, "..", "..", "privsvc", plat, "src", "router.ts"),
        "utf8"
      );
      expect(store).not.toContain('from "./grpc-bridge"');
      expect(router).toContain("handleRenewCert(req, renewCertOverGrpc)");
    });
  }
});

// ── Windows, que habla el mismo protocolo por su cuenta ──────────────
//
// Su privsvc es C# y genera el cliente del MISMO `controlplane.proto`,
// así que la RPC le aparece sola al recompilar. Lo que hay que sostener
// es que también dejó el POST: mientras siguiera ahí, la flota Windows
// —la mayor parte del parque— seguiría sin poder renovar y el síntoma
// sería idéntico al de los otros dos, que ya nos costó nueve días.
describe("la renovación de Windows tampoco habla HTTPS", () => {
  const fs = require("fs");
  const path = require("path");
  const src = fs.readFileSync(
    path.join(
      __dirname, "..", "..",
      "privsvc", "windows", "Tracenium.PrivSvc.Windows", "Ipc", "CryptoCertRenew.cs"
    ),
    "utf8"
  );

  it("⚠️ no queda ningún POST de renovación", () => {
    expect(src).not.toContain("PostAsJsonAsync");
    expect(src).not.toMatch(/certificates\/renew/);
  });

  it("⚠️ llama a la RPC por el canal ya autenticado", () => {
    expect(src).toContain("GrpcBridgeSingleton.Instance.RenewCertAsync");
  });

  it("⚠️ distingue los fallos de gRPC, no los funde en uno", () => {
    // El código de estado es lo que separa «reintenta» de «no insistas».
    // Un certificado revocado no mejora reintentando.
    expect(src).toContain("catch (RpcException");
    expect(src).toContain("rpc.StatusCode");
  });
});
