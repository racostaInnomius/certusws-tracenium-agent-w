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
// ya está probado— sino EL CSR QUE SALE POR EL CABLE, capturado en un
// servidor de verdad.

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { execFileSync } from "child_process";
import crypto from "crypto";
import fs from "fs";
import https from "https";
import os from "os";
import path from "path";
import type { AddressInfo } from "net";
import { loadOrCreateAltKey } from "../../privsvc/shared/alt-key";

const raiz = fs.mkdtempSync(path.join(os.tmpdir(), "renew-hibrido-"));

process.env.TRACENIUM_PRIVSVC_DATA_DIR = path.join(raiz, "data");
process.env.TRACENIUM_PRIVSVC_CONFIG_DIR = path.join(raiz, "etc");
process.env.TRACENIUM_PRIVSVC_LOG_DIR = path.join(raiz, "log");
process.env.TRACENIUM_PRIVSVC_SOCKET_PATH = path.join(raiz, "privsvc.sock");
// El handler sólo confía en el bundle del agente si se le pide: sin esto
// validaría el servidor de prueba contra las CA del sistema.
process.env.CERT_RENEWAL_TRUST_AGENT_CA = "1";

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

/** Una CA de juguete y el certificado del servidor de renovación. */
let ca: { certPem: string; keyPath: string; certPath: string };
let servidorPem: { cert: string; key: string };

beforeAll(() => {
  const caKey = path.join(raiz, "ca.key");
  const caCrt = path.join(raiz, "ca.crt");
  execFileSync(OPENSSL, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", caKey]);
  execFileSync(OPENSSL, [
    "req", "-x509", "-new", "-key", caKey, "-days", "2", "-subj", "/CN=CA de prueba",
    "-addext", "basicConstraints=critical,CA:TRUE", "-out", caCrt
  ]);
  ca = { certPem: fs.readFileSync(caCrt, "utf8"), keyPath: caKey, certPath: caCrt };

  const srvKey = path.join(raiz, "srv.key");
  const srvCsr = path.join(raiz, "srv.csr");
  const srvCrt = path.join(raiz, "srv.crt");
  execFileSync(OPENSSL, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", srvKey]);
  execFileSync(OPENSSL, ["req", "-new", "-key", srvKey, "-subj", "/CN=localhost", "-out", srvCsr]);
  execFileSync(OPENSSL, [
    "x509", "-req", "-in", srvCsr, "-CA", caCrt, "-CAkey", caKey, "-CAcreateserial",
    "-days", "2", "-out", srvCrt,
    "-extfile", "/dev/stdin"
  ], { input: "subjectAltName=DNS:localhost,IP:127.0.0.1\n" });
  servidorPem = { cert: fs.readFileSync(srvCrt, "utf8"), key: fs.readFileSync(srvKey, "utf8") };
});

afterAll(() => {
  try { fs.rmSync(raiz, { recursive: true, force: true }); } catch {}
});

/** Emite una hoja cualquiera: el handler sólo la parsea, no la valida. */
function hojaDeMentira(): string {
  const k = path.join(raiz, `hoja-${Math.random().toString(36).slice(2)}.key`);
  const c = `${k}.crt`;
  execFileSync(OPENSSL, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", k]);
  execFileSync(OPENSSL, ["req", "-x509", "-new", "-key", k, "-days", "2", "-subj", "/CN=hoja", "-out", c]);
  return fs.readFileSync(c, "utf8");
}

/**
 * Servidor de renovación que CAPTURA el CSR recibido. Es el punto entero
 * del test: lo que importa no es lo que el handler devuelva, sino lo que
 * manda.
 */
function servidorRenovacion(): Promise<{ port: number; visto: () => string | null; cerrar: () => void }> {
  let csrVisto: string | null = null;
  const srv = https.createServer(
    { cert: servidorPem.cert, key: servidorPem.key },
    (req, res) => {
      const trozos: Buffer[] = [];
      req.on("data", (d) => trozos.push(Buffer.from(d)));
      req.on("end", () => {
        try {
          csrVisto = JSON.parse(Buffer.concat(trozos).toString("utf8")).csrPem;
        } catch { csrVisto = null; }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          clientCertPem: hojaDeMentira(),
          caBundlePem: ca.certPem,
          status: "pending"
        }));
      });
    }
  );
  return new Promise((r) =>
    srv.listen(0, "127.0.0.1", () =>
      r({
        port: (srv.address() as AddressInfo).port,
        visto: () => csrVisto,
        cerrar: () => srv.close()
      })
    )
  );
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

    async function renovar(port: number, extra: Record<string, unknown> = {}) {
      return mod.handleRenewCert({
        v: 1,
        id: "r1",
        method: "crypto.cert.renew",
        params: { serverBaseUrl: `https://127.0.0.1:${port}`, tenantId: TENANT, deviceId: DEVICE, ...extra },
        meta: { tenantId: TENANT, deviceId: DEVICE }
      });
    }

    it("⚠️ un equipo con clave alternativa se renueva HÍBRIDO, sin que nadie se lo pida", async () => {
      // El corazón del fallo. La rotación no manda `altKeyAlgorithm`: el
      // equipo tiene que conservar su forma solo, o la primera renovación
      // lo degrada a clásico y nadie se entera.
      identidadInstalada(true);
      const s = await servidorRenovacion();
      try {
        const r = await renovar(s.port);
        expect(r.ok, JSON.stringify(r.error || {})).toBe(true);
        expect(r.result.altKeyAlgorithm).toBe("ML_DSA_65");

        const csr = s.visto();
        expect(csr, "el servidor no recibió ningún CSR").toBeTruthy();
        expect(extensionesCatalyst(csr!)).toBe(3);
      } finally {
        s.cerrar();
      }
    });

    it("⚠️ un equipo clásico se renueva CLÁSICO: nada cambia para la flota de hoy", async () => {
      identidadInstalada(false);
      const s = await servidorRenovacion();
      try {
        const r = await renovar(s.port);
        expect(r.ok, JSON.stringify(r.error || {})).toBe(true);
        expect(r.result.altKeyAlgorithm).toBeNull();
        expect(extensionesCatalyst(s.visto()!)).toBe(0);
      } finally {
        s.cerrar();
      }
    });

    it("⚠️ el CSR de la renovación lleva el SAN URI del equipo autenticado", async () => {
      // Es lo que el backend exige en renovación (`requireSanFor`): sin
      // este SAN la emisión se rechaza y la rotación no avanzaría, con el
      // CSR bien formado y todo.
      identidadInstalada(false);
      const s = await servidorRenovacion();
      try {
        await renovar(s.port);
        const f = path.join(raiz, `san-${plat.nombre}.csr`);
        fs.writeFileSync(f, s.visto()!);
        const texto = execFileSync(OPENSSL, ["req", "-in", f, "-text", "-noout"], { encoding: "utf8" });
        expect(texto).toContain(`tracenium://tenant/${TENANT}/device/${DEVICE}`);
      } finally {
        s.cerrar();
      }
    });

    it("un altKeyAlgorithm desconocido falla RUIDOSAMENTE", async () => {
      identidadInstalada(false);
      const s = await servidorRenovacion();
      try {
        const r = await renovar(s.port, { altKeyAlgorithm: "ML_DSA_87" });
        expect(r.ok).toBe(false);
        expect(s.visto(), "no debió llegar a mandar nada").toBeNull();
      } finally {
        s.cerrar();
      }
    });
  });
}
