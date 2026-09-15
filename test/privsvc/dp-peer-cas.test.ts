// test/privsvc/dp-peer-cas.test.ts
//
// ¿A quién sirve un DP de macOS/Linux? Se prueba con TLS DE VERDAD, porque la
// propiedad vive en cómo verifica Node, no en el texto del `ca`.
//
// 🔴 El caso de campo (15-sep, en Windows): DP en la Issuing vieja, peer rotado
// a la G2 → rechazado, update a Azure, `connect ETIMEDOUT`. Aquí la jerarquía
// imita la de producción: Root RSA, G2 en P-384, vieja en RSA; el bundle que
// entrega el backend lleva las dos intermedias SIN la raíz.
//
// ⚠️ Medido al escribir esto: el TLS de Node NO acepta cadenas parciales. Con
// `ca` = sólo intermedias rechaza a TODOS; la raíz tiene que estar.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "child_process";
import crypto from "crypto";
import fs from "fs";
import https from "https";
import os from "os";
import path from "path";
import * as linux from "../../privsvc/linux/src/dp-peer-cas";
import * as macos from "../../privsvc/macos/src/dp-peer-cas";

let dir = "";
const f = (n: string) => path.join(dir, n);
const read = (n: string) => fs.readFileSync(f(n), "utf8");
const ossl = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });

function root(name: string, cn: string) {
  ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.crt`,
    "-subj", cn, "-days", "30", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign");
}
function signed(name: string, cn: string, ca: string, ext: "ca" | "leaf", keyAlg: string[]) {
  ossl("req", "-new", "-nodes", ...keyAlg, "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", cn);
  ossl("x509", "-req", "-in", `${name}.csr`, "-CA", `${ca}.crt`, "-CAkey", `${ca}.key`, "-set_serial",
    String(Math.floor(Math.random() * 1e9)), "-out", `${name}.crt`, "-days", "30", "-extfile", "ext.cnf", "-extensions", ext);
}

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "tracenium-dp-peer-cas-"));
  fs.writeFileSync(f("ext.cnf"),
    "[ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n" +
    "[leaf]\nbasicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth,serverAuth\n");
  const rsa = ["-newkey", "rsa:2048"];
  const p384 = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"];
  root("root", "/C=US/O=Tracenium/OU=RootCA/CN=Tracenium Root CA");
  signed("g1", "/C=US/O=Tracenium/OU=IssuingCA/CN=Tracenium Issuing CA", "root", "ca", rsa);
  signed("g2", "/C=US/O=Tracenium/CN=Tracenium Issuing CA G2", "root", "ca", p384);
  signed("dp", "/CN=tracenium-agent-dp", "g1", "leaf", rsa);
  signed("peerG1", "/CN=tracenium-agent-peer-g1", "g1", "leaf", rsa);
  signed("peerG2", "/CN=tracenium-agent-18f2240b", "g2", "leaf", rsa);
  // Una jerarquía AJENA con los mismos nombres.
  root("evilRoot", "/C=US/O=Tracenium/OU=RootCA/CN=Tracenium Root CA");
  signed("evilG2", "/C=US/O=Tracenium/CN=Tracenium Issuing CA G2", "evilRoot", "ca", rsa);
  signed("peerEvil", "/CN=tracenium-agent-evil", "evilG2", "leaf", rsa);

  // ⚠️ La falsificación que de verdad aísla la FIRMA. La jerarquía ajena de
  // arriba no la aísla: su G2 lleva un authorityKeyIdentifier que NO es el de
  // la raíz real, así que `checkIssued` ya la rechaza por AKI y la verificación
  // de firma nunca llega a probarse (una mutación que la quitaba pasaba los
  // tests, 15-sep). Aquí la raíz ajena copia el NOMBRE y el SKI de la real, y
  // su CA hereda ese AKI: nombre y AKI casan, sólo la firma delata el engaño.
  const ski = String(ossl("x509", "-in", "root.crt", "-noout", "-ext", "subjectKeyIdentifier"))
    .match(/[0-9A-F]{2}(?::[0-9A-F]{2}){5,}/i)?.[0];
  if (!ski) throw new Error("no se pudo leer el SKI de la raíz real");
  ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "cloneRoot.key", "-out", "cloneRoot.crt",
    "-subj", "/C=US/O=Tracenium/OU=RootCA/CN=Tracenium Root CA", "-days", "30",
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    "-addext", `subjectKeyIdentifier=${ski}`);
  fs.appendFileSync(f("ext.cnf"),
    "[caAki]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nauthorityKeyIdentifier=keyid:always\n");
  ossl("req", "-new", "-nodes", "-newkey", "rsa:2048", "-keyout", "forgedG2.key", "-out", "forgedG2.csr",
    "-subj", "/C=US/O=Tracenium/CN=Tracenium Issuing CA G2");
  ossl("x509", "-req", "-in", "forgedG2.csr", "-CA", "cloneRoot.crt", "-CAkey", "cloneRoot.key", "-set_serial", "77",
    "-out", "forgedG2.crt", "-days", "30", "-extfile", "ext.cnf", "-extensions", "caAki");
}, 60_000);

afterAll(() => {
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

/** El ca-bundle de un DP enrolado ANTES de la G2: vieja + raíz (buildFullCaBundlePem). */
const caBundleViejo = () => read("g1.crt") + read("root.crt");
/** Lo que sirve el backend en AGENT_CA_BUNDLE_PEM: G2 + vieja, sin raíz. */
const bundleEntregado = () => read("g2.crt") + read("g1.crt");

async function handshake(ca: string[], peer: string, reload?: string[]): Promise<number | string> {
  const server = https.createServer(
    { key: read("dp.key"), cert: read("dp.crt"), ca, requestCert: true, rejectUnauthorized: true },
    (_req, res) => res.end("ok")
  );
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  if (reload) server.setSecureContext({ key: read("dp.key"), cert: read("dp.crt"), ca: reload });
  const port = (server.address() as any).port;
  try {
    return await new Promise((resolve) => {
      const req = https.request(
        { host: "127.0.0.1", port, path: "/", key: read(`${peer}.key`), cert: read(`${peer}.crt`), rejectUnauthorized: false },
        (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); }
      );
      req.on("error", (e: any) => resolve(String(e.code || e.message)));
      req.end();
    });
  } finally {
    server.close();
  }
}

describe.each([["linux", linux], ["macos", macos]])("dp-peer-cas (%s)", (_plat, mod) => {
  it("sin bundle entregado, el DP de la vieja RECHAZA al peer de la G2 — el fallo de campo", async () => {
    const { ca } = mod.dpServerCa(caBundleViejo(), read("root.crt"), null);
    expect(await handshake(ca, "peerG2")).not.toBe(200);
    expect(await handshake(ca, "peerG1")).toBe(200);
  });

  it("⭐ con el bundle REAL del backend sirve a la G2 y sigue sirviendo a la vieja", async () => {
    const { ca, acceptedIssuingCas } = mod.dpServerCa(caBundleViejo(), read("root.crt"), bundleEntregado());
    expect(acceptedIssuingCas).toBe(2);
    expect(await handshake(ca, "peerG2")).toBe(200);
    expect(await handshake(ca, "peerG1")).toBe(200);
  });

  it("setSecureContext aplica el bundle nuevo sin reiniciar el servidor", async () => {
    const antes = mod.dpServerCa(caBundleViejo(), read("root.crt"), null).ca;
    const despues = mod.dpServerCa(caBundleViejo(), read("root.crt"), bundleEntregado()).ca;
    expect(await handshake(antes, "peerG2", despues)).toBe(200);
  });

  it("⚠️ una CA entregada de OTRA raíz (mismo nombre) no entra, y su peer tampoco", async () => {
    expect(mod.trustedDeliveredCaPems(read("evilG2.crt"), [read("root.crt")])).toEqual([]);
    const { ca, acceptedIssuingCas } = mod.dpServerCa(caBundleViejo(), read("root.crt"), read("evilG2.crt"));
    expect(acceptedIssuingCas).toBe(1);
    expect(await handshake(ca, "peerEvil")).not.toBe(200);
  });

  it("⭐ una CA con el NOMBRE y el AKI de la raíz real pero firmada con otra clave NO entra", () => {
    const forged = new crypto.X509Certificate(read("forgedG2.crt"));
    const realRoot = new crypto.X509Certificate(read("root.crt"));
    // Precondición: si esto dejara de ser cierto, el test ya no probaría la
    // firma y pasaría por la razón equivocada — que es lo que ocurría antes.
    expect(forged.checkIssued(realRoot), "la falsificación debe casar en nombre y AKI").toBe(true);
    expect(forged.verify(realRoot.publicKey), "…y sólo la firma debe delatarla").toBe(false);

    expect(mod.trustedDeliveredCaPems(read("forgedG2.crt"), [read("root.crt")])).toEqual([]);
    expect(mod.dpServerCa(caBundleViejo(), read("root.crt"), read("forgedG2.crt")).acceptedIssuingCas).toBe(1);
  });

  it("no acepta como CA emisora una hoja ni una raíz entregadas", () => {
    expect(mod.trustedDeliveredCaPems(read("peerG1.crt") + read("root.crt"), [read("root.crt")])).toEqual([]);
  });

  it("sin anclas no se acepta nada; el ancla puede venir sólo de la raíz del paquete", () => {
    expect(mod.trustedDeliveredCaPems(read("g2.crt"), [read("g1.crt")])).toEqual([]);
    // ca-bundle sin raíz, raíz sólo en el paquete: la G2 entregada se criba bien.
    expect(mod.dpServerCa(read("g1.crt"), read("root.crt"), read("g2.crt")).acceptedIssuingCas).toBe(2);
  });

  it("ignora basura, respeta el tope y no repite", () => {
    expect(mod.trustedDeliveredCaPems("basura", [read("root.crt")])).toEqual([]);
    expect(mod.trustedDeliveredCaPems("A".repeat(mod.MAX_DELIVERED_BUNDLE_CHARS + 1), [read("root.crt")])).toEqual([]);
    const { ca } = mod.dpServerCa(caBundleViejo(), read("root.crt"), bundleEntregado() + read("g1.crt"));
    expect(ca).toHaveLength(3); // vieja + raíz + G2
  });
});

describe("dp.ts usa el ca calculado (lectura del fuente, en los dos privsvc)", () => {
  for (const plat of ["linux", "macos"]) {
    const src = fs.readFileSync(path.join(__dirname, "../../privsvc", plat, "src", "dp.ts"), "utf8");
    it(`${plat}: el servidor y la recarga salen de dpTlsMaterial, y el prefetch persiste lo entregado`, () => {
      // El `ca` DEL createServer, no uno cualquiera del fichero.
      const i = src.indexOf("https.createServer(");
      const createServer = src.slice(i, src.indexOf("handleBlobRequest", i));
      expect(i).toBeGreaterThan(0);
      expect(createServer).toMatch(/\bca: material\.ca,/);
      expect(src).toContain("persistDeliveredPeerCas(params.peerCaBundlePem)");
      expect(src).toMatch(/setSecureContext\(\{[^}]*ca: material\.ca/);
      expect(src).toContain('server.on("tlsClientError", logPeerRejection)');
    });
  }
});
