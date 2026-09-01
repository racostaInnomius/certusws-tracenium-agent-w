// test/privsvc/cdp-cert-install.test.ts
//
// ADR-0011 FASE 3 — `cdp.cert.install`, el momento en el que los guards
// de la fase 1 dejan de estar sin cablear.
//
// ── Qué prueba este fichero y qué NO ────────────────────────────────
//
// Prueba el HANDLER: que llama a los dos guards, que respeta su
// veredicto, que comprueba la correspondencia con la clave, que escribe
// el fullchain y que cierra el bucle de la decisión 9.d.
//
// NO prueba los guards en sí. Eso lo hace su propia suite, contra el
// trust store REAL —incluida una verificación en un Ubuntu 26.04 de
// verdad—, y es donde tiene que hacerse.
//
// ⚠️ La separación no es de estilo. `cdp-write-guard.ts` fija la ruta de
// openssl a `/usr/bin/openssl` y NO la lee del entorno, que es lo
// correcto para un servicio privilegiado: si el binario que decide la
// confianza se pudiera cambiar con una variable, el guard no decidiría
// nada. La consecuencia es que un test no puede hacerle creer que una
// CA de prueba está instalada. Así que:
//
//   · el rechazo por cadena se prueba con el guard REAL (en este entorno
//     nada encadena, que es justo lo que hace falta),
//   · y el camino positivo lo simula, COMPROBANDO ADEMÁS que el handler
//     llamó al guard — sin esa comprobación, simular el guard sería
//     indistinguible de saltárselo.

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";

const req = (method: string, params: any) => ({ v: 1 as const, id: "t1", method, params });

describe("cdp.cert.install — Linux", () => {
  let lin: any;
  let inst: any;
  let guard: any;
  let raiz: string;
  let ca: string;

  const ossl = (args: string[]) => execFileSync("/usr/bin/openssl", args, { stdio: "pipe" });

  /** Firma un CSR con la intermedia y devuelve el PEM de la hoja. */
  function firmar(csrPem: string, nombre = "leaf"): string {
    const csr = path.join(raiz, `${nombre}.csr`);
    const out = path.join(raiz, `${nombre}.pem`);
    fs.writeFileSync(csr, csrPem);
    ossl([
      "x509", "-req", "-in", csr,
      "-CA", path.join(ca, "int.pem"), "-CAkey", path.join(ca, "int.key"),
      "-CAcreateserial", "-days", "1", "-sha256", "-out", out
    ]);
    return fs.readFileSync(out, "utf8");
  }

  /** La intermedia — lo que de verdad viaja en `chainPems`. */
  const intermedia = () => fs.readFileSync(path.join(ca, "int.pem"), "utf8");

  /** Simula «la cadena llega a un ancla instalada» y deja ver si se usó. */
  function guardDiceQueSi(destinoOk: string | true) {
    const cadena = vi
      .spyOn(guard, "chainsToInstalledAnchor")
      .mockResolvedValue({ trusted: true, reason: "simulado en el test" });
    const ruta = vi
      .spyOn(guard, "isWritablePath")
      .mockImplementation((p: any) => destinoOk === true || String(p) === destinoOk);
    return { cadena, ruta, restore: () => { cadena.mockRestore(); ruta.mockRestore(); } };
  }

  beforeAll(async () => {
    raiz = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-inst-"));
    ca = path.join(raiz, "ca");
    fs.mkdirSync(ca, { recursive: true });

    // Jerarquía de verdad: raíz → intermedia → hoja. Una CA de un solo
    // nivel obligaría a meter la RAÍZ en `chainPems`, que no es el uso
    // real —ahí van intermedias— y además se comporta distinto según el
    // OpenSSL que haya delante.
    ossl([
      "req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", path.join(ca, "root.key"), "-out", path.join(ca, "root.pem"),
      "-days", "1", "-subj", "/CN=Raiz de prueba Tracenium"
    ]);
    ossl([
      "req", "-newkey", "rsa:2048", "-nodes",
      "-keyout", path.join(ca, "int.key"), "-out", path.join(ca, "int.csr"),
      "-subj", "/CN=Intermedia de prueba Tracenium"
    ]);
    const ext = path.join(ca, "int.ext");
    fs.writeFileSync(
      ext,
      "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
    );
    ossl([
      "x509", "-req", "-in", path.join(ca, "int.csr"),
      "-CA", path.join(ca, "root.pem"), "-CAkey", path.join(ca, "root.key"),
      "-CAcreateserial", "-days", "1", "-sha256",
      "-extfile", ext, "-out", path.join(ca, "int.pem")
    ]);

    process.env.TRACENIUM_PRIVSVC_CONFIG_DIR = raiz;
    vi.resetModules();
    lin = await import("../../privsvc/linux/src/cdp-keys");
    guard = await import("../../privsvc/linux/src/cdp-write-guard");
    inst = await import("../../privsvc/linux/src/cdp-cert-install");
  }, 60_000);

  afterAll(() => {
    delete process.env.TRACENIUM_PRIVSVC_CONFIG_DIR;
    try {
      fs.rmSync(raiz, { recursive: true, force: true });
    } catch {}
  });

  it("⭐ ciclo completo: CSR → firma → instalación, y la clave deja de ser huérfana", async () => {
    const csr: any = await lin.handleCdpCsrGenerate(
      req("cdp.csr.generate", {
        keyId: "web01",
        subject: "CN=web01.corp,O=Acme",
        dnsNames: ["web01.corp"],
        eku: "serverAuth",
        requestId: "req-1"
      })
    );
    expect(csr.ok).toBe(true);

    const antes: any = await lin.handleCdpKeyList(req("cdp.key.list", {}));
    expect(antes.result.keys.find((k: any) => k.keyId === "web01").orphan).toBe(true);

    const hoja = firmar(csr.result.csrPem);
    const destino = path.join(raiz, "nginx-ssl", "prueba.pem");
    const g = guardDiceQueSi(destino);

    const r: any = await inst.handleCdpCertInstall(
      req("cdp.cert.install", {
        keyId: "web01",
        certPem: hoja,
        chainPems: [intermedia()],
        destination: destino
      })
    );

    // ⚠️ Que el handler PREGUNTÓ. Sin esto, simular el guard sería
    // indistinguible de que el handler se lo saltara.
    expect(g.ruta).toHaveBeenCalledWith(destino);
    expect(g.cadena).toHaveBeenCalledOnce();
    expect(g.cadena.mock.calls[0][0]).toContain("BEGIN CERTIFICATE");
    // Y que le pasó las intermedias: sin ellas el guard real rechazaría
    // todo, incluido lo legítimo.
    expect(g.cadena.mock.calls[0][1]).toHaveLength(1);
    g.restore();

    expect(r.ok).toBe(true);
    expect(r.result.certsWritten).toBe(2);

    // Hoja MÁS intermedia: es el `fullchain` que esperan nginx y
    // compañía. Sin ella el servicio arranca y fallan los clientes — un
    // fallo que no aparece en el arranque sino en el primer usuario.
    const escrito = fs.readFileSync(destino, "utf8");
    expect(escrito.match(/BEGIN CERTIFICATE/g)?.length).toBe(2);
    // Y el fichero es legible por el servicio, no 0600: nginx no corre
    // como root después de arrancar.
    expect(fs.statSync(destino).mode & 0o777).toBe(0o644);

    // 9.d cerrado: la clave deja de ser huérfana.
    const despues: any = await lin.handleCdpKeyList(req("cdp.key.list", {}));
    const k = despues.result.keys.find((x: any) => x.keyId === "web01");
    expect(k.orphan).toBe(false);
    expect(k.certInstalledAt).toBeTruthy();
  }, 60_000);

  it("⭐ rechaza un destino fuera de la allowlist — la decisión 1", async () => {
    const csr: any = await lin.handleCdpCsrGenerate(
      req("cdp.csr.generate", { keyId: "web02", subject: "CN=web02.corp" })
    );
    const hoja = firmar(csr.result.csrPem, "leaf2");

    // Guard de rutas REAL. Los tres primeros son los directorios de
    // anclas del sistema: el destino que este ADR existe para hacer
    // inalcanzable.
    for (const malo of [
      "/usr/local/share/ca-certificates/evil.crt",
      "/etc/pki/ca-trust/source/anchors/evil.crt",
      "/etc/ssl/certs/evil.pem",
      "/etc/nginx/../ssl/certs/evil.pem",
      "/tmp/cualquier-cosa.pem"
    ]) {
      const r: any = await inst.handleCdpCertInstall(
        req("cdp.cert.install", { keyId: "web02", certPem: hoja, destination: malo })
      );
      expect(r.ok).toBe(false);
      expect(r.error.code).toBe("destination_not_writable");
      expect(fs.existsSync(malo)).toBe(false);
    }
  }, 60_000);

  it("exige destino: en Linux no hay sitio canónico que adivinar", async () => {
    const r: any = await inst.handleCdpCertInstall(
      req("cdp.cert.install", {
        keyId: "web02",
        certPem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----"
      })
    );
    expect(r.ok).toBe(false);
    expect(r.error.code).toBe("bad_request");
  });

  it("⭐ con el guard REAL, una cadena que no llega a un ancla NO se escribe", async () => {
    // Aquí el guard de cadena no se simula. En este entorno nada
    // encadena al trust store del sistema, que es exactamente la
    // condición que hace falta: si el handler ignorara el veredicto,
    // escribiría el fichero y este test lo vería.
    const hoja = firmar(
      (await lin.handleCdpCsrGenerate(req("cdp.csr.generate", { keyId: "web03", subject: "CN=w3" })))
        .result.csrPem,
      "leaf3"
    );
    const destino = path.join(raiz, "no-deberia-existir.pem");
    const ruta = vi.spyOn(guard, "isWritablePath").mockReturnValue(true);

    const r: any = await inst.handleCdpCertInstall(
      req("cdp.cert.install", { keyId: "web03", certPem: hoja, destination: destino })
    );
    ruta.mockRestore();

    expect(r.ok).toBe(false);
    expect(r.error.code).toBe("chain_not_trusted");
    expect(fs.existsSync(destino)).toBe(false);
  }, 60_000);

  it("⭐ rechaza un certificado que no corresponde a la clave", async () => {
    // Encadena bien, pero es de OTRA clave. Sin esta comprobación se
    // escribiría igual, y el fallo aparecería más tarde y en otro sitio:
    // el servicio arrancando con un par que no casa.
    const otro: any = await lin.handleCdpCsrGenerate(
      req("cdp.csr.generate", { keyId: "otra", subject: "CN=otra.corp" })
    );
    const hojaDeOtra = firmar(otro.result.csrPem, "leaf-otra");

    const destino = path.join(raiz, "no-escribir.pem");
    const g = guardDiceQueSi(true);
    const r: any = await inst.handleCdpCertInstall(
      req("cdp.cert.install", {
        keyId: "web02",
        certPem: hojaDeOtra,
        chainPems: [intermedia()],
        destination: destino
      })
    );
    g.restore();

    expect(r.ok).toBe(false);
    expect(r.error.code).toBe("cert_key_mismatch");
    expect(fs.existsSync(destino)).toBe(false);
  }, 60_000);

  it("aplica el tope por job EN EL AGENTE, no solo en el control plane", async () => {
    const r: any = await inst.handleCdpCertInstall(
      req("cdp.cert.install", {
        keyId: "web02",
        certPem: intermedia(),
        chainPems: Array(inst.MAX_CERTS_POR_JOB).fill(intermedia()),
        destination: "/etc/nginx/ssl/x.pem"
      })
    );
    expect(r.ok).toBe(false);
    expect(r.error.code).toBe("too_many_certs");
  });

  it("un fallo de instalación NO destruye la clave: el par sobrevive al reintento", async () => {
    // La CA ya firmó, así que clave y certificado son un par. Destruir
    // la clave tiraría un certificado emitido y dejaría el reintento
    // imposible. Y mientras no se instale, la clave sigue saliendo como
    // huérfana — la lista de huérfanas ES la cola de reintentos.
    expect(fs.existsSync(lin.cdpKeyPath("web02"))).toBe(true);
    const lista: any = await lin.handleCdpKeyList(req("cdp.key.list", {}));
    expect(lista.result.keys.find((k: any) => k.keyId === "web02").orphan).toBe(true);
  });
});
