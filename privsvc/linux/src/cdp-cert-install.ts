// privsvc/linux/src/cdp-cert-install.ts
//
// ADR-0011 FASE 3 — `cdp.cert.install`.
//
// Gemelo de `privsvc/macos/src/cdp-cert-install.ts` y de
// `CdpCertInstall.cs`. Es el momento en el que los guards de la fase 1
// dejan de estar sin cablear:
//
//   decision 1 · allowlist de destinos, que EXCLUYE los directorios de
//                anclas (`/usr/local/share/ca-certificates`,
//                `/etc/pki/ca-trust/source/anchors`, `/etc/ssl/certs`)
//   decision 2 · solo se instala lo que YA encadena a un ancla presente,
//                validado contra el trust store LOCAL — un backend
//                comprometido afirmaria que la cadena es buena
//
// ── En que se diferencia de macOS ───────────────────────────────────
//
// Alli el destino es un llavero y «atar» el certificado a la clave lo
// hace el sistema por el hash de la clave publica. Aqui el destino es
// una RUTA —donde nginx o haproxy van a buscar el PEM— y no hay nada
// que ate nada: es el operador quien apunta su servicio a ese fichero.
//
// Por eso la comprobacion de correspondencia es explicita y va ANTES de
// escribir. Un certificado que no corresponde a esta clave se escribiria
// igual de bien, y el fallo aparecería mas tarde y en otro sitio: el
// servicio arrancando con un par que no case, que es un modo de fallo
// mucho peor de diagnosticar que un rechazo aqui.

import fs from "fs";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import { isWritablePath, chainsToInstalledAnchor } from "./cdp-write-guard";
import { cdpKeyPath, isValidKeyId, markCertInstalled } from "./cdp-keys";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";

const execFileAsync = promisify(execFile);
const OPENSSL_BIN = process.env.OPENSSL_BIN || "/usr/bin/openssl";
const OPENSSL_TIMEOUT_MS = 15_000;

/**
 * Tope de certificados por peticion.
 *
 * ⚠️ El tope va tambien AQUI, no solo en el control plane. Un tope que
 * solo vive en el backend no protege de un backend comprometido, que es
 * exactamente el adversario que este ADR modela.
 */
export const MAX_CERTS_POR_JOB = 10;

/**
 * ¿El certificado corresponde a la clave?
 *
 * Se comparan los modulos: es la comprobacion que hace cualquiera a mano
 * con `openssl x509 -modulus` y `openssl rsa -modulus`, y la unica que
 * responde la pregunta sin instalar nada.
 */
export async function certMatchesKey(certPath: string, keyPath: string): Promise<boolean> {
  try {
    const [cert, key] = await Promise.all([
      execFileAsync(OPENSSL_BIN, ["x509", "-noout", "-modulus", "-in", certPath], {
        timeout: OPENSSL_TIMEOUT_MS
      }),
      execFileAsync(OPENSSL_BIN, ["rsa", "-noout", "-modulus", "-in", keyPath], {
        timeout: OPENSSL_TIMEOUT_MS
      })
    ]);
    const a = String(cert.stdout || "").trim();
    const b = String(key.stdout || "").trim();
    // Y que no sean dos cadenas vacias iguales: si openssl no imprime
    // modulo, comparar "" con "" daria verdadero y el gate se regalaria.
    return a.length > 0 && a === b;
  } catch {
    return false;
  }
}

export async function handleCdpCertInstall(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const p: any = req.params || {};
  const keyId = String(p.keyId || "");

  if (!isValidKeyId(keyId)) return fail(req.id, "bad_request", "keyId invalido");

  let keyPath: string;
  try {
    keyPath = cdpKeyPath(keyId);
  } catch (err: any) {
    return fail(req.id, "bad_request", String(err?.message || err));
  }
  if (!fs.existsSync(keyPath)) {
    return fail(req.id, "key_not_found", `no hay clave para keyId ${keyId}`);
  }

  const certPem = String(p.certPem || "");
  if (!certPem.includes("BEGIN CERTIFICATE")) {
    return fail(req.id, "bad_request", "certPem requerido");
  }

  const chainPems: string[] = Array.isArray(p.chainPems)
    ? p.chainPems.map((c: any) => String(c)).filter((c: string) => c.includes("BEGIN CERTIFICATE"))
    : [];

  if (1 + chainPems.length > MAX_CERTS_POR_JOB) {
    return fail(
      req.id,
      "too_many_certs",
      `${1 + chainPems.length} certificados en una peticion; el tope es ${MAX_CERTS_POR_JOB}`
    );
  }

  // ── Guard 1: el destino ───────────────────────────────────────────
  //
  // Obligatorio y sin defecto. En Linux no hay un sitio canonico —cada
  // servicio busca su PEM donde le han dicho—, y elegir uno por el
  // operador seria adivinar. Que falte es un fallo, no un caso a
  // rellenar.
  const destino = String(p.destination || "");
  if (!destino) {
    return fail(req.id, "bad_request", "destination requerido (ruta del PEM del servicio)");
  }
  if (!isWritablePath(destino)) {
    return fail(
      req.id,
      "destination_not_writable",
      `destino no permitido: ${destino} (nunca directorios de anclas del sistema)`
    );
  }

  // ── Guard 2: la cadena, contra el trust store LOCAL ───────────────
  const veredicto = await chainsToInstalledAnchor(certPem, chainPems);
  if (!veredicto.trusted) {
    logger.warn(`cdp.cert.install rechazado por cadena: ${veredicto.reason}`);
    return fail(req.id, "chain_not_trusted", veredicto.reason);
  }

  // ── Correspondencia con la clave ──────────────────────────────────
  const tmpCert = `${keyPath}.incoming`;
  try {
    fs.writeFileSync(tmpCert, certPem, { encoding: "utf8", mode: 0o600 });
    if (!(await certMatchesKey(tmpCert, keyPath))) {
      return fail(
        req.id,
        "cert_key_mismatch",
        `el certificado no corresponde a la clave ${keyId}`
      );
    }

    // ── Escritura ───────────────────────────────────────────────────
    //
    // Se escribe la HOJA seguida de las intermedias: es el `fullchain`
    // que esperan nginx, haproxy y compania. Sin las intermedias el
    // servicio arranca y los clientes fallan la validacion — un fallo
    // que no aparece en el arranque sino en el primer usuario.
    const contenido = [certPem.trim(), ...chainPems.map((c) => c.trim())].join("\n") + "\n";

    fs.mkdirSync(path.dirname(destino), { recursive: true });
    // Escritura atomica: un servicio que recargue a mitad de un write no
    // puede encontrarse medio PEM.
    const tmpDest = `${destino}.tracenium.tmp`;
    fs.writeFileSync(tmpDest, contenido, { encoding: "utf8", mode: 0o644 });
    fs.renameSync(tmpDest, destino);

    markCertInstalled(keyId);

    return success(req.id, {
      keyId,
      installed: true,
      destination: destino,
      // Se dice cuantos van, para que el operador pueda cotejarlo con lo
      // que pidio sin abrir el fichero.
      certsWritten: 1 + chainPems.length,
      keyPath,
      chainReason: veredicto.reason
    });
  } catch (err: any) {
    // Ver la cabecera del gemelo de macOS: NO se destruye la clave. La
    // CA ya firmo, asi que clave y certificado son un par y el reintento
    // los necesita a los dos. Mientras no se instale, la clave sigue
    // saliendo como huerfana en `cdp.key.list` — la lista de huerfanas
    // ES la cola de reintentos.
    return fail(req.id, "cert_install_failed", String(err?.message || err));
  } finally {
    try {
      fs.rmSync(tmpCert, { force: true });
    } catch {
      /* el temporal se pierde, no la instalacion */
    }
  }
}
