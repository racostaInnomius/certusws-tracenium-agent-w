// privsvc/macos/src/cdp-cert-install.ts
//
// ADR-0011 FASE 3 — `cdp.cert.install`.
//
// Es el momento en el que la fase 1 deja de estar sin cablear. Los dos
// guards que se construyeron ANTES que esta capacidad —y el ADR ordena
// asi las fases «porque es la unica forma de que la defensa no se
// recorte por presion de calendario cuando la funcionalidad ya este a
// medio camino»— son ahora obligatorios en el camino:
//
//   decision 1 · allowlist de destinos, que EXCLUYE las anclas
//   decision 2 · solo se instala lo que YA encadena a un ancla presente,
//                validado contra el trust store LOCAL
//
// ── Por que la validacion de cadena la hace el ENDPOINT ─────────────
//
// Porque la tesis del ADR es que el control plane puede ser el
// adversario. Un backend comprometido afirmaria que la cadena es buena;
// preguntarselo a el seria pedirle al gate que se valide a si mismo.
//
// ── Lo que este handler NO hace ─────────────────────────────────────
//
// No destruye la clave cuando la instalacion falla, y es deliberado. La
// decision 9.c enumera las salidas terminales —fallo de FIRMA, timeout,
// cancelacion, aprobacion denegada o caducada— y esta no es una: para
// cuando llegamos aqui la CA YA firmo, asi que clave y certificado son
// un par. Destruir la clave tiraria un certificado emitido y dejaria el
// reintento imposible, porque el certificado no encajaria con una clave
// nueva.
//
// Y hay una propiedad bonita en dejarla: mientras no se instale, la
// clave sigue apareciendo como huerfana en `cdp.key.list` (decision
// 9.d). La lista de huerfanas ES la cola de reintentos.

import fs from "fs";
import os from "os";
import path from "path";
import { isWritableKeychain, chainsToInstalledAnchor } from "./cdp-write-guard";
import { installCert, SYSTEM_KEYCHAIN } from "./keystore";
import { cdpKeyLabel, isValidKeyId, assertNotEnrollmentKey, markCertInstalled } from "./cdp-keys";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";

/**
 * Tope de certificados por peticion.
 *
 * ⚠️ El tope va tambien AQUI, no solo en el control plane. Un tope que
 * solo vive en el backend no protege de un backend comprometido, que es
 * exactamente el adversario que este ADR modela. El del control plane
 * existe para dar un error util al operador; este existe para que el
 * limite sea real.
 */
export const MAX_CERTS_POR_JOB = 10;

export async function handleCdpCertInstall(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const p: any = req.params || {};
  const keyId = String(p.keyId || "");

  if (!isValidKeyId(keyId)) return fail(req.id, "bad_request", "keyId invalido");

  let label: string;
  try {
    label = cdpKeyLabel(keyId);
    assertNotEnrollmentKey(label);
  } catch (err: any) {
    return fail(req.id, "bad_request", String(err?.message || err));
  }

  const certPem = String(p.certPem || "");
  if (!certPem.includes("BEGIN CERTIFICATE")) {
    return fail(req.id, "bad_request", "certPem requerido");
  }

  const chainPems: string[] = Array.isArray(p.chainPems)
    ? p.chainPems.map((c: any) => String(c)).filter((c: string) => c.includes("BEGIN CERTIFICATE"))
    : [];

  // El tope cuenta la hoja mas su cadena: lo que limita es cuanto
  // material acepta una sola peticion, no cuantas hojas.
  if (1 + chainPems.length > MAX_CERTS_POR_JOB) {
    return fail(
      req.id,
      "too_many_certs",
      `${1 + chainPems.length} certificados en una peticion; el tope es ${MAX_CERTS_POR_JOB}`
    );
  }

  // ── Guard 1: el destino ───────────────────────────────────────────
  //
  // En macOS el unico destino escribible es el llavero de la maquina.
  // El llamante puede nombrarlo, pero solo para que la peticion sea
  // explicita: si nombra otro, se rechaza. NO esta el bundle de anclas
  // de Apple, que ademas SIP protege.
  const destino = String(p.destination || SYSTEM_KEYCHAIN);
  if (!isWritableKeychain(destino)) {
    return fail(
      req.id,
      "destination_not_writable",
      `destino no permitido: ${destino} (solo el llavero de la maquina; nunca anclas)`
    );
  }

  // ── Guard 2: la cadena, contra el trust store LOCAL ───────────────
  const veredicto = await chainsToInstalledAnchor(certPem, chainPems);
  if (!veredicto.trusted) {
    // Se devuelve el motivo del sistema tal cual. Un operador al que se
    // le rechaza una instalacion necesita saber si le falta la
    // intermedia (arreglable) o si la raiz no esta en el equipo, que es
    // el caso que este gate existe para impedir.
    logger.warn(`cdp.cert.install rechazado por cadena: ${veredicto.reason}`);
    return fail(req.id, "chain_not_trusted", veredicto.reason);
  }

  // ── Instalacion ───────────────────────────────────────────────────
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tracenium-install-"));
  try {
    const certPath = path.join(dir, "cert.pem");
    fs.writeFileSync(certPath, certPem, { encoding: "utf8", mode: 0o600 });

    const out = await installCert(label, certPath, destino);
    if (!out.ok) {
      // Ver la cabecera: NO se destruye la clave. El certificado ya esta
      // emitido y el par tiene que sobrevivir al reintento.
      return fail(req.id, out.code || "cert_install_failed", out.message || "no se pudo instalar");
    }

    // La clave deja de ser huerfana. Es lo que cierra el bucle de 9.d:
    // sin esto seguiria apareciendo en el panel como material sin uso.
    markCertInstalled(keyId);

    return success(req.id, {
      keyId,
      installed: true,
      destination: destino,
      subject: out.subject ?? null,
      sha256: out.sha256 ?? null,
      chainReason: veredicto.reason
    });
  } catch (err: any) {
    return fail(req.id, "cert_install_failed", String(err?.message || err));
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* el temporal se pierde, no la instalacion */
    }
  }
}
