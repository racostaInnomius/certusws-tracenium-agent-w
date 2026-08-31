// privsvc/macos/src/anchor-distrust.ts
//
// Quitar la confianza a un ancla en macOS. ADR-0011, decision 10.
//
// ⚠️ SIN RUTA QUE LA INVOQUE TODAVIA, y es deliberado. La decision 10
// exige el regimen de aprobacion de ADR-0009, que esta aceptado y sin
// construir. La fase 1 del propio ADR-0011 manda construir la defensa
// ANTES que la capacidad que la necesita, "porque es la unica forma de
// que la defensa no se recorte por presion de calendario".
//
// ── Por que DESCONFIAR y no BORRAR, aqui con mas razon ──────────────
//
// Del llavero que ENVIA Apple (`SystemRootCertificates.keychain`) no se
// puede borrar: lo protege SIP. Y no hace falta — Apple mismo conserva
// ahi las CAs que retira y les marca la confianza en negativo. El
// mecanismo es ese: `security add-trusted-cert -d -r deny`, que escribe
// un trust setting explicito de DESCONFIANZA en el dominio de admin.
//
// ── El control plane NUNCA manda material de certificado ─────────────
//
// Se opera por HUELLA SHA-1: el handler busca el certificado en los
// llaveros del propio equipo y exporta el PEM que ya tenia. Si no lo
// encuentra, no hay nada que desconfiar y se niega. Por esta ruta un
// control plane comprometido no puede INTRODUCIR nada, solo retirar la
// confianza de algo que el equipo ya tenia.

import fs from "fs";
import os from "os";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import { loadAnchorPins } from "./anchor-pin";
import { CERT_DIR } from "./paths";

const execFileAsync = promisify(execFile);

const SECURITY_BIN = "/usr/bin/security";
const SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain";
const SYSTEM_ROOTS_KEYCHAIN =
  "/System/Library/Keychains/SystemRootCertificates.keychain";
const EXEC_TIMEOUT_MS = 20000;
const EXEC_MAX_BUFFER = 16 * 1024 * 1024;

export type DistrustOutcome =
  | { ok: true; sha1: string; subject: string | null }
  | { ok: false; code: string; message: string };

function normalizeSha1(value: string): string {
  return value.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
}

/**
 * Localiza un certificado por huella SHA-1 en los llaveros del equipo y
 * devuelve su PEM.
 *
 * `-Z` hace que `find-certificate` imprima la huella SHA-1 junto a cada
 * PEM, que es como se emparejan sin tener que parsear cada certificado.
 */
export function extractPemBySha1(
  output: string,
  wantedSha1: string
): { pem: string; subject: string | null } | null {
  const wanted = normalizeSha1(wantedSha1);
  // Cada bloque empieza en la linea "SHA-1 hash: XXXX" y contiene un PEM.
  const blocks = output.split(/(?=SHA-1 hash:)/g);
  for (const block of blocks) {
    const hash = /SHA-1 hash:\s*([0-9A-Fa-f]+)/.exec(block);
    if (!hash || normalizeSha1(hash[1]) !== wanted) continue;
    const pem = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/.exec(block);
    if (!pem) return null;
    const subj = /"labl"<blob>="([^"]*)"/.exec(block);
    return { pem: pem[0], subject: subj ? subj[1] : null };
  }
  return null;
}

export async function distrustAnchor(sha1: string): Promise<DistrustOutcome> {
  const wanted = normalizeSha1(sha1);
  if (wanted.length === 0) {
    return { ok: false, code: "invalid_params", message: "sha1 is required" };
  }

  // ── Salvaguarda 1: jamas la propia cadena del agente ──────────────
  //
  // Desconfiar del ancla que sostiene el mTLS del agente seria un
  // suicidio remoto: el equipo dejaria de hablar con el control plane, y
  // sin conexion no se le puede mandar el arreglo. Se comprueba
  // LOCALMENTE contra el fichero de pines de la fase 0, no contra lo que
  // diga el servidor — que es el adversario del que este ADR protege.
  //
  // ⚠️ Los pines se guardan como huella SHA-256 y aqui se opera con
  // SHA-1, asi que la comparacion directa NO vale. Se resuelve mas abajo
  // comparando el PEM localizado contra los pines, una vez se tiene el
  // certificado en la mano.
  const pinned = loadAnchorPins(CERT_DIR);

  let listing: string;
  try {
    const { stdout } = await execFileAsync(
      SECURITY_BIN,
      ["find-certificate", "-a", "-Z", "-p", SYSTEM_KEYCHAIN, SYSTEM_ROOTS_KEYCHAIN],
      { timeout: EXEC_TIMEOUT_MS, maxBuffer: EXEC_MAX_BUFFER }
    );
    listing = stdout;
  } catch (err: any) {
    return { ok: false, code: "keychain_unreadable", message: String(err?.message || err) };
  }

  // ── Salvaguarda 2: tiene que estar presente ───────────────────────
  const found = extractPemBySha1(listing, wanted);
  if (!found) {
    return {
      ok: false,
      code: "anchor_not_present",
      message: "certificate is not in this machine's keychains; nothing to distrust"
    };
  }

  // Ahora si se puede cerrar la salvaguarda 1: se calcula la huella
  // SHA-256 del PEM localizado y se compara con los pines.
  const crypto = await import("crypto");
  const der = Buffer.from(
    found.pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, ""),
    "base64"
  );
  const sha256 = crypto.createHash("sha256").update(der).digest("hex").toLowerCase();
  if (pinned.some((p) => p.toLowerCase() === sha256)) {
    return {
      ok: false,
      code: "anchor_is_own_chain",
      message: "refusing to distrust an anchor this agent's own certificate chain depends on"
    };
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tracenium-distrust-"));
  const certFile = path.join(tempDir, "anchor.crt");
  try {
    fs.writeFileSync(certFile, found.pem, { encoding: "utf8", mode: 0o600 });
    // `-d` = dominio de admin, `-r deny` = marca de DESCONFIANZA. No se
    // borra nada: el certificado sigue en el llavero y el inventario lo
    // seguira viendo, que es correcto — lo que cambia es su confianza.
    await execFileAsync(
      SECURITY_BIN,
      ["add-trusted-cert", "-d", "-r", "deny", "-k", SYSTEM_KEYCHAIN, certFile],
      { timeout: EXEC_TIMEOUT_MS }
    );
    return { ok: true, sha1: wanted, subject: found.subject };
  } catch (err: any) {
    return { ok: false, code: "distrust_failed", message: String(err?.message || err) };
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      /* el temp se pierde, no la operacion */
    }
  }
}
