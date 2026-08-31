// privsvc/macos/src/cdp-write-guard.ts
//
// ADR-0011 FASE 1 — la defensa, construida ANTES que la capacidad.
//
// ⚠️ NADA INVOCA ESTO TODAVIA, y es deliberado. La fase 3 del ADR
// (`cdp.cert.install`) es quien lo usara. El propio ADR ordena asi las
// fases "porque es la unica forma de que la defensa no se recorte por
// presion de calendario cuando la funcionalidad ya este a medio camino".
//
// Gemelo de CdpWriteGuard.cs. Se mantienen paralelos a proposito: dos
// implementaciones de la misma regla que divergen son peores que una
// sola, porque nadie sabe cual manda.
//
// Implementa las decisiones 1 y 2 del ADR:
//   1. Allowlist de destinos escribibles, que EXCLUYE las anclas.
//   2. Solo se instala lo que ya encadena a un ancla presente, validado
//      contra el trust store LOCAL — un backend comprometido afirmaria
//      que la cadena es buena.

import fs from "fs";
import os from "os";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
const SECURITY_BIN = "/usr/bin/security";
const VERIFY_TIMEOUT_MS = 15000;

/**
 * Los UNICOS destinos escribibles en macOS.
 *
 * `System.keychain` es el llavero de la maquina: ahi vive la identidad
 * de un servicio, y poner un certificado de hoja es la operacion normal.
 *
 * ⚠️ NO esta `SystemRootCertificates.keychain`, que es el bundle que
 * envia Apple —y que ademas SIP protege—, ni ningun mecanismo de trust
 * settings: otorgar confianza es exactamente la amenaza que este ADR
 * existe para gobernar.
 *
 * Se compara la RUTA COMPLETA y no el nombre de fichero: un
 * `System.keychain` colocado en el directorio de un usuario no es el
 * llavero de la maquina, y aceptarlo por parecido de nombre seria
 * regalar el gate.
 */
const WRITABLE_KEYCHAINS = new Set<string>(["/Library/Keychains/System.keychain"]);

export function isWritableKeychain(keychainPath: string | null | undefined): boolean {
  if (typeof keychainPath !== "string" || keychainPath.trim().length === 0) return false;
  return WRITABLE_KEYCHAINS.has(path.normalize(keychainPath.trim()));
}

export type ChainVerdict = { trusted: boolean; reason: string };

/**
 * ¿Encadena este certificado a un ancla que el equipo YA tiene?
 *
 * Se delega en `security verify-cert`, el verificador del propio
 * sistema, en lugar de reimplementar la construccion de cadenas. Dos
 * motivos: reimplementarla es como se cometen los errores sutiles de
 * validacion, y ademas el veredicto que importa es el del SISTEMA —es
 * el que van a aplicar el resto de programas del equipo.
 *
 * ⚠️ La entrada es un PEM que escribe el llamante en un temporal con
 * permisos restringidos. No se acepta una ruta arbitraria del control
 * plane: eso convertiria el gate en un lector de ficheros a peticion.
 */
export async function chainsToInstalledAnchor(
  certPem: string,
  /**
   * Intermedias que acompanan al certificado.
   *
   * ⚠️ Hacen falta. MEDIDO en macOS con un certificado real:
   *   leaf + intermedia -> exit 0   (encadena a una raiz instalada)
   *   solo el leaf      -> exit 1   (falta la intermedia)
   *   autofirmado ajeno -> exit 1   (no encadena, que es lo que se busca)
   * Sin pasarlas, este gate rechazaria TODO — incluido lo legitimo.
   */
  chainPems: string[] = []
): Promise<ChainVerdict> {
  if (typeof certPem !== "string" || !certPem.includes("BEGIN CERTIFICATE")) {
    return { trusted: false, reason: "no se recibio un certificado PEM" };
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tracenium-verify-"));
  try {
    const args: string[] = ["verify-cert"];
    const escribir = (pem: string, nombre: string) => {
      const f = path.join(dir, nombre);
      fs.writeFileSync(f, pem, { encoding: "utf8", mode: 0o600 });
      args.push("-c", f);
    };
    escribir(certPem, "candidate.pem");
    chainPems.forEach((pem, i) => escribir(pem, `chain${i}.pem`));

    // ⚠️ NO se pasa `-l`, y eso importa. `-l` significa "el leaf es una
    // CA (normalmente un error, salvo con esta opcion)" — no significa
    // "solo local", que es lo que yo supuse al escribir esto la primera
    // vez y me corrigio la propia herramienta.
    //
    // Omitirlo es ademas lo correcto aqui: hace que `verify-cert`
    // RECHACE un leaf que sea a su vez una CA, que es exactamente lo que
    // piden las decisiones 1 y 4 del ADR — se instalan hojas, nunca
    // anclas.
    await execFileAsync(SECURITY_BIN, args, { timeout: VERIFY_TIMEOUT_MS });
    return { trusted: true, reason: "la cadena llega a un ancla instalada" };
  } catch (err: any) {
    // `verify-cert` sale con codigo != 0 cuando la cadena no valida. Se
    // reporta su texto: un operador al que se le rechaza una instalacion
    // necesita saber si le falta la intermedia (arreglable) o si la raiz
    // no esta en el equipo, que es el caso que este gate existe para
    // impedir.
    const detalle = String(err?.stderr || err?.message || err).trim().split("\n")[0];
    return { trusted: false, reason: detalle || "la cadena no valida contra el trust store local" };
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* el temporal se pierde, no la decision */
    }
  }
}
