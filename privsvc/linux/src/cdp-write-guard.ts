// privsvc/linux/src/cdp-write-guard.ts
//
// ADR-0011 FASE 1 — la defensa, construida ANTES que la capacidad.
//
// ⚠️ NADA INVOCA ESTO TODAVIA, y es deliberado. Gemelo de
// CdpWriteGuard.cs (Windows) y de cdp-write-guard.ts (macOS): se
// mantienen paralelos a proposito, porque dos implementaciones de la
// misma regla que divergen son peores que una sola.
//
// ⚠️ Linux parte de una situacion distinta y MEJOR que las otras dos: su
// crypto-store NUNCA instala anclas del sistema, por decision deliberada
// y documentada (`update-ca-trust` / `update-ca-certificates` no se
// llaman nunca). Eso quedo verificado en el gate 1 del ADR. Este guard
// existe para que la fase 3 encuentre la misma barrera en las tres
// plataformas, no porque aqui haya un agujero que tapar.

import fs from "fs";
import os from "os";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
const OPENSSL_BIN = "/usr/bin/openssl";
const VERIFY_TIMEOUT_MS = 15000;

/**
 * Los UNICOS destinos escribibles en Linux.
 *
 * Directorios de configuracion de servicio, donde poner el PEM de un
 * servicio es la operacion normal.
 *
 * ⚠️ NO estan los directorios de anclas del sistema —
 * `/usr/local/share/ca-certificates`, `/etc/pki/ca-trust/source/anchors`
 * ni `/etc/ssl/certs`—: escribir ahi (y correr update-ca-*) es otorgar
 * confianza, que es la amenaza que este ADR gobierna.
 */
const WRITABLE_DIRS = [
  "/etc/nginx",
  "/etc/haproxy",
  "/etc/apache2",
  "/etc/httpd",
  "/etc/letsencrypt/live",
  "/etc/tracenium/certs"
];

export function isWritablePath(target: string | null | undefined): boolean {
  if (typeof target !== "string" || target.trim().length === 0) return false;
  const p = path.resolve(target.trim());
  // `path.resolve` normaliza los `..`, asi que una ruta como
  // "/etc/nginx/../ssl/certs" no puede colarse por parecerse a una
  // permitida. Se exige ademas el separador para que "/etc/nginx-evil"
  // no pase por ser prefijo de "/etc/nginx".
  return WRITABLE_DIRS.some((dir) => p === dir || p.startsWith(dir + path.sep));
}

export type ChainVerdict = { trusted: boolean; reason: string };

/**
 * ¿Encadena a un ancla que el equipo YA tiene?
 *
 * Se delega en `openssl verify` contra el almacen de la distro en vez de
 * reimplementar la construccion de cadenas: reimplementarla es como se
 * cometen los errores sutiles de validacion, y el veredicto que importa
 * es el que aplicara el resto del sistema.
 *
 * ⚠️ SIN salida a la red. `openssl verify` no busca eslabones por AIA,
 * asi que la respuesta es "este equipo ya confia en esto" y no "internet
 * dice que esta bien" — que es lo que pide la decision 2.
 *
 * ⚠️ NO verificado en un Linux real: esta Mac no tiene uno. La forma se
 * copio de la de macOS, que si se probo en vivo (leaf+intermedia -> ok,
 * leaf solo -> no, autofirmado ajeno -> no). Conviene repetir esa
 * comprobacion en un endpoint Linux antes de que la fase 3 dependa de
 * esto.
 */
export async function chainsToInstalledAnchor(
  certPem: string,
  chainPems: string[] = []
): Promise<ChainVerdict> {
  if (typeof certPem !== "string" || !certPem.includes("BEGIN CERTIFICATE")) {
    return { trusted: false, reason: "no se recibio un certificado PEM" };
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tracenium-verify-"));
  try {
    const leaf = path.join(dir, "candidate.pem");
    fs.writeFileSync(leaf, certPem, { encoding: "utf8", mode: 0o600 });

    const args = ["verify"];
    if (chainPems.length > 0) {
      const untrusted = path.join(dir, "chain.pem");
      fs.writeFileSync(untrusted, chainPems.join("\n"), { encoding: "utf8", mode: 0o600 });
      args.push("-untrusted", untrusted);
    }
    args.push(leaf);

    await execFileAsync(OPENSSL_BIN, args, { timeout: VERIFY_TIMEOUT_MS });
    return { trusted: true, reason: "la cadena llega a un ancla instalada" };
  } catch (err: any) {
    const detalle = String(err?.stdout || err?.stderr || err?.message || err)
      .trim()
      .split("\n")
      .filter(Boolean)
      .pop();
    return { trusted: false, reason: detalle || "la cadena no valida contra el trust store local" };
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* el temporal se pierde, no la decision */
    }
  }
}
