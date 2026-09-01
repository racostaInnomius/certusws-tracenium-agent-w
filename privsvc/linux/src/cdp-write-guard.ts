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
 * ✅ VERIFICADO en un Ubuntu 26.04 real (OpenSSL 3.5), ejecutando este
 * mismo modulo con el Node que empaqueta el agente:
 *   leaf + intermedia -> trusted        (encadena a una raiz instalada)
 *   solo el leaf      -> no             (falta la intermedia)
 *   autofirmado ajeno -> no             (lo que este gate busca impedir)
 *   basura            -> no
 *
 * ⚠️ Y una trampa que costo dos intentos: `openssl verify` SI devuelve
 * codigo != 0 al fallar, pero medirlo con una tuberia (`| head`) da el
 * codigo del ULTIMO comando y parece que siempre sale 0. Con esa lectura
 * equivocada, este guard habria aprobado un autofirmado.
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
    // El motivo util esta en STDOUT, no en stderr. MEDIDO en Ubuntu
    // 26.04 con OpenSSL 3.5 contra un host real:
    //   stdout: "error 20 at 0 depth lookup: unable to get local issuer
    //            certificate"  -> falta la intermedia: ARREGLABLE
    //   stdout: "error 18 at 0 depth lookup: self-signed certificate"
    //            -> la raiz no esta: el caso que este gate existe para
    //            impedir
    //   stderr: "error <ruta>: verification failed"  -> generico, inutil
    //
    // La primera version se quedaba con el generico y perdia justo la
    // distincion que hace accionable el rechazo.
    const salida = `${err?.stdout || ""}\n${err?.stderr || ""}`;
    const lineaUtil = salida
      .split("\n")
      .map((l: string) => l.trim())
      .find((l: string) => /^error \d+ at/.test(l));
    return {
      trusted: false,
      reason:
        lineaUtil ||
        String(err?.stderr || err?.message || err).trim().split("\n")[0] ||
        "la cadena no valida contra el trust store local"
    };
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* el temporal se pierde, no la decision */
    }
  }
}
