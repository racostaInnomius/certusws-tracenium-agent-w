// privsvc/macos/src/keystore.ts
//
// ADR-0011 decision 9.b — el almacen de claves NO EXTRAIBLES de macOS.
//
// Envoltorio del helper `tracenium-keystore`. Toda la sustancia —y el
// porque de que haga falta un binario nativo en vez del CLI `security`—
// esta en `helpers/keystore/main.swift`. Resumen de una linea: se midio
// que `security import -x` NO hace la clave no extraible, y la unica via
// que funciona es crearla dentro del llavero y no dejar que exista fuera.
//
// ⚠️ NADIE LLAMA A ESTO TODAVIA, igual que los guards de la fase 1 del
// mismo ADR. No es un olvido de cableado; es que la clave de identidad
// del PROPIO agente no puede mudarse aqui. Ver `crypto-store.ts`, bloque
// «System Keychain — client identity»: hay cinco consumidores en macOS
// que necesitan los BYTES de la clave —`grpc.credentials.createSsl`,
// el `https.request` de la renovacion, `crypto.createPrivateKey` del
// credential-store, el mTLS del distribution point, y un `curl --key`
// que ni siquiera admite otra cosa que una RUTA—. Una clave que no sale
// del llavero no puede alimentar a ninguno.
//
// Eso reencuadra la deuda que el ADR daba por «de macOS»: no lo es. Es
// del transporte. Windows se libra porque su puente es C# y SChannel
// firma con un handle de CNG sin ver la clave; macOS y Linux van por
// grpc-js, que solo entiende buffers. Mientras el transporte sea ese, la
// identidad del agente seguira siendo un fichero en las dos.
//
// Lo que este modulo SI cierra es lo que la fase 2 necesita: un almacen
// donde las claves que emita `cdp.csr.generate` —nuevas, sin ese lastre—
// nazcan no extraibles, con nombre, y por tanto borrables (decision 9.c).

import fs from "fs";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

/** El llavero de la maquina. Mismo destino que el resto del PrivSvc. */
export const SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain";

/**
 * Tope de espera de cada invocacion.
 *
 * Generar RSA-2048 tarda decimas de segundo, pero el llavero puede
 * quedarse esperando un dialogo que en un demonio sin sesion grafica no
 * va a contestar nadie. Un tope convierte ese cuelgue en un fallo, que
 * es lo unico que un servicio privilegiado puede permitirse.
 *
 * ⚠️ Vale el invariante de siempre: job > cliente IPC > este tope.
 */
const HELPER_TIMEOUT_MS = 30_000;

/** Donde el paquete deja el helper. */
export function keystoreHelperPath(): string {
  return (
    process.env.TRACENIUM_KEYSTORE_BIN ||
    path.join("/Library/Application Support/Tracenium/PrivSvc/macos", "tracenium-keystore")
  );
}

export function keystoreAvailable(): boolean {
  try {
    return fs.existsSync(keystoreHelperPath());
  } catch {
    return false;
  }
}

export type KeystoreResult = { ok: boolean; code?: string; message?: string; [k: string]: any };

/**
 * Invoca el helper y devuelve su unica linea JSON.
 *
 * ⚠️ El helper sale con codigo != 0 cuando responde `ok:false`, asi que
 * el JSON llega por la rama de error de execFile. Se parsea IGUAL en las
 * dos ramas: quedarse con el mensaje generico de execFile perderia el
 * `code` estable, que es lo unico sobre lo que el llamante puede
 * ramificar. Es el mismo error que ya se cometio en el guard de Linux.
 */
async function run(args: string[]): Promise<KeystoreResult> {
  const bin = keystoreHelperPath();
  if (!keystoreAvailable()) {
    return { ok: false, code: "helper_missing", message: `no esta ${bin}` };
  }
  let salida = "";
  try {
    const { stdout } = await execFileAsync(bin, args, { timeout: HELPER_TIMEOUT_MS });
    salida = stdout;
  } catch (err: any) {
    salida = String(err?.stdout || "");
    if (!salida.trim()) {
      return {
        ok: false,
        code: "helper_failed",
        message: String(err?.stderr || err?.message || err).trim().split("\n")[0]
      };
    }
  }
  try {
    return JSON.parse(salida.trim().split("\n").pop() || "");
  } catch {
    return { ok: false, code: "helper_bad_output", message: salida.trim().slice(0, 200) };
  }
}

function baseArgs(label: string, keychain?: string): string[] {
  return ["--label", label, "--keychain", keychain || SYSTEM_KEYCHAIN];
}

/**
 * Crea la clave si no existe. Idempotente: si ya hay una con esa
 * etiqueta se devuelve `created:false` y NO se regenera — regenerar en
 * silencio invalidaria el certificado que ya la esta usando.
 */
export function createKey(label: string, opts?: { bits?: number; keychain?: string }) {
  return run([
    "create",
    ...baseArgs(label, opts?.keychain),
    ...(opts?.bits ? ["--bits", String(opts.bits)] : [])
  ]);
}

/**
 * Estado de la clave.
 *
 * `extractable` no se deduce de como se creo: el helper INTENTA sacarla,
 * que es lo mismo que haria un atacante. Una propiedad de seguridad que
 * solo se afirma no esta comprobada.
 */
export function keyInfo(label: string, keychain?: string) {
  return run(["info", ...baseArgs(label, keychain)]);
}

/**
 * CSR firmado por la clave del llavero.
 *
 * Las extensiones son las mismas que emite hoy la ruta de `openssl req`
 * (keyUsage critica digitalSignature, EKU, SAN), para que el CSR sea
 * intercambiable con el que la CA ya firma.
 */
export function generateCsr(
  label: string,
  subject: string,
  opts?: { dns?: string; uri?: string; eku?: "clientAuth" | "serverAuth"; keychain?: string }
) {
  return run([
    "csr",
    ...baseArgs(label, opts?.keychain),
    "--subject", subject,
    ...(opts?.dns ? ["--dns", opts.dns] : []),
    ...(opts?.uri ? ["--uri", opts.uri] : []),
    ...(opts?.eku ? ["--eku", opts.eku] : [])
  ]);
}

/**
 * Destruye la clave. Decision 9.c: destruye quien creo, y en TODA salida
 * terminal — fallo de firma, timeout, cancelacion, y aprobacion denegada
 * o caducada.
 *
 * El helper borra en bucle y despues COMPRUEBA que no queda: un par RSA
 * son dos items en el llavero y una sola llamada de borrado devuelve
 * exito dejando la clave privada dentro. Ese falso verde se midio.
 */
export function deleteKey(label: string, keychain?: string) {
  return run(["delete", ...baseArgs(label, keychain)]);
}
