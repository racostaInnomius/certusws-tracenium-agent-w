// test/privsvc/openssl-compat.ts
//
// ⚠️ DIFERENCIAS ENTRE VERSIONES DE OPENSSL QUE ROMPIERON EL CI.
//
// Estos dos helpers existen por un fallo concreto: las aserciones de los
// CSR híbridos se escribieron mirando el `openssl` de un Mac (3.6), y eso
// convirtió propiedades del CSR en propiedades de ESE OpenSSL. En el
// runner (ubuntu-latest, OpenSSL 3.0.13) se cayeron seis tests —run
// 34064523051, rama Agent-Fixes.
//
// Medido en Ubuntu 24.04 / OpenSSL 3.0.13:
//
//   openssl req -in bueno.pem -verify -noout
//     exit=0  stdout=0 B  stderr=45 B
//     stderr: «Certificate request self-signature verify OK»
//
//   openssl req -in ROTO.pem -verify -noout
//     exit=0                       ← el código de salida NO discrimina
//     stderr: «Certificate request self-signature verify failure»
//
// O sea: en 3.0 el mensaje va a stderr y en 3.6 a stdout, y apoyarse en
// el código de salida daría un test que en CI no comprueba nada. Lo
// único que separa el CSR bueno del roto en las dos versiones es el
// TEXTO del mensaje.
//
// Vive aparte de los dos ficheros de test a propósito: duplicarlo es
// exactamente cómo divergen los árboles paralelos de este repo.

import { spawnSync } from "child_process";

export const OPENSSL = process.env.OPENSSL_BIN || "openssl";

/**
 * Corre `openssl req -verify` y devuelve stdout Y stderr juntos.
 *
 * Se concatenan porque el mensaje cambia de canal según la versión (ver
 * arriba). Quien llama debe asertar sobre el texto —/verify OK/— y NO
 * sobre el código de salida, que en 3.0 es 0 aunque la firma esté rota.
 */
export function opensslVerificaCsr(pemPath: string): string {
  const r = spawnSync(OPENSSL, ["req", "-in", pemPath, "-verify", "-noout"], {
    encoding: "utf8"
  });
  return `${r.stdout || ""}${r.stderr || ""}`;
}

/**
 * ¿Menciona el volcado de `openssl req -text` esta extensión?
 *
 * ⚠️ OpenSSL 3.6 conoce las extensiones catalyst y las rotula por
 * NOMBRE; el 3.0 del runner no las conoce y las imprime por OID.
 *
 * Se acepta cualquiera de las dos formas: lo que se quiere demostrar es
 * que un tercero DECODIFICA la estructura, no cómo la rotula.
 */
export function mencionaExtension(texto: string, oid: string, nombre: string): boolean {
  return texto.includes(oid) || texto.includes(nombre);
}
