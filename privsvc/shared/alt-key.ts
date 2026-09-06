// privsvc/shared/alt-key.ts
//
// ADR-0015 punto 7 — la clave alternativa ML-DSA-65 del endpoint.
//
// ── DÓNDE VIVE Y POR QUÉ AHÍ ──────────────────────────────────────────
//
// Junto a `client.key.pem`, en el mismo directorio y con los mismos 0600.
// No es comodidad: es que las dos claves son UNA identidad. Separarlas
// abriría el estado en el que un equipo tiene la clásica y no la
// alternativa —o al revés— y ese estado no tiene arreglo automático:
// el certificado ya emitido nombra las dos.
//
// ⚠️ SE ACEPTA POR ESCRITO QUE ESTÁ MENOS PROTEGIDA QUE LA CLÁSICA en las
// plataformas donde la clásica no es un fichero. En macOS y Linux hoy las
// dos son ficheros 0600, así que aquí no hay pérdida; la asimetría real
// aparece en Windows, donde la clásica vive en CNG no exportable y la
// alternativa tendrá que ser software con DPAPI (bloque 3). El ADR lo
// asume: la alternativa era esperar a que Server 2022 salga de la flota.
//
// ── PKCS#8 EN CLARO, Y POR QUÉ NO SE CIFRA AQUÍ ───────────────────────
//
// Porque cifrarlo con una clave que hay que guardar al lado no protege de
// nada y sí añade un modo de fallo: un equipo que pierde la clave de
// cifrado pierde la identidad sin poder decirlo. Lo que protege este
// fichero es el permiso 0600 y que el directorio sea del servicio
// privilegiado — lo mismo que protege a `client.key.pem`, que lleva ahí
// desde el principio con el mismo criterio.

import fs from "fs";
import path from "path";
import { getMlDsaProvider, spkiFromPkcs8, MlDsaKeyPairDer } from "./mldsa";

/** El nombre del fichero, junto a `client.key.pem`. */
export const ALT_KEY_FILENAME = "client.alt-key.pem";

const PEM_HEADER = "-----BEGIN PRIVATE KEY-----";
const PEM_FOOTER = "-----END PRIVATE KEY-----";

export type AltKeyMaterial = {
  pkcs8Der: Buffer;
  spkiDer: Buffer;
  /** `true` si se acaba de generar en esta llamada. */
  generated: boolean;
  path: string;
};

function toPem(pkcs8Der: Buffer): string {
  const b64 = pkcs8Der.toString("base64").replace(/(.{64})/g, "$1\n").trimEnd();
  return `${PEM_HEADER}\n${b64}\n${PEM_FOOTER}\n`;
}

function fromPem(pem: string): Buffer {
  const cuerpo = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  if (!cuerpo) throw new Error("el PEM de la clave alternativa está vacío");
  return Buffer.from(cuerpo, "base64");
}

/** La ruta de la clave alternativa, derivada de la de la clásica. */
export function altKeyPathFor(clientKeyPath: string): string {
  return path.join(path.dirname(clientKeyPath), ALT_KEY_FILENAME);
}

/**
 * Carga la clave alternativa, generándola si no existe.
 *
 * ⚠️ `reuse` importa y su valor por defecto es DELIBERADO. En una
 * renovación se reutiliza —cambiar de clave alternativa obligaría a
 * reemitir por un motivo que no existe— y en un alta desde cero se
 * genera. Es el mismo criterio que `reuseExistingKey` ya aplica a la
 * clásica, y tenerlos distintos produciría el estado partido que el
 * comentario de arriba describe.
 *
 * ⚠️ La SPKI se RECALCULA siempre desde la privada en vez de guardarse
 * aparte. Dos ficheros que pueden discrepar es un desacuerdo esperando
 * ocurrir, y aquí el desacuerdo sería un CSR que declara una clave
 * pública cuya prueba de posesión está firmada con otra: rechazado por el
 * backend, con un mensaje que no señalaría a este fichero.
 */
export function loadOrCreateAltKey(
  clientKeyPath: string,
  opts: { reuse?: boolean } = {}
): AltKeyMaterial {
  const reuse = opts.reuse !== false;
  const p = altKeyPathFor(clientKeyPath);

  if (reuse && fs.existsSync(p)) {
    const pkcs8Der = fromPem(fs.readFileSync(p, "utf8"));
    return { pkcs8Der, spkiDer: spkiFromPkcs8(pkcs8Der), generated: false, path: p };
  }

  const kp: MlDsaKeyPairDer = getMlDsaProvider().generateKeyPair();
  // `mode` en el open y chmod después: el primero no se aplica si el
  // fichero ya existía, y este camino se recorre justamente cuando hay
  // que reemplazar uno viejo.
  fs.writeFileSync(p, toPem(kp.pkcs8Der), { encoding: "utf8", mode: 0o600 });
  fs.chmodSync(p, 0o600);

  return { pkcs8Der: kp.pkcs8Der, spkiDer: kp.spkiDer, generated: true, path: p };
}

/** Borra la clave alternativa. Para el desmantelado del equipo. */
export function destroyAltKey(clientKeyPath: string): boolean {
  const p = altKeyPathFor(clientKeyPath);
  try {
    if (!fs.existsSync(p)) return false;
    fs.rmSync(p, { force: true });
    return true;
  } catch {
    return false;
  }
}
