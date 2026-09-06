// privsvc/shared/mldsa.ts
//
// ADR-0015 punto 7 — la primitiva ML-DSA-65 del AGENTE.
//
// ── POR QUÉ EN PROCESO Y NO CON EL `openssl` DEL SISTEMA ──────────────
//
// Todo lo demás que hace `crypto-store.ts` sale de `openssl genpkey` /
// `openssl req`. Aquí no se puede, y no por gusto: **el `openssl` de
// macOS es LibreSSL y no conoce ML-DSA**. Un `execFile` fallaría en
// macOS y funcionaría en Linux, o sea la peor forma de fallar — la que
// pasa el desarrollo y aparece en la mitad de la flota.
//
// Node tampoco ayuda todavía: el runtime que empaqueta el agente es
// 22.22.3, y `crypto.generateKeyPairSync("ml-dsa-65")` NO existe ahí
// (comprobado). Existe desde Node 24, así que el proveedor nativo queda
// cableado y se encenderá solo el día que `.nodeversion` suba.
//
// ── LA MONEDA COMÚN ES DER ────────────────────────────────────────────
//
// Igual que en el backend, y por el mismo motivo: los tamaños de la SPKI
// (1.974 B) y del PKCS#8 (4.098 B) coinciden byte a byte entre noble,
// OpenSSL 3.5+ y el `crypto` de Node 24. Hablando DER, lo que produce
// este módulo lo consume el emisor del backend sin conversiones, que es
// justo lo que el CSR híbrido necesita.
//
// ⚠️ Esto es un PUERTO del `modules/pki/mldsa.ts` del backend, no una
// reimplementación. Son repositorios distintos sin paquete común, así que
// la divergencia se vigila con el criterio de aceptación del encargo: el
// CSR que sale de aquí lo tiene que aceptar el validador de allí.

import crypto from "crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import {
  readTlv,
  children,
  seq,
  oidFromHex,
  bitString,
  octetString,
  tlv,
  DER_SEQUENCE,
  DER_OCTET_STRING,
  DER_INTEGER
} from "./der";

/** id-ml-dsa-65, arco CSOR de NIST. */
export const ML_DSA_65_OID = "2.16.840.1.101.3.4.3.18";

/** Tamaños fijos del parámetro 65. Se usan para validar, no para adivinar. */
export const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
export const ML_DSA_65_SIGNATURE_BYTES = 3309;
export const ML_DSA_65_SEED_BYTES = 32;

const ML_DSA_65_OID_HEX = "608648016503040312";
const ML_DSA_65_OID_DER = Buffer.from(ML_DSA_65_OID_HEX, "hex");

export type MlDsaKeyPairDer = {
  /** SubjectPublicKeyInfo completo. */
  spkiDer: Buffer;
  /** PrivateKeyInfo (PKCS#8) completo. */
  pkcs8Der: Buffer;
};

export interface MlDsaProvider {
  /** Para poder decir en un log CUÁL se usó. */
  readonly name: string;
  generateKeyPair(): MlDsaKeyPairDer;
  /** Firma cruda, sin prehash: es lo que exigen altSignatureValue y la PoP. */
  sign(message: Uint8Array, pkcs8Der: Buffer): Buffer;
  verify(signature: Uint8Array, message: Uint8Array, spkiDer: Buffer): boolean;
}

/** AlgorithmIdentifier { id-ml-dsa-65 }, SIN parámetros (ML-DSA no los lleva). */
export function mlDsaAlgorithmIdentifier(): Buffer {
  return seq(oidFromHex(ML_DSA_65_OID_HEX));
}

/** SubjectPublicKeyInfo a partir de la clave pública cruda. */
export function spkiFromRawPublicKey(publicKey: Uint8Array): Buffer {
  if (publicKey.length !== ML_DSA_65_PUBLIC_KEY_BYTES) {
    throw new Error(
      `clave pública ML-DSA-65 de ${publicKey.length} bytes; se esperaban ${ML_DSA_65_PUBLIC_KEY_BYTES}`
    );
  }
  return seq(mlDsaAlgorithmIdentifier(), bitString(Buffer.from(publicKey)));
}

/**
 * La clave pública cruda dentro de una SPKI.
 *
 * Se toman los últimos 1.952 bytes —la SPKI de ML-DSA-65 tiene longitud
 * fija y el BIT STRING es su último elemento— pero se EXIGE el OID antes:
 * sin esa comprobación, una SPKI de otro algoritmo del mismo tamaño
 * pasaría por buena y produciría verificaciones siempre falsas que nadie
 * sabría explicar.
 */
export function rawPublicKeyFromSpki(spkiDer: Buffer): Uint8Array {
  if (!spkiDer.includes(ML_DSA_65_OID_DER)) {
    throw new Error("la SPKI no declara id-ml-dsa-65");
  }
  if (spkiDer.length < ML_DSA_65_PUBLIC_KEY_BYTES) {
    throw new Error(`SPKI de ${spkiDer.length} bytes: demasiado corta para ML-DSA-65`);
  }
  return spkiDer.subarray(spkiDer.length - ML_DSA_65_PUBLIC_KEY_BYTES);
}

/**
 * La semilla de 32 bytes dentro de un PKCS#8 de ML-DSA.
 *
 *   SEQUENCE {
 *     INTEGER 0
 *     SEQUENCE { OID id-ml-dsa-65 }
 *     OCTET STRING {          -- privateKey
 *       SEQUENCE {
 *         OCTET STRING (32)   -- ← la semilla
 *         OCTET STRING        -- la clave expandida
 *       }
 *     }
 *   }
 *
 * ⚠️ Se RECORRE por posición, no se escanea buscando `04 20`. En material
 * de clave privada un desplazamiento leído de más da una clave DISTINTA
 * que firma sin quejarse y que nadie puede verificar: un DER manipulado
 * que colocara un OCTET STRING de 32 bytes donde va la versión se llevaría
 * cualquier búsqueda por etiqueta. La ASN.1 dice qué va en cada sitio.
 */
export function seedFromPkcs8(pkcs8Der: Buffer): Buffer {
  if (!pkcs8Der.includes(ML_DSA_65_OID_DER)) {
    throw new Error("el PKCS#8 no declara id-ml-dsa-65");
  }

  const raiz = readTlv(pkcs8Der, 0);
  if (!raiz || raiz.tag !== DER_SEQUENCE) {
    throw new Error("el PKCS#8 no empieza por un SEQUENCE");
  }

  const nivel1 = children(pkcs8Der, raiz);
  if (nivel1.length < 3) {
    throw new Error("el PKCS#8 no tiene los tres campos de PrivateKeyInfo");
  }
  if (nivel1[0].tag !== DER_INTEGER) {
    throw new Error("el PKCS#8 no empieza por la versión");
  }
  if (nivel1[1].tag !== DER_SEQUENCE) {
    throw new Error("el PKCS#8 no lleva el AlgorithmIdentifier donde debe");
  }
  const privateKey = nivel1[2];
  if (privateKey.tag !== DER_OCTET_STRING) {
    throw new Error("el tercer campo del PKCS#8 no es el OCTET STRING de privateKey");
  }

  const interior = readTlv(pkcs8Der, privateKey.start);
  if (!interior || interior.tag !== DER_SEQUENCE) {
    throw new Error("el privateKey de ML-DSA no contiene el SEQUENCE esperado");
  }

  const semilla = children(pkcs8Der, interior).find(
    (p) => p.tag === DER_OCTET_STRING && p.length === ML_DSA_65_SEED_BYTES
  );
  if (!semilla) {
    throw new Error("no se encontró la semilla de 32 bytes en el PKCS#8");
  }

  return pkcs8Der.subarray(semilla.start, semilla.end);
}

/**
 * La SPKI que corresponde a un PKCS#8.
 *
 * Se reconstruye el par desde la SEMILLA, que es determinista: la misma
 * semilla da siempre la misma pública. Existe para que la clave pública
 * no haya que guardarla en un segundo fichero — dos ficheros que pueden
 * discrepar son un desacuerdo esperando ocurrir, y aquí el desacuerdo
 * sería un CSR que declara una clave y firma la prueba de posesión con
 * otra: rechazado por el backend con un mensaje que no señalaría a la
 * causa.
 */
export function spkiFromPkcs8(pkcs8Der: Buffer): Buffer {
  const kp = ml_dsa65.keygen(seedFromPkcs8(pkcs8Der));
  return spkiFromRawPublicKey(kp.publicKey);
}

/** PKCS#8 a partir de una semilla, en la misma forma que emite OpenSSL. */
export function pkcs8FromSeed(seed: Buffer, secretKey: Uint8Array): Buffer {
  const inner = seq(octetString(seed), octetString(Buffer.from(secretKey)));
  return seq(
    tlv(DER_INTEGER, Buffer.from([0x00])),
    mlDsaAlgorithmIdentifier(),
    octetString(inner)
  );
}

// ── Proveedor en JS puro ──────────────────────────────────────────────

const nobleProvider: MlDsaProvider = {
  name: "noble/post-quantum@0.7.1",

  generateKeyPair(): MlDsaKeyPairDer {
    const seed = crypto.randomBytes(ML_DSA_65_SEED_BYTES);
    const kp = ml_dsa65.keygen(seed);
    return {
      spkiDer: spkiFromRawPublicKey(kp.publicKey),
      pkcs8Der: pkcs8FromSeed(seed, kp.secretKey)
    };
  },

  sign(message: Uint8Array, pkcs8Der: Buffer): Buffer {
    // Se reconstruye desde la SEMILLA en vez de leer la clave expandida:
    // así una clave generada por OpenSSL —o por el Node nativo del día de
    // mañana— funciona aquí sin depender de dónde coloque exactamente los
    // 4.032 bytes expandidos.
    const kp = ml_dsa65.keygen(seedFromPkcs8(pkcs8Der));
    // ⚠️ La API de noble 0.7 es sign(mensaje, secreta). En versiones
    // anteriores el orden era el contrario, y equivocarlo NO da error de
    // tipos: da una firma que nadie puede verificar.
    return Buffer.from(ml_dsa65.sign(message, kp.secretKey));
  },

  verify(signature: Uint8Array, message: Uint8Array, spkiDer: Buffer): boolean {
    try {
      return ml_dsa65.verify(signature, message, rawPublicKeyFromSpki(spkiDer));
    } catch {
      // Una firma de longitud equivocada o una SPKI ilegible son «no
      // verifica». Lanzar aquí rompería la verificación del servidor, que
      // corre dentro de `checkServerIdentity` y no puede tirar la conexión
      // en modo observación.
      return false;
    }
  }
};

// ── Proveedor nativo (Node ≥ 24), cableado y dormido ──────────────────

let nativeAvailable: boolean | null = null;

/**
 * ¿Trae este runtime ML-DSA en `crypto`?
 *
 * Hoy la respuesta es NO: el agente empaqueta Node 22.22.3. Está escrito
 * para que el día que `.nodeversion` suba a 24 el cambio sea de cero
 * líneas — y para que el interruptor exista si el nativo diera guerra.
 */
export function hasNativeMlDsa(): boolean {
  if (nativeAvailable !== null) return nativeAvailable;
  try {
    crypto.generateKeyPairSync("ml-dsa-65" as never);
    nativeAvailable = true;
  } catch {
    nativeAvailable = false;
  }
  return nativeAvailable;
}

const nativeProvider: MlDsaProvider = {
  name: `node:${process.versions.node}`,

  generateKeyPair(): MlDsaKeyPairDer {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ml-dsa-65" as never);
    return {
      spkiDer: publicKey.export({ format: "der", type: "spki" }) as Buffer,
      pkcs8Der: privateKey.export({ format: "der", type: "pkcs8" }) as Buffer
    };
  },

  sign(message: Uint8Array, pkcs8Der: Buffer): Buffer {
    const key = crypto.createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
    return crypto.sign(null, Buffer.from(message), key);
  },

  verify(signature: Uint8Array, message: Uint8Array, spkiDer: Buffer): boolean {
    try {
      const key = crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
      return crypto.verify(null, Buffer.from(message), key, Buffer.from(signature));
    } catch {
      return false;
    }
  }
};

/**
 * El proveedor de este proceso.
 *
 * `TRACENIUM_MLDSA_PROVIDER=noble|native` fuerza uno. El forzado MANDA
 * sobre la autodetección: es lo que permite comparar las dos
 * implementaciones sobre los mismos vectores, y lo que deja una salida si
 * el nativo resultara peor que el puro.
 */
export function getMlDsaProvider(): MlDsaProvider {
  const forzado = String(process.env.TRACENIUM_MLDSA_PROVIDER || "").trim().toLowerCase();
  if (forzado === "noble") return nobleProvider;
  if (forzado === "native") return nativeProvider;
  return hasNativeMlDsa() ? nativeProvider : nobleProvider;
}
