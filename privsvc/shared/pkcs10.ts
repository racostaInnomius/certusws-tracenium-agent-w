// privsvc/shared/pkcs10.ts
//
// ADR-0015 punto 8 — el CSR híbrido, construido a mano.
//
// ── POR QUÉ NO `openssl req` ──────────────────────────────────────────
//
// Porque no puede. `openssl req` sabe poner extensiones solicitadas desde
// un fichero de configuración, pero la mitad alternativa exige DOS cosas
// que ese camino no da:
//
//   1. La `subjectAltPublicKeyInfo` (2.5.29.72) con una SPKI de ML-DSA,
//      que el `openssl` de macOS ni siquiera sabe construir — es
//      LibreSSL, no conoce el algoritmo.
//   2. Una SEGUNDA firma sobre el propio CertificationRequestInfo, hecha
//      con la clave alternativa, y colocada DENTRO de ese mismo
//      CertificationRequestInfo. Eso es un problema de huevo y gallina
//      que ninguna herramienta de línea de comandos resuelve.
//
// ── EL ORDEN, QUE ES TODO ─────────────────────────────────────────────
//
// La regla catalyst es la misma que en el certificado, y equivocarla no
// produce un error: produce una firma que no verifica.
//
//   a) Se arma el CertificationRequestInfo con las extensiones 72 y 73
//      pero SIN la 74.
//   b) Se firma ESE cuerpo con la clave ML-DSA → altSignatureValue.
//   c) Se vuelve a armar el CertificationRequestInfo, ahora con las tres.
//   d) Se firma el resultado con la clave CLÁSICA → la firma del PKCS#10.
//
// Quien verifica la mitad alternativa tiene que rehacer el paso (a):
// quitar la 74 y firmar sobre lo que queda. Por eso el backend expone
// `csrInfoWithoutAltSignature`, y por eso este fichero y aquél tienen que
// contar la misma historia.
//
// ── NINGÚN OID INVENTADO ──────────────────────────────────────────────
//
// La prueba de posesión alternativa NO viaja en un atributo propio: viaja
// en la 2.5.29.74 dentro del `extensionRequest` estándar
// (1.2.840.113549.1.9.14), que es donde ya van keyUsage, EKU y SAN.
// Tracenium no tiene un Private Enterprise Number registrado, así que
// cualquier OID «nuestro» sería inventado — y un OID inventado en un
// certificado de producción es deuda que no se puede pagar después.
// Comprobado antes de construirlo: OpenSSL 3.6 lee la 72 ahí dentro y el
// CSR sigue verificando su firma clásica.

import crypto from "crypto";
import {
  tlv,
  seq,
  set,
  oidFromHex,
  bitString,
  octetString,
  contextConstructed,
  contextPrimitive,
  DER_INTEGER,
  DER_BOOLEAN
} from "./der";
import { getMlDsaProvider, mlDsaAlgorithmIdentifier } from "./mldsa";

// OIDs, todos estándar.
const OID_EXTENSION_REQUEST = "2a864886f70d01090e"; // 1.2.840.113549.1.9.14
const OID_KEY_USAGE = "551d0f"; // 2.5.29.15
const OID_EKU = "551d25"; // 2.5.29.37
const OID_SAN = "551d11"; // 2.5.29.17
const OID_ALT_SPKI = "551d48"; // 2.5.29.72
const OID_ALT_SIG_ALG = "551d49"; // 2.5.29.73
const OID_ALT_SIG_VALUE = "551d4a"; // 2.5.29.74
const OID_CLIENT_AUTH = "2b06010505070302"; // 1.3.6.1.5.5.7.3.2
const OID_COMMON_NAME = "550403"; // 2.5.4.3

const OID_SHA256_RSA = "2a864886f70d01010b"; // sha256WithRSAEncryption
const OID_ECDSA_SHA256 = "2a8648ce3d040302"; // ecdsa-with-SHA256
const OID_ECDSA_SHA384 = "2a8648ce3d040303"; // ecdsa-with-SHA384

const DER_NULL = Buffer.from([0x05, 0x00]);
const DER_UTF8_STRING = 0x0c;

export type ClassicAlgorithm = "RSA_2048" | "EC_P384";

export type BuildCsrOptions = {
  /** Clave clásica, ya cargada. Es la que firma el PKCS#10. */
  classicKey: crypto.KeyObject;
  classicAlgorithm: ClassicAlgorithm;
  /** CN del sujeto — en la práctica el hostname. */
  commonName: string;
  tenantId: string;
  deviceId: string;
  /** DNS adicional en el SAN. Se omite si coincide con el CN vacío. */
  dnsName?: string;
  /** PKCS#8 de la clave alternativa. Sin él, el CSR sale CLÁSICO. */
  altPrivateKeyPkcs8?: Buffer | null;
  /** SPKI de la clave alternativa. Obligatoria si hay privada. */
  altPublicKeySpki?: Buffer | null;
};

/** Un Name con un solo RDN: CN. */
function nameWithCommonName(cn: string): Buffer {
  return seq(set(seq(oidFromHex(OID_COMMON_NAME), tlv(DER_UTF8_STRING, Buffer.from(cn, "utf8")))));
}

/** Una extensión: SEQUENCE { OID, [critical], OCTET STRING valor }. */
function extension(oidHex: string, critical: boolean, value: Buffer): Buffer {
  return seq(
    oidFromHex(oidHex),
    ...(critical ? [tlv(DER_BOOLEAN, Buffer.from([0xff]))] : []),
    octetString(value)
  );
}

/**
 * El AlgorithmIdentifier de la firma clásica.
 *
 * ⚠️ RSA lleva parámetros NULL y ECDSA NO los lleva. No es una sutileza
 * de estilo: un ECDSA con NULL lo rechazan verificadores estrictos, y un
 * RSA sin NULL también. Se equivoca fácil porque los dos «funcionan» en
 * OpenSSL laxo y fallan en el que importa.
 */
function classicSignatureAlgorithm(alg: ClassicAlgorithm): Buffer {
  if (alg === "RSA_2048") return seq(oidFromHex(OID_SHA256_RSA), DER_NULL);
  return seq(oidFromHex(OID_ECDSA_SHA384));
}

function classicDigest(alg: ClassicAlgorithm): string {
  return alg === "RSA_2048" ? "sha256" : "sha384";
}

/**
 * Las extensiones solicitadas, en el orden en que se escriben.
 *
 * `alt74` va aparte porque en la primera pasada no existe todavía: ése es
 * el paso (a) del orden catalyst.
 */
function requestedExtensions(
  opts: BuildCsrOptions,
  altSpki: Buffer | null,
  alt74: Buffer | null
): Buffer[] {
  const sanEntries: Buffer[] = [];
  if (opts.dnsName) {
    // [2] dNSName, implícito primitivo.
    sanEntries.push(contextPrimitive(2, Buffer.from(opts.dnsName, "ascii")));
  }
  // [6] uniformResourceIdentifier — la identidad que el backend valida.
  sanEntries.push(
    contextPrimitive(
      6,
      Buffer.from(`tracenium://tenant/${opts.tenantId}/device/${opts.deviceId}`, "ascii")
    )
  );

  const exts: Buffer[] = [
    // digitalSignature: un solo bit, 7 sin usar.
    extension(OID_KEY_USAGE, true, tlv(0x03, Buffer.from([0x07, 0x80]))),
    extension(OID_EKU, false, seq(oidFromHex(OID_CLIENT_AUTH))),
    extension(OID_SAN, false, seq(...sanEntries))
  ];

  if (altSpki) {
    exts.push(extension(OID_ALT_SPKI, false, altSpki));
    exts.push(extension(OID_ALT_SIG_ALG, false, mlDsaAlgorithmIdentifier()));
  }
  if (alt74) {
    exts.push(extension(OID_ALT_SIG_VALUE, false, alt74));
  }

  return exts;
}

/** CertificationRequestInfo con las extensiones que se le den. */
function certificationRequestInfo(
  opts: BuildCsrOptions,
  spkiDer: Buffer,
  exts: Buffer[]
): Buffer {
  return seq(
    tlv(DER_INTEGER, Buffer.from([0x00])), // version v1(0)
    nameWithCommonName(opts.commonName),
    spkiDer,
    // attributes [0] IMPLICIT — un solo atributo: extensionRequest.
    contextConstructed(0, seq(oidFromHex(OID_EXTENSION_REQUEST), set(seq(...exts))))
  );
}

export type BuiltCsr = {
  der: Buffer;
  pem: string;
  /** `true` si lleva las tres extensiones catalyst. */
  hybrid: boolean;
};

/**
 * Construye el PKCS#10.
 *
 * Sin `altPrivateKeyPkcs8` sale un CSR clásico bien formado: es lo que
 * hace que este constructor pueda sustituir a `openssl req` en todos los
 * casos y no sólo en el híbrido. Un único camino de código es lo que
 * evita que el clásico —el 100 % de la flota hoy— se pruebe menos.
 */
export function buildCsr(opts: BuildCsrOptions): BuiltCsr {
  const spkiDer = opts.classicKey.type === "private"
    ? (crypto.createPublicKey(opts.classicKey).export({ format: "der", type: "spki" }) as Buffer)
    : (opts.classicKey.export({ format: "der", type: "spki" }) as Buffer);

  const altPriv = opts.altPrivateKeyPkcs8 ?? null;
  const altSpki = opts.altPublicKeySpki ?? null;

  // Media pareja es un error de programación, no un CSR degradado: emitir
  // la SPKI alternativa sin poder firmar la prueba de posesión produce un
  // CSR que el backend RECHAZA por diseño (punto 3). Mejor fallar aquí.
  if ((altPriv && !altSpki) || (!altPriv && altSpki)) {
    throw new Error("clave alternativa incompleta: hacen falta PKCS#8 y SPKI, o ninguna");
  }

  let exts = requestedExtensions(opts, altSpki, null);
  let info = certificationRequestInfo(opts, spkiDer, exts);

  if (altPriv && altSpki) {
    // (b) La firma alternativa cubre el cuerpo SIN la 74…
    const altSig = getMlDsaProvider().sign(info, altPriv);
    // (c) …y después la 74 entra y el cuerpo se rehace.
    exts = requestedExtensions(opts, altSpki, bitString(altSig));
    info = certificationRequestInfo(opts, spkiDer, exts);
  }

  // (d) La firma clásica cubre el cuerpo definitivo.
  const classicSig = crypto.sign(classicDigest(opts.classicAlgorithm), info, opts.classicKey);

  const der = seq(info, classicSignatureAlgorithm(opts.classicAlgorithm), bitString(classicSig));
  const b64 = der.toString("base64").replace(/(.{64})/g, "$1\n").trimEnd();

  return {
    der,
    pem: `-----BEGIN CERTIFICATE REQUEST-----\n${b64}\n-----END CERTIFICATE REQUEST-----\n`,
    hybrid: Boolean(altPriv && altSpki)
  };
}
