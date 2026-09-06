// privsvc/shared/catalyst.ts
//
// ADR-0015 punto 9 — leer y VERIFICAR la mitad alternativa de un
// certificado ya recibido.
//
// ── QUÉ CERTIFICADO, Y POR QUÉ IMPORTA LA DIRECCIÓN ───────────────────
//
// El backend mira el certificado del AGENTE después del handshake
// (`modules/pki/hybrid-observer.ts`). Esto mira el del SERVIDOR, desde el
// agente. No son la misma comprobación con los papeles cambiados: lo que
// protege ésta es la suplantación del control plane, que es exactamente
// el riesgo que dejó abierto la filtración de la clave de la Issuing —
// cualquiera con esa clave puede presentar un certificado que la CA
// avala. La mitad post-cuántica no estaba en esa filtración.
//
// ── NINGUNA PILA TLS HACE ESTO ────────────────────────────────────────
//
// OpenSSL 3.6 NOMBRA las tres extensiones catalyst al imprimir un
// certificado —lo comprobamos— pero no las verifica. Node y SChannel
// tampoco. O sea que sin este fichero la mitad alternativa del servidor
// no la comprueba nadie y el certificado híbrido es decoración cara.

import { readTlv, children, contentOf, rawOf, seq, tlv, DER_SEQUENCE } from "./der";
import { getMlDsaProvider } from "./mldsa";

const OID_ALT_SPKI = Buffer.from("551d48", "hex"); // 2.5.29.72
const OID_ALT_SIG_VALUE = Buffer.from("551d4a", "hex"); // 2.5.29.74

/** El SEQUENCE de extensiones del TBS, o null si no hay. */
function extensionsOf(certDer: Buffer): ReturnType<typeof children> | null {
  const root = readTlv(certDer, 0);
  if (!root || root.tag !== DER_SEQUENCE) return null;
  const tbs = children(certDer, root)[0];
  if (!tbs) return null;
  const wrapper = children(certDer, tbs).find((c) => c.tag === 0xa3);
  if (!wrapper) return null;
  const extsSeq = readTlv(certDer, wrapper.start);
  if (!extsSeq || extsSeq.tag !== DER_SEQUENCE) return null;
  return children(certDer, extsSeq);
}

/** El valor de una extensión por OID, o null. */
function extensionValue(certDer: Buffer, oid: Buffer): Buffer | null {
  const exts = extensionsOf(certDer);
  if (!exts) return null;
  for (const ext of exts) {
    const cs = children(certDer, ext);
    if (!cs[0] || !contentOf(certDer, cs[0]).equals(oid)) continue;
    // El valor es siempre el ÚLTIMO hijo: el `critical` es opcional y
    // leer por índice fijo se rompería con las extensiones que lo llevan.
    return contentOf(certDer, cs[cs.length - 1]);
  }
  return null;
}

/** La SubjectAltPublicKeyInfo (2.5.29.72) del certificado, o null. */
export function subjectAltSpkiOf(certDer: Buffer): Buffer | null {
  return extensionValue(certDer, OID_ALT_SPKI);
}

/** La firma alternativa (2.5.29.74), sin el octeto de relleno del BIT STRING. */
export function altSignatureValueOf(certDer: Buffer): Buffer | null {
  const v = extensionValue(certDer, OID_ALT_SIG_VALUE);
  if (!v) return null;
  const bits = readTlv(v, 0);
  if (!bits || bits.tag !== 0x03 || bits.length < 2) return null;
  return v.subarray(bits.start + 1, bits.end);
}

/**
 * El TBS **sin** la extensión 74, que es sobre lo que se firmó.
 *
 * ⚠️ El resto se copia BYTE A BYTE del original. Reconstruir los campos
 * anteriores volviéndolos a codificar sería casi lo mismo — y ese «casi»
 * es una firma que no verifica sin que nada parezca mal.
 */
export function tbsWithoutAltSignatureValue(certDer: Buffer): Buffer | null {
  const root = readTlv(certDer, 0);
  if (!root) return null;
  const tbs = children(certDer, root)[0];
  if (!tbs) return null;
  const wrapper = children(certDer, tbs).find((c) => c.tag === 0xa3);
  if (!wrapper) return null;
  const extsSeq = readTlv(certDer, wrapper.start);
  if (!extsSeq || extsSeq.tag !== DER_SEQUENCE) return null;

  const conservadas: Buffer[] = [];
  let habia74 = false;
  for (const ext of children(certDer, extsSeq)) {
    const id = children(certDer, ext)[0];
    if (id && contentOf(certDer, id).equals(OID_ALT_SIG_VALUE)) {
      habia74 = true;
      continue;
    }
    conservadas.push(rawOf(certDer, ext));
  }
  if (!habia74) return null;

  const antesDeExts = certDer.subarray(tbs.start, wrapper.offset);
  return seq(antesDeExts, tlv(0xa3, seq(...conservadas)));
}

/**
 * Qué se vio en el certificado.
 *
 * ⚠️ `unverifiable` NO es `invalid`, y confundirlos sería el falso
 * positivo grande: significa que el certificado trae mitad alternativa y
 * la CA del bundle no tiene con qué comprobarla porque todavía es
 * clásica. Ése es exactamente el estado por el que se pasa mientras la
 * Issuing híbrida no exista.
 */
export type CatalystVerdict = "absent" | "valid" | "invalid" | "unverifiable";

/** El veredicto sobre un certificado, dada la SPKI alternativa de su emisor. */
export function classifyCatalyst(
  certDer: Buffer,
  issuerAltSpki: Buffer | null
): CatalystVerdict {
  let alt: Buffer | null = null;
  try {
    alt = subjectAltSpkiOf(certDer);
  } catch {
    return "absent";
  }
  if (!alt) return "absent";
  if (!issuerAltSpki) return "unverifiable";

  try {
    const cuerpo = tbsWithoutAltSignatureValue(certDer);
    const firma = altSignatureValueOf(certDer);
    if (!cuerpo || !firma) return "invalid";
    return getMlDsaProvider().verify(firma, cuerpo, issuerAltSpki) ? "valid" : "invalid";
  } catch {
    return "invalid";
  }
}

/** Qué pasó con la cadena alternativa entera. */
export type AltChainResult = {
  verdicts: CatalystVerdict[];
  /** Tramos seguidos, desde la hoja, con veredicto `valid`. */
  depth: number;
  anyInvalid: boolean;
};

/**
 * Recorre la mitad alternativa a lo largo de la CADENA, no de un eslabón.
 *
 * ⚠️ ES LO QUE HACE QUE LA ROOT HÍBRIDA (D4) SIRVA DE ALGO. Su clave
 * alternativa sólo compra seguridad si alguien comprueba que la Issuing
 * lleva una firma hecha con ella; su propia autofirma alternativa no la
 * verifica nadie, porque un ancla se confía por estar en el almacén.
 *
 * `chain` va de la HOJA a la RAÍZ. La raíz entra porque de ella sale la
 * clave del último tramo, aunque su autofirma no se comprueba.
 *
 * ⚠️ Devuelve PROFUNDIDAD, no un booleano. Durante la migración la cadena
 * post-cuántica es más corta que la clásica —dos tramos, uno o ninguno
 * según hasta dónde llegó el despliegue— y un verificador de «todo o
 * nada» declararía rota una flota que funciona como se planeó.
 */
export function classifyCatalystChain(chain: readonly Buffer[]): AltChainResult {
  const verdicts: CatalystVerdict[] = [];
  let depth = 0;
  let anyInvalid = false;
  let seguida = true;

  for (let i = 0; i < chain.length - 1; i++) {
    let emisorAlt: Buffer | null = null;
    try {
      emisorAlt = subjectAltSpkiOf(chain[i + 1]);
    } catch {
      emisorAlt = null;
    }
    const v = classifyCatalyst(chain[i], emisorAlt);
    if (v === "invalid") anyInvalid = true;
    if (seguida && v === "valid") depth++;
    else seguida = false;
    verdicts.push(v);
  }

  return { verdicts, depth, anyInvalid };
}

/** Una línea legible para el log: la profundidad es el dato, no un ok/ko. */
export function describeCatalystChain(r: AltChainResult): string {
  if (r.verdicts.length === 0) return "cadena sin tramos que comprobar";
  return `profundidad PQ ${r.depth}/${r.verdicts.length} · ${r.verdicts.join(" → ")}`;
}

/**
 * La SPKI alternativa de la CA, sacada del bundle que el agente ya tiene.
 *
 * ⚠️ Del BUNDLE y no de una variable de configuración nueva. La mitad
 * alternativa de una CA vive en su certificado por definición; un valor
 * aparte podría discrepar del certificado que el equipo usa de verdad, y
 * ese desacuerdo se leería como «el servidor tiene la firma inválida».
 *
 * Se recorren TODOS los certificados del bundle y se devuelve la primera
 * mitad alternativa que aparezca: el bundle lleva la Issuing y puede
 * llevar la Root, y la que firma al servidor es la Issuing.
 */
export function issuerAltSpkiFromBundle(caBundlePem: string): Buffer | null {
  const bloques = String(caBundlePem).match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g
  );
  if (!bloques) return null;

  for (const b of bloques) {
    try {
      const der = Buffer.from(b.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
      const alt = subjectAltSpkiOf(der);
      if (alt) return alt;
    } catch {
      // Un certificado ilegible del bundle no puede tumbar la conexión.
      // Se pasa al siguiente: quedarse sin mitad alternativa degrada a
      // `unverifiable`, que es un veredicto y no un corte.
    }
  }
  return null;
}
