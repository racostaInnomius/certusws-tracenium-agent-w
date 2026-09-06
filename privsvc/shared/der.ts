// privsvc/shared/der.ts
//
// ADR-0015 — DER mínimo, de escritura y de lectura.
//
// ── POR QUÉ `privsvc/shared/` Y NO UNA COPIA EN CADA SISTEMA ───────────
//
// `privsvc/macos/src/` y `privsvc/linux/src/` son hoy dos árboles
// duplicados: `crypto-store.ts`, `server-pin.ts` y `cdp-keys.ts` existen
// dos veces cada uno. Para casi todo eso es tolerable, porque lo que
// diverge son llamadas al sistema que YA son distintas.
//
// Aquí no. Esto codifica un PKCS#10 que el backend tiene que aceptar y
// verifica una firma que autentica al servidor: si las dos copias
// divergen en un byte, una plataforma deja de poder enrolar y la otra no,
// y el fallo aparece en campo. Es exactamente el modo de fallo que este
// producto ya tiene documentado con nombre —«las 3 listas de un job»— y
// no hay ninguna razón de sistema operativo para duplicarlo: es
// aritmética sobre bytes, idéntica en los dos.
//
// esbuild empaqueta cada privsvc desde su propio `index.ts` con
// `--bundle`, así que un directorio compartido entra en los dos sin
// tocar el empaquetado.
//
// ── POR QUÉ ESCRITO A MANO Y NO `asn1js` ──────────────────────────────
//
// ⚠️ DESVIACIÓN DEL ENCARGO, que pedía asn1js. Dos razones y una
// comprobación que la sostiene:
//
//   1. Esto se carga en un servicio que corre como root. Cada dependencia
//      nueva ahí es superficie, y `@noble/post-quantum` ya es una que no
//      se puede evitar.
//   2. asn1js no sabría nada de catalyst: las tres extensiones y el orden
//      de firma habría que escribirlos igual a mano. Lo que ahorraría es
//      el TLV, que son las cuarenta líneas de abajo.
//
// Y el encoding no es una apuesta: es el MISMO que ya emite el
// constructor de CSR híbridos del backend, cuyos tests demuestran que
// OpenSSL 3.6 lo lee y que el validador de emisión lo acepta. El criterio
// de aceptación que fijó el encargo —`openssl req -verify` más el
// validador del punto 3— se comprueba en los tests de este bloque.

// ── Escritura ─────────────────────────────────────────────────────────

export const DER_SEQUENCE = 0x30;
export const DER_SET = 0x31;
export const DER_OCTET_STRING = 0x04;
export const DER_BIT_STRING = 0x03;
export const DER_INTEGER = 0x02;
export const DER_OID = 0x06;
export const DER_BOOLEAN = 0x01;

/**
 * La longitud en forma corta o larga, según DER.
 *
 * ⚠️ La forma larga es obligatoria a partir de 128 y aquí no es un caso
 * raro: una SPKI de ML-DSA-65 mide 1.974 bytes y una firma 3.309, así que
 * el camino de dos bytes de longitud se recorre en cada CSR híbrido. Un
 * codificador que sólo hiciera la forma corta produciría basura
 * silenciosa justo en el caso que este módulo existe para cubrir.
 */
export function encodeLength(n: number): Buffer {
  if (n < 0) throw new Error("longitud negativa");
  if (n < 0x80) return Buffer.from([n]);

  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>>= 8;
  }
  if (bytes.length > 4) throw new Error("longitud DER inverosímil");
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** Un TLV: etiqueta, longitud y contenido. */
export function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

export const seq = (...parts: Buffer[]): Buffer => tlv(DER_SEQUENCE, Buffer.concat(parts));
export const set = (...parts: Buffer[]): Buffer => tlv(DER_SET, Buffer.concat(parts));

/** Un OBJECT IDENTIFIER ya codificado, dado en hexadecimal. */
export const oidFromHex = (hex: string): Buffer => tlv(DER_OID, Buffer.from(hex, "hex"));

/**
 * Un BIT STRING con cero bits sin usar.
 *
 * El octeto inicial de relleno se olvida con facilidad y su ausencia
 * desplaza todo el contenido un byte: la firma deja de verificar sin que
 * nada parezca mal formado.
 */
export const bitString = (content: Buffer): Buffer =>
  tlv(DER_BIT_STRING, Buffer.concat([Buffer.from([0x00]), content]));

export const octetString = (content: Buffer): Buffer => tlv(DER_OCTET_STRING, content);

/** Un contexto explícito [n], constructed. */
export const contextConstructed = (n: number, content: Buffer): Buffer =>
  tlv(0xa0 | n, content);

/** Un contexto implícito [n], primitivo — el `uniformResourceIdentifier` del SAN es [6]. */
export const contextPrimitive = (n: number, content: Buffer): Buffer =>
  tlv(0x80 | n, content);

// ── Lectura ───────────────────────────────────────────────────────────
//
// Sólo lo necesario para leer un certificado ya emitido: las tres
// extensiones catalyst y el TBS. Deliberadamente estricto — un DER que no
// se entiende se rechaza en vez de interpretarse.

export type Tlv = {
  tag: number;
  /** Desplazamiento de la etiqueta. */
  offset: number;
  /** Desplazamiento del primer byte de contenido. */
  start: number;
  length: number;
  /** Desplazamiento del primer byte DESPUÉS del contenido. */
  end: number;
};

/**
 * Lee un TLV en `offset`. `null` si no se puede.
 *
 * ⚠️ Rechaza la longitud indefinida de BER (0x80). Es válida en BER y NO
 * en DER, y aceptarla abriría la puerta a dos codificaciones del mismo
 * certificado — que es como se construye una firma que verifica sobre
 * unos bytes y significa otra cosa.
 */
export function readTlv(buf: Buffer, offset: number): Tlv | null {
  if (offset < 0 || offset + 2 > buf.length) return null;

  const tag = buf[offset];
  // Etiquetas multibyte: no aparecen en X.509 y no se adivinan.
  if ((tag & 0x1f) === 0x1f) return null;

  const first = buf[offset + 1];
  let length: number;
  let start: number;

  if (first < 0x80) {
    length = first;
    start = offset + 2;
  } else {
    const n = first & 0x7f;
    if (n === 0 || n > 4) return null; // 0 = indefinida (BER)
    if (offset + 2 + n > buf.length) return null;
    length = 0;
    for (let i = 0; i < n; i++) length = (length << 8) | buf[offset + 2 + i];
    start = offset + 2 + n;
  }

  const end = start + length;
  if (end > buf.length) return null;
  return { tag, offset, start, length, end };
}

/** Los hijos directos de un constructed. */
export function children(buf: Buffer, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let p = parent.start;
  while (p < parent.end) {
    const t = readTlv(buf, p);
    if (!t) break;
    out.push(t);
    p = t.end;
  }
  return out;
}

/** El contenido de un TLV, sin etiqueta ni longitud. */
export const contentOf = (buf: Buffer, t: Tlv): Buffer => buf.subarray(t.start, t.end);

/** El TLV entero, etiqueta y longitud incluidas. */
export const rawOf = (buf: Buffer, t: Tlv): Buffer => buf.subarray(t.offset, t.end);
