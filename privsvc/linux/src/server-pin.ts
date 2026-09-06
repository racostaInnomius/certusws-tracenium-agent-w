// server-pin.ts
//
// Fijación (pinning) de la clave pública del control plane.
//
// ── Por qué ─────────────────────────────────────────────────────────────
// El agente valida al servidor contra la CA: `createSsl(caBundle, …)`. Eso
// significa que CUALQUIER certificado firmado por esa CA se acepta como el
// control plane. La clave privada de esa CA llegó a estar publicada dentro
// de una imagen pública de Docker Hub, junto con la del propio servidor
// gRPC — así que quien pueda situarse en el camino de red (DNS, WiFi
// hostil, upstream comprometido) presentaría un certificado válido, y el
// agente le entregaría su telemetría y aceptaría sus comandos.
//
// Se fija la CLAVE PÚBLICA y no el certificado: así la renovación no rompe
// nada mientras se conserve el par de claves, que es la práctica normal.
// El valor es el mismo que produce
// `openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`.
//
// ── Por qué NO viene activado por defecto ───────────────────────────────
// Un pin equivocado deja al equipo sin poder conectar — y sin conexión no
// hay manera de mandarle el arreglo: se convierte en una visita presencial.
// Con la lista vacía el comportamiento es el de siempre y además se
// REGISTRA el pin observado, que es como el operador averigua el valor que
// tendrá que configurar. Encenderlo pasa a ser una decisión con el dato
// delante en vez de una apuesta.

import { createHash, X509Certificate } from "crypto";
import { checkServerIdentity as defaultCheckServerIdentity } from "tls";
import { classifyCatalystChain, describeCatalystChain, CatalystVerdict } from "../../shared/catalyst";

export interface PinnableCertificate {
  /** SPKI en DER, tal como la entrega Node en `getPeerCertificate()`. */
  pubkey?: Buffer;
  /** DER del certificado completo; respaldo si `pubkey` no viniera. */
  raw?: Buffer;
  /**
   * El emisor, que Node encadena aquí.
   *
   * ⚠️ En la RAÍZ este campo apunta a SÍ MISMO — Node no lo deja en
   * `undefined`— así que recorrerlo sin cortar es un bucle infinito. Ver
   * `cadenaDe`.
   */
  issuerCertificate?: PinnableCertificate;
}

/**
 * La cadena en DER, de la hoja a la raíz, siguiendo `issuerCertificate`.
 *
 * ⚠️ DOS CORTES, Y HACEN COSAS DISTINTAS. Lo escribo separado porque mi
 * primera versión los confundió en un solo comentario, y el test que
 * escribí medía la propiedad equivocada:
 *
 *   · El conjunto `vistos` es el que MANDA. Node hace que la raíz se
 *     apunte a sí misma como emisora, así que una parada por «llegué a
 *     undefined» no llegaría nunca — y, más importante, sin él la raíz
 *     entraría varias veces y `classifyCatalystChain` verificaría tramos
 *     raíz←raíz, informando de una profundidad post-cuántica que no
 *     existe. Un número inventado justo donde el número es lo único que
 *     sirve para decidir cuándo exigir. Hay test que lo fija.
 *
 *   · El tope de 10 es cinturón sobre tirantes, y se queda dicho como
 *     tal: con `vistos` cualquier ciclo termina, así que este tope sólo
 *     acotaría una cadena de más de diez certificados DISTINTOS, que Node
 *     no produce. Ningún test lo distingue y no pretendo que lo haga.
 */
function cadenaDe(cert: PinnableCertificate | undefined): Buffer[] {
  const out: Buffer[] = [];
  const vistos = new Set<string>();
  let actual = cert;

  while (actual && Buffer.isBuffer(actual.raw) && out.length < 10) {
    const clave = actual.raw.toString("base64");
    if (vistos.has(clave)) break;
    vistos.add(clave);
    out.push(actual.raw);
    actual = actual.issuerCertificate;
  }
  return out;
}

/** SHA-256 de la SubjectPublicKeyInfo, en base64. `null` si no se puede leer. */
export function publicKeyPin(cert: PinnableCertificate | null | undefined): string | null {
  if (!cert) return null;

  let spki: Buffer | null = Buffer.isBuffer(cert.pubkey) ? cert.pubkey : null;

  if (!spki && Buffer.isBuffer(cert.raw)) {
    try {
      spki = new X509Certificate(cert.raw).publicKey.export({
        type: "spki",
        format: "der",
      }) as Buffer;
    } catch {
      // Node no exporta claves cuyo algoritmo no modela. Sin pin legible se
      // devuelve null y decide quien llame; adivinar sería peor.
      spki = null;
    }
  }

  if (!spki || spki.length === 0) return null;
  return createHash("sha256").update(spki).digest("base64");
}

export type ObservePin = (pin: string | null, hostname: string) => void;

/**
 * ADR-0015 punto 9 — qué mitad alternativa traía el servidor.
 *
 * ⚠️ OBSERVAR, NUNCA CORTAR, y por la misma razón que el pin: hoy no
 * existe una Issuing híbrida, así que NINGÚN servidor puede presentar una
 * mitad alternativa válida todavía. Un modo que exigiera algo dejaría a
 * la flota entera sin canal — y sin canal no hay forma de mandarle el
 * arreglo, que es una visita presencial por equipo.
 *
 * Lo que sí se puede hacer desde ya es REGISTRAR lo que se ve, que es
 * como se averigua cuándo se puede exigir sin apostar.
 */
export type ObserveCatalyst = (resumen: string, hostname: string) => void;

/**
 * Construye el `checkServerIdentity` para `grpc.credentials.createSsl`.
 *
 * ⚠️ Trampa que este código evita: pasar un `checkServerIdentity` propio
 * **SUSTITUYE** al de Node, que es quien comprueba que el certificado
 * corresponde al nombre al que nos conectamos. Un pinning que se limitara
 * a mirar el pin habría QUITADO la verificación de hostname — debilitando
 * la conexión mientras aparenta reforzarla. Por eso lo primero que se hace
 * es delegar en el de Node y sólo después comprobar el pin.
 */
export function makeCheckServerIdentity(
  pins: readonly string[] = [],
  observe?: ObservePin,
  catalyst?: { issuerAltSpki: Buffer | null; observe?: ObserveCatalyst },
): (hostname: string, cert: PinnableCertificate) => Error | undefined {
  const allowed = new Set(pins.map((p) => String(p).trim()).filter(Boolean));

  return (hostname: string, cert: PinnableCertificate): Error | undefined => {
    // 1. Lo que Node haría por su cuenta. No se salta nunca.
    const identityError = defaultCheckServerIdentity(hostname, cert as never);
    if (identityError) return identityError;

    // 1.b La mitad alternativa (ADR-0015). Va DESPUÉS de la verificación
    // de identidad y ANTES del pin, y su resultado no participa en el
    // valor de retorno: se mira y se cuenta. Envuelto porque un fallo
    // observando no puede tirar una conexión que por lo demás es válida.
    if (catalyst && cert?.raw) {
      try {
        // La CADENA, no la hoja: el tramo Issuing←Root es la razón entera
        // de que la Root sea híbrida (D4), y no se ve mirando un eslabón.
        // Si Node no encadenó nada, queda un solo certificado y el
        // resultado son cero tramos — que se dice, no se calla.
        const cadena = cadenaDe(cert);
        catalyst.observe?.(describeCatalystChain(classifyCatalystChain(cadena)), hostname);
      } catch {
        // Ni siquiera se registra: no hay nada que decir y este camino
        // corre en cada handshake.
      }
    }

    // 2. El pin.
    const pin = publicKeyPin(cert);
    observe?.(pin, hostname);

    if (allowed.size === 0) return undefined; // modo observación

    if (!pin) {
      return new Error("no se pudo leer la clave pública del servidor para comprobar el pin");
    }
    if (!allowed.has(pin)) {
      return new Error(
        `la clave pública de ${hostname} no coincide con ningún pin configurado`,
      );
    }
    return undefined;
  };
}

/** Lee la lista de pins de los parámetros de conexión. Tolerante a formas. */
export function readServerKeyPins(params: Record<string, unknown> | null | undefined): string[] {
  const raw = params?.serverKeyPins;
  if (Array.isArray(raw)) return raw.map((p) => String(p).trim()).filter(Boolean);
  // Se admite una cadena separada por comas: es lo que sobrevive a pasar
  // por un fichero de configuración o una variable de entorno.
  if (typeof raw === "string") return raw.split(",").map((p) => p.trim()).filter(Boolean);
  return [];
}
