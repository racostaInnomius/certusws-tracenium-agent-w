// privsvc/macos/src/dp-peer-cas.ts
//
// ¿A qué clientes sirve un Distribution Point? A los de CUALQUIER CA emisora
// del tenant. Gemelo de privsvc/linux/src/dp-peer-cas.ts y de
// privsvc/windows/.../Ipc/DpPeerTrust.cs.
//
// 🔴 EL INCIDENTE (15-sep, MSIG-VEEAM-PC, Windows): el DP sólo aceptaba la CA
// con la que él mismo se enroló; los DP estaban en la Issuing vieja y el peer
// había rotado a la G2. Aquí el `ca` del servidor es el ca-bundle de la
// identidad, que en un DP enrolado antes de la G2 NO la trae — el mismo fallo
// esperando a su primer DP de macOS/Linux.
//
// Por eso el `ca` es el ca-bundle MÁS las CAs que el control plane entrega con
// cada prefetch, y de éstas sólo las que firmó una raíz que el DP ya tiene
// (la del ca-bundle o la que instala el paquete). El canal de entrega amplía
// el conjunto dentro de la misma jerarquía y no puede meter una CA ajena.
//
// ⚠️ La raíz TIENE que estar en `ca`: el TLS de Node no acepta cadenas
// parciales, así que con sólo intermedias rechaza a todos los clientes
// (medido). `buildFullCaBundlePem` ya la añade al ca-bundle.

import crypto from "crypto";

/** Tope del bundle entregado: dos intermedias ocupan ~4 KB. */
export const MAX_DELIVERED_BUNDLE_CHARS = 64 * 1024;

const CLOCK_SKEW_MS = 5 * 60 * 1000;

export function splitPemCertificates(pem: string | null | undefined): string[] {
  if (!pem || pem.length > MAX_DELIVERED_BUNDLE_CHARS * 4) return [];
  return pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
}

function parse(pem: string): crypto.X509Certificate | null {
  try {
    return new crypto.X509Certificate(pem);
  } catch {
    return null;
  }
}

function isSelfSigned(c: crypto.X509Certificate): boolean {
  return c.subject === c.issuer && c.checkIssued(c) && c.verify(c.publicKey);
}

function isValidAt(c: crypto.X509Certificate, now: Date): boolean {
  const t = now.getTime();
  return Date.parse(c.validFrom) - CLOCK_SKEW_MS <= t && t <= Date.parse(c.validTo) + CLOCK_SKEW_MS;
}

/**
 * Las CAs entregadas que el DP puede aceptar: CA, no autofirmada, vigente y
 * firmada por una de las raíces autofirmadas de `anchorPems`.
 */
export function trustedDeliveredCaPems(
  deliveredPem: string | null | undefined,
  anchorPems: string[],
  now: Date = new Date()
): string[] {
  if (!deliveredPem || deliveredPem.length > MAX_DELIVERED_BUNDLE_CHARS) return [];
  const anchors = anchorPems
    .map(parse)
    .filter((a): a is crypto.X509Certificate => !!a && a.ca && isSelfSigned(a));
  if (anchors.length === 0) return [];

  return splitPemCertificates(deliveredPem).filter((pem) => {
    const c = parse(pem);
    if (!c || !c.ca || isSelfSigned(c) || !isValidAt(c, now)) return false;
    return anchors.some((a) => c.checkIssued(a) && c.verify(a.publicKey));
  });
}

/**
 * El `ca` del servidor del DP: el ca-bundle de la identidad más las CAs
 * entregadas que pasan la criba, sin repetidos. `acceptedIssuingCas` cuenta las
 * CA emisoras (no raíces) del resultado, para el acuse del prefetch.
 */
export function dpServerCa(
  caBundlePem: string,
  bundledRootPem: string | null,
  deliveredPem: string | null
): { ca: string[]; acceptedIssuingCas: number } {
  const own = splitPemCertificates(caBundlePem);
  const anchorsPem = [...own, ...(bundledRootPem ? splitPemCertificates(bundledRootPem) : [])];
  const seen = new Set<string>();
  const ca: string[] = [];
  for (const pem of [...own, ...trustedDeliveredCaPems(deliveredPem, anchorsPem)]) {
    const c = parse(pem);
    if (!c || seen.has(c.fingerprint256)) continue;
    seen.add(c.fingerprint256);
    ca.push(pem);
  }
  // La raíz del paquete sólo sirve de ANCLA para cribar lo entregado; no se
  // añade al `ca` — eso ampliaría la confianza de hoy más allá de este arreglo.
  const acceptedIssuingCas = ca
    .map(parse)
    .filter((c): c is crypto.X509Certificate => !!c && c.ca && !isSelfSigned(c)).length;
  return { ca, acceptedIssuingCas };
}
