// src/plugins/cdp/chain-verify.ts
//
// Ola 1.3a — validación de cadena de los certificados de ALMACÉN.
//
// Hasta ahora solo los listeners y las sondas tenían veredicto de cadena
// (lo da el handshake: `tls.chainAuthorized`). Un certificado en
// LocalMachine\My, en un keystore o en /etc/nginx no tenía ninguno, así
// que «este certificado de servidor no tiene su intermedia en el equipo»
// o «su firma no casa con el emisor que dice tener» eran invisibles.
//
// Aquí, con TODO lo inventariado en el mismo escaneo, para cada
// certificado no autofirmado:
//   · issuerFound     — hay un certificado con su DN de emisor como sujeto
//                       y que `checkIssued` acepta (nombre + AKI/SKI +
//                       uso de clave), es decir, el emisor ESTÁ en el equipo;
//   · signatureValid  — su firma verifica con la clave de ese emisor;
//   · trusted         — subiendo por emisores (tope de profundidad) se llega
//                       a una raíz del almacén de confianza del SO.
//
// Límites, dichos: el inventario de este equipo no es el mundo. Un emisor
// ausente aquí puede estar en el servidor que lo sirve o en otro almacén
// que no leemos. Y en Windows el almacén de raíces se puebla BAJO DEMANDA
// (la lección de `nonstandard_root`, retirada el 2026-08-26): «no llega a
// una raíz de confianza» puede significar solo que Windows aún no se la
// descargó. Por eso estos veredictos son hechos para filtrar, no alertas.
//
// Solo lee certificados (datos públicos) del registro de DER del escaneo.

import crypto from "crypto";
import type { CdpCertItem, CdpChainVerdict } from "../../domain/cdp-types";

const MAX_DEPTH = 8;
/** Solo lo que está EN el equipo. Listener/probe: su cadena la juzga el handshake. */
const EVALUATED_SOURCES = new Set<CdpCertItem["source"]>(["store", "java-store", "file", "nss"]);

type Node = { fp: string; cert: crypto.X509Certificate; selfSigned: boolean };

/**
 * Anota `item.chain` en los items evaluables. Muta y devuelve los mismos
 * items. `derByFingerprint` es el registro de parse-cert del escaneo; un
 * item sin DER registrado (un doble de test, un item de caché antiguo) se
 * deja sin veredicto — ausencia, no «falso».
 */
export function annotateStoreChains(items: CdpCertItem[], derByFingerprint: ReadonlyMap<string, Buffer>): CdpCertItem[] {
  const nodes = new Map<string, Node>();
  const nodeFor = (fp: string): Node | null => {
    const cached = nodes.get(fp);
    if (cached) return cached;
    const der = derByFingerprint.get(fp);
    if (!der) return null;
    try {
      const cert = new crypto.X509Certificate(der);
      const node = { fp, cert, selfSigned: cert.subject === cert.issuer };
      nodes.set(fp, node);
      return node;
    } catch {
      return null;
    }
  };

  // Índice por DN de sujeto: los candidatos a emisor de todo el inventario
  // (también listeners: una intermedia servida es una intermedia que el
  // equipo tiene a mano en ese momento).
  const bySubject = new Map<string, Node[]>();
  const trustedRoots = new Set<string>();
  for (const item of items) {
    const node = nodeFor(item.fingerprint256);
    if (!node) continue;
    const list = bySubject.get(node.cert.subject) ?? [];
    if (!list.some((n) => n.fp === node.fp)) list.push(node);
    bySubject.set(node.cert.subject, list);
    // «Raíz de confianza del SO» = autofirmada en un almacén de raíces del
    // sistema operativo. NO los cacerts de Java ni NSS: son la confianza de
    // una aplicación, no la del equipo.
    if (item.source === "store" && item.store.scope === "system-roots" && node.selfSigned) trustedRoots.add(node.fp);
  }

  const memo = new Map<string, CdpChainVerdict | null>();

  const evaluate = (node: Node, depth: number, visiting: Set<string>): CdpChainVerdict | null => {
    if (node.selfSigned) return null;
    const known = memo.get(node.fp);
    if (known !== undefined) return known;
    if (depth > MAX_DEPTH || visiting.has(node.fp)) return { issuerFound: true };
    visiting.add(node.fp);

    const candidates = (bySubject.get(node.cert.issuer) ?? []).filter((c) => {
      if (c.fp === node.fp) return false;
      try {
        return node.cert.checkIssued(c.cert);
      } catch {
        return false;
      }
    });

    let verdict: CdpChainVerdict;
    if (candidates.length === 0) {
      verdict = { issuerFound: false };
    } else {
      // Con varios emisores posibles (CA renovada con el mismo DN, firma
      // cruzada) se prefiere el que verifica, y entre ellos el que llega a
      // una raíz de confianza.
      let best: CdpChainVerdict | null = null;
      for (const cand of candidates) {
        let sig: boolean | undefined;
        try {
          sig = node.cert.verify(cand.cert.publicKey);
        } catch {
          sig = undefined; // algoritmo que el OpenSSL del agente no conoce (PQC)
        }
        let trusted: boolean | undefined;
        if (sig === false) {
          trusted = false;
        } else if (cand.selfSigned) {
          trusted = trustedRoots.has(cand.fp);
        } else {
          const up = evaluate(cand, depth + 1, visiting);
          trusted = up?.trusted;
        }
        const v: CdpChainVerdict = { issuerFound: true, ...(sig !== undefined ? { signatureValid: sig } : {}), ...(trusted !== undefined ? { trusted } : {}) };
        const score = (x: CdpChainVerdict) => (x.signatureValid === true ? 2 : x.signatureValid === undefined ? 1 : 0) * 2 + (x.trusted === true ? 1 : 0);
        if (!best || score(v) > score(best)) best = v;
      }
      verdict = best!;
    }

    visiting.delete(node.fp);
    memo.set(node.fp, verdict);
    return verdict;
  };

  for (const item of items) {
    if (!EVALUATED_SOURCES.has(item.source)) continue;
    const node = nodeFor(item.fingerprint256);
    if (!node) continue;
    const verdict = evaluate(node, 0, new Set());
    if (verdict) item.chain = verdict;
  }
  return items;
}
