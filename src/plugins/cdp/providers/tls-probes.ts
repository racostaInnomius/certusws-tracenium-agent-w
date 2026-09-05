// src/plugins/cdp/providers/tls-probes.ts
//
// Rol Probe (fase 2 del analisis de madurez 2026-09): el agente sondea
// objetivos TLS que NO tienen agente — balanceadores, appliances, bases
// de datos gestionadas, hipervisores— y reporta lo que sirven y lo que
// negocian, igual que hace contra su propio loopback.
//
// ── Por que un agente y no el control plane ──────────────────────────
//
// El control plane esta en la nube; el balanceador del cliente esta en
// su LAN. El agente ya esta dentro, ya tiene mTLS con nosotros, y el
// patron «un agente asume un rol para su segmento» ya existe (el
// Distribution Point). No hace falta nada nuevo en el cliente.
//
// ── Lo que NUNCA hace ────────────────────────────────────────────────
//
// - No descubre: sondea SOLO lo que el operador escribio en la policy.
//   Un escaner de red es otra cosa y ADR-0004 lo excluye a proposito.
// - No escribe un byte de protocolo de aplicacion: el socket muere en
//   cuanto el handshake da un certificado, como en loopback.
// - No sondea loopback ni al propio equipo por esta via (para eso esta
//   el colector de listeners, con atribucion a proceso).
// - `hasPrivateKey` es siempre false: lo que hay al otro lado no es de
//   este equipo, y afirmar lo contrario contaminaria el embudo de
//   propiedad, que es la tesis del producto.

import type { AgentContext } from "../../../core/agent-context";
import type { CdpCertItem, CdpStoreInfo } from "../../../domain/cdp-types";
import { parseCertToItem } from "../parse-cert";
import { probeTlsWithKem, type TlsProbeResult } from "./tls-listeners";
import { isIpv4, probeTargetKey, type ProbeTarget } from "../../../domain/probe-target";

export { parseProbeTarget } from "../../../domain/probe-target";

const MAX_CONCURRENCY = 4;

export type TlsProbesResult = {
  items: CdpCertItem[];
  stores: CdpStoreInfo[];
  parseFailures: number;
  targets: number;
  answered: number;
};

type Options = {
  /** Test seam. */
  probe?: (host: string, port: number, servername: string) => Promise<TlsProbeResult | null>;
};

async function mapLimited<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await fn(items[index]);
    }
  });
  await Promise.all(workers);
  return results;
}

export async function collectTlsProbes(ctx: AgentContext, options: Options = {}): Promise<TlsProbesResult> {
  const result: TlsProbesResult = { items: [], stores: [], parseFailures: 0, targets: 0, answered: 0 };
  const targets = ctx.policyRuntime.getCdpProbeTargets();
  result.targets = targets.length;
  if (targets.length === 0) return result;

  const probe = options.probe ?? probeTlsWithKem;
  const probed = await mapLimited(targets, MAX_CONCURRENCY, (t) =>
    // SNI = el nombre que escribio el operador. Para una IP no hay SNI
    // que mandar y muchos servidores devuelven igual su certificado por
    // defecto.
    probe(t.host, t.port, isIpv4(t.host) ? "" : t.host).catch(() => null)
  );

  targets.forEach((t, i) => {
    const hit = probed[i];
    if (!hit) return;
    result.answered += 1;
    const key = probeTargetKey(t);
    const store: CdpStoreInfo = { id: `probe/tcp/${key}`, name: key, scope: "network" };
    const item = parseCertToItem(hit.der, { store, hasPrivateKey: false });
    if (!item) {
      result.parseFailures += 1;
      return;
    }
    item.source = "probe";
    item.hasPrivateKey = false;
    item.tls = {
      port: t.port,
      target: t.host,
      chainDepth: hit.chainDepth,
      chainAuthorized: hit.chainAuthorized,
      ...(hit.chainError ? { chainError: hit.chainError } : {}),
      ...(hit.protocol ? { protocol: hit.protocol } : {}),
      ...(hit.cipher ? { cipher: hit.cipher } : {}),
      ...(hit.kexGroup ? { kexGroup: hit.kexGroup } : {}),
      ...(hit.kemHybrid !== undefined ? { kemHybrid: hit.kemHybrid } : {}),
      ...(hit.kemProbeError ? { kemProbeError: hit.kemProbeError } : {}),
      ...(hit.startTls ? { startTls: hit.startTls } : {})
    };
    result.items.push(item);
    result.stores.push(store);
  });

  if (result.targets > 0) {
    ctx.logger?.info?.("CDP: sondas TLS remotas", { targets: result.targets, answered: result.answered });
  }
  return result;
}
