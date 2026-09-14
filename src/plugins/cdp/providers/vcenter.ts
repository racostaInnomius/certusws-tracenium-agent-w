// src/plugins/cdp/providers/vcenter.ts
//
// vCenter por el gateway de infraestructura (2026-09-14). Si este equipo es
// el gateway de vCenter (ADR-0001) y el bloque `gateway` de su policy pide
// `readCertificates`, el escaneo de Crypto Discovery lee ADEMÁS:
//
//   - el certificado máquina de vCenter: lo que sirve en 443, el mismo que
//     el pin del gateway comprueba;
//   - el certificado de cada host ESXi del inventario, leído del PROPIO host
//     en 443 — lo que de verdad sirve, que es lo que la sonda remota mediría
//     si alguien apuntara cada host a mano. vCenter pone la lista y el
//     nombre con el que conoce a cada uno; no hace falta escribir objetivos.
//
// ── Por qué un bloque aparte, como AD CS ────────────────────────────
//
// Nada de esto está EN este equipo. Meterlo en `certificates.items` lo
// convertiría en «un certificado en MSIG-WSUS», y el embudo de propiedad,
// las alertas y el rescan actuarían sobre algo que no vive ahí. El control
// plane lo proyecta a `cdp_crypto_assets` con origen `vcenter`.
//
// ── Lista completa, que viaja cuando cambia ─────────────────────────
//
// A diferencia de AD CS (incremental), cada lectura es el estado actual:
// el control plane retira por ausencia lo que no vino, salvo que un host
// no se haya podido leer (`complete: false`). El plugin manda el bloque
// sólo cuando su digest cambia o en un baseline completo, para no engordar
// cada tick con lo mismo.
//
// ── Credencial ──────────────────────────────────────────────────────
//
// La misma que Patch Management selló en el navegador y que sólo el
// PrivSvc puede abrir. Vive en este proceso lo que dura una lectura y se
// borra al terminar, como en el conector. Con `System.View` basta: la
// verificación por uso (`uses.certificates`) lo dice antes de llegar aquí.

import type { AgentContext } from "../../../core/agent-context";
import type { CdpVcenterCert, CdpVcenterHost, CdpVcenterReport } from "../../../domain/cdp-types";
import type { ConnectorDeps, VCenterCredential } from "../../../connectors/vcenter";
import type { GatewayConfig } from "../../../connectors/vcenter/gateway-config";
import { parseCertToItem } from "../parse-cert";

export type CollectVcenterOptions = {
  /** Test seam: the connector's deps (config, credential, client). */
  deps?: ConnectorDeps;
  /** Test seam: the TLS read of one host's certificate. */
  fetchPeerCertificate?: (host: string, port: number) => Promise<Buffer>;
  now?: () => Date;
  /** Hosts read at once. Small on purpose: a gateway is not a scanner. */
  concurrency?: number;
  /** Cap on hosts read per scan; the rest are reported as unread. */
  maxHosts?: number;
};

export const VCENTER_MAX_HOSTS = 2000;

/** Un certificado DER → los campos del cable, sin lo que sólo aplica en un equipo. */
export function derToVcenterCert(der: Buffer, where: string): CdpVcenterCert | null {
  const item = parseCertToItem(der, { store: { id: `vcenter/${where}`, name: where, scope: "network" }, hasPrivateKey: false });
  if (!item) return null;
  const { id: _id, store: _store, source: _source, hasPrivateKey: _hpk, ...rest } = item as any;
  return rest as CdpVcenterCert;
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return out;
}

export async function collectVcenter(ctx: AgentContext, options: CollectVcenterOptions = {}): Promise<CdpVcenterReport | undefined> {
  const deps: ConnectorDeps = options.deps ?? (await import("../../../connectors/vcenter")).makeConnectorDeps(ctx);
  const cfg: GatewayConfig | null = deps.gatewayConfig();
  if (!cfg || cfg.readCertificates !== true) return undefined;
  const now = options.now ?? (() => new Date());
  const fetchPeer = options.fetchPeerCertificate ?? (await import("../../../connectors/vcenter/vim-client")).fetchPeerCertificateDer;
  const maxHosts = Math.min(Math.max(Number(options.maxHosts) || VCENTER_MAX_HOSTS, 1), VCENTER_MAX_HOSTS);

  // Sin credencial no hay nada que leer, y no se toca vCenter: el estado
  // (`credential_state`) ya lo ve el operador en el gateway.
  let cred: VCenterCredential;
  try {
    cred = await deps.getCredential(cfg.vcenter.credentialRef);
  } catch (err: any) {
    ctx.logger?.warn?.("CDP/vCenter: sin credencial en el gateway, no se lee", { code: err?.code, error: err?.message || String(err) });
    return undefined;
  }

  const errors: string[] = [];
  const report: CdpVcenterReport = {
    url: cfg.vcenter.url,
    host: cfg.vcenter.host,
    readAt: now().toISOString(),
    hosts: [],
    complete: true,
  };

  const client = deps.makeClient(cfg);
  let inventory: Array<{ moref: string; name: string; connectionState: string }> = [];
  try {
    // El pin primero: si vCenter no es quien dice, ni credencial ni lectura.
    await client.assertPinnedCertificate();
    try {
      const der = await client.fetchServerCertificateDer();
      const machine = derToVcenterCert(der, cfg.vcenter.host);
      if (machine) report.machine = machine;
      else errors.push("vcenter: certificate could not be parsed");
    } catch (err: any) {
      errors.push(`vcenter: ${err?.message || String(err)}`);
    }
    await client.retrieveServiceContent();
    await client.login(cred.username, cred.password);
    try {
      inventory = await client.listHosts();
    } finally {
      await client.logout().catch(() => undefined);
    }
  } catch (err: any) {
    // Sin inventario no hay lectura completa: se reporta lo que hay (el
    // certificado máquina, si se leyó) y el motivo, y no se retira nada.
    errors.push(`inventory: ${err?.message || String(err)}`);
    report.complete = false;
  } finally {
    cred.password = "";
  }

  const capped = inventory.slice(0, maxHosts);
  if (inventory.length > capped.length) {
    errors.push(`inventory: ${inventory.length - capped.length} host(s) beyond the per-scan cap were not read`);
    report.complete = false;
  }

  report.hosts = await mapLimit(capped, options.concurrency ?? 4, async (h): Promise<CdpVcenterHost> => {
    const base = { name: h.name, moref: h.moref, connectionState: h.connectionState };
    if (!h.name) return { ...base, error: "host has no name in vCenter" };
    try {
      const der = await fetchPeer(h.name, 443);
      const certificate = derToVcenterCert(der, h.name);
      if (!certificate) return { ...base, error: "certificate could not be parsed" };
      return { ...base, certificate };
    } catch (err: any) {
      return { ...base, error: err?.message || String(err) };
    }
  });
  if (report.hosts.some((h) => !h.certificate)) report.complete = false;
  if (errors.length) report.errors = errors;

  ctx.logger?.info?.("CDP/vCenter: lectura terminada", {
    host: cfg.vcenter.host,
    hosts: report.hosts.length,
    unread: report.hosts.filter((h) => !h.certificate).length,
    machine: !!report.machine,
    complete: report.complete,
  });
  return report;
}
