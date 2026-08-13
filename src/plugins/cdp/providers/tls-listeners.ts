// src/plugins/cdp/providers/tls-listeners.ts
//
// Captures the certificate a local TLS service ACTUALLY SERVES, which is
// the thing users and clients see — and which can differ from anything in
// a certificate store. A service can be pinned to an old cert file, be
// running with a config that was never reloaded after renewal, or serve a
// self-signed cert nobody registered anywhere.
//
// This is the most intrusive collector in CDP, so it is fenced in:
//
//   * OPT-IN. Off unless policy sets `cdp.scanTlsListeners`.
//   * LOOPBACK ONLY. Every probe goes to 127.0.0.1 — nothing leaves the
//     host, and no remote service is ever touched.
//   * NO DATA SENT. The socket is destroyed the moment the handshake
//     yields a peer certificate. We never write a byte of application
//     protocol, so a probe cannot be mistaken for a request.
//   * SHORT TIMEOUT, LOW CONCURRENCY. A plaintext port fails the
//     handshake fast; the cap keeps a host with hundreds of listeners
//     from seeing a burst of connections.
//   * SKIP LIST. Ports whose protocols react badly to a stray TLS
//     ClientHello (or that are simply never TLS) are never probed.
//
// `rejectUnauthorized: false` is intentional and safe here: we are
// INVENTORYING the certificate, not trusting it. A self-signed or expired
// cert is exactly what we most want to see, and no data is exchanged.

import tls from "tls";
import type { AgentContext } from "../../../core/agent-context";
import type { CdpCertItem, CdpStoreInfo } from "../../../domain/cdp-types";
import { parseCertToItem } from "../parse-cert";
import { listListeningPorts } from "../listening-ports";

const PROBE_TIMEOUT_MS = 3000;
const MAX_CONCURRENCY = 8;
const MAX_PORTS = 200;

/**
 * Never probed. Databases and mail/IRC-style protocols can log noisily or
 * drop a connection badly when handed an unexpected TLS ClientHello, and
 * the agent's own gRPC/IPC ports have nothing to inventory.
 */
export const SKIPPED_PORTS = new Set([
  22,    // SSH — plaintext banner protocol, and probes pollute auth logs
  23,    // telnet
  25,    // SMTP (STARTTLS, not implicit TLS)
  53,    // DNS
  110,   // POP3 (STARTTLS)
  143,   // IMAP (STARTTLS)
  1433,  // MSSQL
  1521,  // Oracle
  3306,  // MySQL — handshake is server-first, a ClientHello confuses it
  5432,  // PostgreSQL — same
  6379,  // Redis
  11211, // memcached
  27017  // MongoDB
]);

export type TlsListenerResult = {
  items: CdpCertItem[];
  stores: CdpStoreInfo[];
  parseFailures: number;
  portsScanned: number;
  portsWithTls: number;
};

type Options = {
  /** Test seam: bypass port enumeration. */
  ports?: number[];
  /** Test seam: override the probe. */
  probe?: (port: number) => Promise<Buffer | null>;
};

/**
 * One handshake. Resolves with the peer certificate in DER, or null when
 * the port is not TLS / does not answer in time. Never rejects — a
 * failed probe is an expected outcome, not an error.
 */
export function probeTlsPort(port: number): Promise<Buffer | null> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: Buffer | null) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* already gone */
      }
      resolve(value);
    };

    const socket = tls.connect(
      {
        host: "127.0.0.1",
        port,
        // Inventory, not trust — see header.
        rejectUnauthorized: false,
        // Some servers require SNI to present a certificate at all.
        servername: "localhost",
        timeout: PROBE_TIMEOUT_MS
      },
      () => {
        const peer = socket.getPeerCertificate(false) as any;
        finish(peer && peer.raw && peer.raw.length > 0 ? peer.raw : null);
      }
    );

    socket.setTimeout(PROBE_TIMEOUT_MS, () => finish(null));
    socket.on("error", () => finish(null));
    socket.on("close", () => finish(null));
  });
}

async function mapLimited<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>
): Promise<R[]> {
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

export async function collectTlsListeners(
  ctx: AgentContext,
  options: Options = {}
): Promise<TlsListenerResult> {
  const result: TlsListenerResult = {
    items: [],
    stores: [],
    parseFailures: 0,
    portsScanned: 0,
    portsWithTls: 0
  };

  const configured = ctx.policyRuntime.getCdpTlsListenerPorts();
  const discovered = options.ports ?? (await listListeningPorts());

  // An explicit port list means "only these" — an operator narrowing the
  // scan must not have the agent probe everything else anyway.
  const candidates = (configured.length > 0
    ? discovered.filter((p) => configured.includes(p))
    : discovered
  )
    .filter((p) => !SKIPPED_PORTS.has(p))
    .slice(0, MAX_PORTS);

  result.portsScanned = candidates.length;
  if (candidates.length === 0) return result;

  const probe = options.probe ?? probeTlsPort;
  const der = await mapLimited(candidates, MAX_CONCURRENCY, (port) =>
    probe(port).catch(() => null)
  );

  candidates.forEach((port, index) => {
    const raw = der[index];
    if (!raw) return;

    result.portsWithTls += 1;

    const store: CdpStoreInfo = {
      id: `listener/tcp/${port}`,
      name: `TLS listener on port ${port}`,
      // Always machine scope: a served certificate is infrastructure, and
      // it must land in the default views and the expiry alert.
      scope: "machine"
    };

    const item = parseCertToItem(raw, { store });
    if (item) {
      item.source = "listener";
      result.items.push(item);
      result.stores.push(store);
    } else {
      result.parseFailures += 1;
    }
  });

  if (result.portsWithTls > 0) {
    ctx.logger?.info?.("CDP: TLS listeners inventoried", {
      scanned: result.portsScanned,
      withTls: result.portsWithTls
    });
  }

  return result;
}
