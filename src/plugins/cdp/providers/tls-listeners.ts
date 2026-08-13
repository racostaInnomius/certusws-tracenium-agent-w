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
import os from "os";
import type { AgentContext } from "../../../core/agent-context";
import type { CdpCertItem, CdpStoreInfo } from "../../../domain/cdp-types";
import { parseCertToItem } from "../parse-cert";
import { listListeningPorts } from "../listening-ports";
import { resolveListenerOwners, type ProcessOwner } from "../process-owner";

const PROBE_TIMEOUT_MS = 3000;
const MAX_CONCURRENCY = 8;
const MAX_PORTS = 200;
const MAX_CHAIN_DEPTH = 12;

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
  /** Test seam: pin the device name used for SAN coverage. */
  hostname?: string;
  /** Test seam: bypass process attribution. */
  owners?: Map<number, ProcessOwner>;
  /** Test seam: override the probe. */
  probe?: (port: number) => Promise<TlsProbeResult | null>;
};

export type TlsProbeResult = {
  /** The leaf certificate, DER-encoded. */
  der: Buffer;
  /** How many certificates the server actually sent. */
  chainDepth: number;
  /** Does the DEVICE'S OWN trust store accept this chain? */
  chainAuthorized: boolean;
  /** OpenSSL verify code when it does not, e.g.
   *  UNABLE_TO_VERIFY_LEAF_SIGNATURE (a missing intermediate). */
  chainError?: string;
  /** Raw subjectAltName, used to check coverage of the device's name. */
  san?: string;
};

/**
 * One handshake. Resolves with the served certificate and the verdict on
 * its chain, or null when the port is not TLS / does not answer in time.
 * Never rejects — a failed probe is an expected outcome, not an error.
 *
 * `checkServerIdentity` is disabled ON PURPOSE. We connect to 127.0.0.1
 * with servername "localhost", so the built-in hostname check fails for
 * essentially every real certificate and its error
 * (ERR_TLS_CERT_ALTNAME_INVALID) MASKS the chain verdict — measured
 * against a live listener whose chain was in fact perfectly valid.
 * Disabling it makes `chainAuthorized` mean what it says: the device's
 * own trust store accepts the chain the service serves. Hostname
 * coverage is evaluated separately, against the device's real name.
 */
export function probeTlsPort(port: number): Promise<TlsProbeResult | null> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: TlsProbeResult | null) => {
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
        // See the doc comment: measures the CHAIN, not the name.
        checkServerIdentity: () => undefined,
        timeout: PROBE_TIMEOUT_MS
      },
      () => {
        const peer = socket.getPeerCertificate(true) as any;
        if (!peer || !peer.raw || peer.raw.length === 0) return finish(null);

        // Walk the chain the server sent. The last certificate points at
        // itself when self-signed, so `seen` is what terminates the walk.
        let depth = 0;
        let node: any = peer;
        const seen = new Set<string>();
        while (node?.fingerprint256 && !seen.has(node.fingerprint256) && depth < MAX_CHAIN_DEPTH) {
          seen.add(node.fingerprint256);
          depth += 1;
          node = node.issuerCertificate;
        }

        finish({
          der: peer.raw,
          chainDepth: depth,
          chainAuthorized: socket.authorized === true,
          chainError: socket.authorized ? undefined : String(socket.authorizationError ?? "UNKNOWN"),
          san: typeof peer.subjectaltname === "string" ? peer.subjectaltname : undefined
        });
      }
    );

    socket.setTimeout(PROBE_TIMEOUT_MS, () => finish(null));
    socket.on("error", () => finish(null));
    socket.on("close", () => finish(null));
  });
}

/**
 * Does the served certificate cover the device's own name?
 *
 * Reported as INFORMATION, never as a hygiene flag: a reverse proxy or
 * virtual host legitimately serves names that have nothing to do with
 * the machine it runs on, so flagging every mismatch would be noise.
 * What it is good for is the opposite direction — spotting a service
 * that should present its own host's name and does not.
 */
export function sanCoversHost(san: string | undefined, hostname: string): boolean | undefined {
  if (!san || !hostname) return undefined;

  const names = san
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.toUpperCase().startsWith("DNS:"))
    .map((entry) => entry.slice(4).trim().toLowerCase());

  if (names.length === 0) return undefined;

  const host = hostname.toLowerCase();
  const shortHost = host.split(".")[0];

  return names.some((name) => {
    if (name === host || name === shortHost) return true;
    if (name.startsWith("*.")) {
      // A wildcard covers exactly one label, per RFC 6125.
      const suffix = name.slice(2);
      const parent = host.split(".").slice(1).join(".");
      return parent === suffix;
    }
    return false;
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
  const probed = await mapLimited(candidates, MAX_CONCURRENCY, (port) =>
    probe(port).catch(() => null)
  );

  const hostname = options.hostname ?? os.hostname();

  // Which process serves each certificate (ADR-0004 a). Resolved only
  // for the ports that actually answered TLS, so a host with hundreds of
  // plaintext listeners costs nothing. Enrichment only: if it fails we
  // still report the certificates.
  const tlsPorts = candidates.filter((_, i) => probed[i]);
  const owners = options.owners ?? (await resolveListenerOwners(tlsPorts));

  candidates.forEach((port, index) => {
    const hit = probed[index];
    if (!hit) return;

    result.portsWithTls += 1;

    const store: CdpStoreInfo = {
      id: `listener/tcp/${port}`,
      name: `TLS listener on port ${port}`,
      // Always machine scope: a served certificate is infrastructure, and
      // it must land in the default views and the expiry alert.
      scope: "machine"
    };

    const item = parseCertToItem(hit.der, { store });
    if (item) {
      item.source = "listener";
      // What the handshake said about the chain, kept next to the
      // certificate it belongs to. `coversDeviceHostname` is reported,
      // never flagged — see sanCoversHost.
      item.tls = {
        port,
        chainDepth: hit.chainDepth,
        chainAuthorized: hit.chainAuthorized,
        ...(hit.chainError ? { chainError: hit.chainError } : {}),
        ...(() => {
          const covers = sanCoversHost(hit.san, hostname);
          return covers === undefined ? {} : { coversDeviceHostname: covers };
        })(),
        ...(() => {
          const owner = owners.get(port);
          return owner ? { process: owner } : {};
        })()
      };
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
