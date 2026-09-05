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
import { STARTTLS_PORTS, StartTlsError, connectWithStartTls } from "../starttls";
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
  22,    // SSH — plaintext banner protocol, and probes pollute auth logs.
         // Las claves de host se leen de disco: ver providers/ssh-host-keys.ts.
  23,    // telnet
  53,    // DNS
  1433,  // MSSQL — TLS dentro de TDS (pre-login), no StartTLS estandar
  1521,  // Oracle
  6379,  // Redis
  11211, // memcached
  27017  // MongoDB
  // 25/587 (SMTP), 110 (POP3), 143 (IMAP), 389 (LDAP), 5432 (PostgreSQL) y
  // 3306 (MySQL) ya NO se saltan: se sondean con su preambulo StartTLS
  // (starttls.ts), que es lo que el servidor espera oir.
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
  /** Fase 2 — lo negociado. Ver CdpCertItem.tls. */
  protocol?: string;
  cipher?: string;
  kexGroup?: string;
  kemHybrid?: boolean | null;
  kemProbeError?: string;
  /** Protocolo del preambulo StartTLS cuando el puerto lo exige
   *  (smtp, imap, pop3, ldap, postgres, mysql). Ausente = TLS implicito. */
  startTls?: string;
};

/** El grupo hibrido que se ofrece como sonda de capacidad. */
export const HYBRID_KEM_GROUP = "X25519MLKEM768";

/**
 * ¿Puede ESTE agente sondear el KEM hibrido? Depende del OpenSSL que
 * empaqueta Node (3.5+). Si no puede, el veredicto es null en toda la
 * flota y se dice — nunca false, que seria acusar al servidor de lo que
 * no sabe hacer el cliente.
 */
export function kemProbeSupported(): boolean {
  try {
    tls.createSecureContext({ ecdhCurve: HYBRID_KEM_GROUP });
    return true;
  } catch {
    return false;
  }
}

type EndpointProbe = {
  der: Buffer;
  chainDepth: number;
  chainAuthorized: boolean;
  chainError?: string;
  san?: string;
  protocol?: string;
  cipher?: string;
  kexGroup?: string;
};

/**
 * Un handshake contra host:port. Es la primitiva que comparten el
 * sondeo de loopback y el rol Probe: lo unico que cambia es a quien se
 * conecta y que SNI se manda. Nunca rechaza.
 */
type ProbeOutcome = { ok: true; probe: EndpointProbe } | { ok: false; code: string };

export function probeTlsEndpoint(
  host: string,
  port: number,
  servername: string,
  extra: { ecdhCurve?: string } = {}
): Promise<EndpointProbe | null> {
  return probeTlsEndpointDetailed(host, port, servername, extra).then((o) => (o.ok ? o.probe : null));
}

/**
 * Igual que probeTlsEndpoint pero dice POR QUE fallo. La diferencia
 * importa para el veredicto de KEM: un servidor que responde con un
 * alert de handshake al grupo hibrido NO lo soporta; uno que no contesta
 * a tiempo no ha dicho nada, y decir «no» por el seria inventar el dato.
 */
export function probeTlsEndpointDetailed(
  host: string,
  port: number,
  servername: string,
  extra: { ecdhCurve?: string } = {}
): Promise<ProbeOutcome> {
  return new Promise((resolve) => {
    let settled = false;
    let socket: tls.TLSSocket | null = null;
    const finish = (value: ProbeOutcome) => {
      if (settled) return;
      settled = true;
      try {
        socket?.destroy();
      } catch {
        /* already gone */
      }
      resolve(value);
    };

    const startTls = STARTTLS_PORTS[port];
    const onSecure = () => {
          const s = socket!;
          const peer = s.getPeerCertificate(true) as any;
          if (!peer || !peer.raw || peer.raw.length === 0) return finish({ ok: false, code: "no_certificate" });

          let depth = 0;
          let node: any = peer;
          const seen = new Set<string>();
          while (node?.fingerprint256 && !seen.has(node.fingerprint256) && depth < MAX_CHAIN_DEPTH) {
            seen.add(node.fingerprint256);
            depth += 1;
            node = node.issuerCertificate;
          }

          const cipher = s.getCipher();
          const eph = (s.getEphemeralKeyInfo() || {}) as { name?: string };
          finish({ ok: true, probe: {
            der: peer.raw,
            chainDepth: depth,
            chainAuthorized: s.authorized === true,
            chainError: s.authorized ? undefined : String(s.authorizationError ?? "UNKNOWN"),
            san: typeof peer.subjectaltname === "string" ? peer.subjectaltname : undefined,
            protocol: s.getProtocol() ?? undefined,
            cipher: cipher?.standardName || cipher?.name || undefined,
            kexGroup: eph?.name || undefined,
            ...(startTls ? { startTls } : {})
          } });
    };
    const wire = (s: tls.TLSSocket) => {
      socket = s;
      s.setTimeout(PROBE_TIMEOUT_MS, () => finish({ ok: false, code: "timeout" }));
      s.on("error", (err: any) => finish({ ok: false, code: String(err?.code || err?.message || "error") }));
      s.on("close", () => finish({ ok: false, code: "closed" }));
    };
    const tlsOpts = {
      rejectUnauthorized: false,
      servername,
      checkServerIdentity: () => undefined,
      ...extra
    };

    try {
      if (startTls) {
        // Preambulo en claro y luego el mismo handshake sobre el socket ya
        // abierto. Un fallo del preambulo dice su razon (`starttls:…`).
        connectWithStartTls(host, port, startTls, PROBE_TIMEOUT_MS)
          .then((plain) => {
            if (settled) return plain.destroy();
            try {
              wire(tls.connect({ socket: plain, ...tlsOpts } as tls.ConnectionOptions, onSecure));
            } catch (err: any) {
              plain.destroy();
              finish({ ok: false, code: `client:${String(err?.code || err?.message || "error")}` });
            }
          })
          .catch((err: any) => finish({ ok: false, code: err instanceof StartTlsError ? err.message : `starttls:${String(err?.message || err)}` }));
        return;
      }
      wire(tls.connect({ host, port, timeout: PROBE_TIMEOUT_MS, ...tlsOpts } as tls.ConnectionOptions, onSecure));
    } catch (err: any) {
      // `ecdhCurve` desconocido para este OpenSSL lanza SINCRONO
      // (ERR_CRYPTO_OPERATION_FAILED). Es un fallo del cliente, no del
      // servidor.
      finish({ ok: false, code: `client:${String(err?.code || err?.message || "error")}` });
    }
  });
}

/** Un alert de handshake es el servidor diciendo «no»; lo demas es silencio. */
const HANDSHAKE_REJECTED = /HANDSHAKE_FAILURE|NO_SHARED_GROUP|NO_SHARED_CIPHER|ILLEGAL_PARAMETER|PROTOCOL_VERSION|SSL_ALERT|TLSV1_ALERT|ECONNRESET/i;

/**
 * Handshake + veredicto de KEM hibrido, en una o dos conexiones.
 *
 * 1. Por defecto. Si ya negocio el grupo hibrido, no hace falta mas.
 * 2. Si no, se repite con el cliente RESTRINGIDO al grupo hibrido: si
 *    completa, el servidor lo soporta pero prefiere clasico; si falla,
 *    no lo soporta. Es una sonda de CAPACIDAD, que para la metrica de
 *    preparacion es lo que se quiere (ADR-0004 e-F2).
 *
 * Con un OpenSSL sin el grupo, el veredicto es null y se explica.
 */
export async function probeTlsWithKem(
  host: string,
  port: number,
  servername: string
): Promise<TlsProbeResult | null> {
  const first = await probeTlsEndpoint(host, port, servername);
  if (!first) return null;

  const out: TlsProbeResult = { ...first };
  if (first.kexGroup && /MLKEM/i.test(first.kexGroup)) {
    out.kemHybrid = true;
    return out;
  }
  if (!kemProbeSupported()) {
    out.kemHybrid = null;
    out.kemProbeError = "client_openssl_lacks_group";
    return out;
  }
  const forced = await probeTlsEndpointDetailed(host, port, servername, { ecdhCurve: HYBRID_KEM_GROUP });
  if (forced.ok) {
    out.kemHybrid = true;
  } else if (HANDSHAKE_REJECTED.test(forced.code)) {
    out.kemHybrid = false;
  } else {
    // Timeout, cierre sin alert, o fallo del propio cliente: no se sabe.
    out.kemHybrid = null;
    out.kemProbeError = forced.code;
  }
  return out;
}

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
  return probeTlsWithKem("127.0.0.1", port, "localhost");
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
        // Fase 2: lo negociado viaja junto al certificado. `kemHybrid`
        // puede ser null y ese null se manda: es «no se pudo saber».
        ...(hit.protocol ? { protocol: hit.protocol } : {}),
        ...(hit.cipher ? { cipher: hit.cipher } : {}),
        ...(hit.kexGroup ? { kexGroup: hit.kexGroup } : {}),
        ...(hit.kemHybrid !== undefined ? { kemHybrid: hit.kemHybrid } : {}),
        ...(hit.kemProbeError ? { kemProbeError: hit.kemProbeError } : {}),
        ...(hit.startTls ? { startTls: hit.startTls } : {}),
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
