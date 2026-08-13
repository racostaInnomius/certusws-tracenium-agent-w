/**
 * Infrastructure Gateway configuration, as delivered in the device policy
 * override under `policy.gateway.vcenter`.
 *
 * PURE parse + validation. No I/O.
 *
 * THE PRESENCE OF THIS CONFIG IS THE ENABLEMENT. There is no separate on/off
 * flag that could drift out of sync with the settings: an endpoint that has no
 * (or an invalid) gateway block simply has no vCenter connector, and a
 * `vcenter_snapshot` job aimed at it is rejected outright. That is why every
 * failure here returns `null` rather than a partially-populated object —
 * a half-configured gateway must never look enabled.
 *
 * Unlike the fleet-wide plugins (amp/pmp/sdp/…), this runs on exactly ONE host
 * per site — the one with network line-of-sight to vCenter. See ADR-0001 (A).
 */

/** A TLS pin is REQUIRED for the operational connector.
 *
 *  vCenter certificates are self-signed by the internal VMCA (confirmed in the
 *  Inc 0 spike), so system-CA validation can never authenticate the server. With
 *  no pin there is nothing stopping the gateway from handing the vSphere service
 *  credential to an impostor. The interactive *verification* flow deliberately
 *  tolerates a missing pin — that is how an admin discovers the fingerprint in
 *  the first place — but the connector that actually logs in does not.
 */
export interface VCenterEndpointConfig {
  /** Origin as configured, e.g. "https://10.130.130.3". */
  url: string;
  host: string;
  port: number;
  /** SHA-256 of the vCenter certificate, hex lowercase, no separators. */
  tlsThumbprintSha256: string;
  /** Key into the gateway's OS credential store. Never the secret itself. */
  credentialRef: string;
}

export interface VCenterScopeConfig {
  datacenter?: string;
  /** Inventory paths the gateway may act within. Empty = whole inventory. */
  folders: string[];
}

export interface VCenterSnapshotConfig {
  /** Capture guest RAM. Off by default: huge and slow, and useless for
   *  rolling back a patch. */
  memory: boolean;
  /** Quiesce the guest filesystem (VSS on Windows) for app consistency. */
  quiesce: boolean;
  /** Delete a successful pre-patch snapshot after this long. Bounds sprawl. */
  retentionHours: number;
  /** Simultaneous snapshot operations against vCenter. */
  maxConcurrent: number;
  /** Per-VM ceiling for a single snapshot task. */
  perVmTimeoutSec: number;
}

export interface GatewayConfig {
  vcenter: VCenterEndpointConfig;
  scope: VCenterScopeConfig;
  snapshot: VCenterSnapshotConfig;
}

export const SNAPSHOT_DEFAULTS: VCenterSnapshotConfig = {
  memory: false,
  quiesce: true,
  retentionHours: 24,
  maxConcurrent: 5,
  perVmTimeoutSec: 900,
};

const clampInt = (v: unknown, min: number, max: number, dflt: number): number => {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, Math.trunc(n)));
};

const asBool = (v: unknown, dflt: boolean): boolean => (typeof v === "boolean" ? v : dflt);

/** Hex SHA-256, separators and case tolerated. Returns "" when unusable. */
export function normalizeThumbprint(v: unknown): string {
  if (typeof v !== "string") return "";
  const hex = v.replace(/[:\s-]/g, "").toLowerCase();
  return /^[0-9a-f]{64}$/.test(hex) ? hex : "";
}

function parseEndpoint(raw: any): VCenterEndpointConfig | null {
  if (!raw || typeof raw !== "object") return null;

  let url: URL;
  try {
    url = new URL(String(raw.url ?? ""));
  } catch {
    return null;
  }
  // https only — a vSphere credential must never cross a plaintext hop.
  if (url.protocol !== "https:") return null;
  if (!url.hostname) return null;

  // `URL.port` is "" for a default-port origin, and "" is not nullish — so it
  // would slip past `??` and coerce to 0. Normalise both sources to undefined.
  const explicitPort = raw.port === "" || raw.port === null ? undefined : raw.port;
  const urlPort = url.port === "" ? undefined : url.port;
  const port = clampInt(explicitPort ?? urlPort ?? 443, 1, 65535, 443);

  const tlsThumbprintSha256 = normalizeThumbprint(raw.tlsThumbprintSha256);
  if (!tlsThumbprintSha256) return null; // fail-closed: no pin, no connector

  const credentialRef =
    typeof raw.credentialRef === "string" && raw.credentialRef.trim()
      ? raw.credentialRef.trim()
      : "vcenter/default";

  return { url: url.origin, host: url.hostname, port, tlsThumbprintSha256, credentialRef };
}

function parseScope(raw: any): VCenterScopeConfig {
  const folders: string[] = Array.isArray(raw?.folders)
    ? (raw.folders as unknown[])
        .filter((f): f is string => typeof f === "string" && f.trim().length > 0)
        .map((f) => f.trim())
        .slice(0, 64)
    : [];
  const datacenter =
    typeof raw?.datacenter === "string" && raw.datacenter.trim() ? raw.datacenter.trim() : undefined;
  return { datacenter, folders: [...new Set(folders)] };
}

function parseSnapshot(raw: any): VCenterSnapshotConfig {
  return {
    memory: asBool(raw?.memory, SNAPSHOT_DEFAULTS.memory),
    quiesce: asBool(raw?.quiesce, SNAPSHOT_DEFAULTS.quiesce),
    // Retention is bounded on BOTH ends: 0 would delete the safety net before
    // anyone could use it; an unbounded value is how datastores fill up.
    retentionHours: clampInt(raw?.retentionHours, 1, 720, SNAPSHOT_DEFAULTS.retentionHours),
    // Snapshotting an entire cluster at once will stun vCenter and the datastore.
    maxConcurrent: clampInt(raw?.maxConcurrent, 1, 32, SNAPSHOT_DEFAULTS.maxConcurrent),
    perVmTimeoutSec: clampInt(raw?.perVmTimeoutSec, 60, 3600, SNAPSHOT_DEFAULTS.perVmTimeoutSec),
  };
}

/**
 * Parse `policy.gateway.vcenter`. Returns null when the endpoint is absent or
 * unusable — which the caller must treat as "this device is not a gateway".
 */
export function parseGatewayConfig(rawGateway: unknown): GatewayConfig | null {
  const raw = rawGateway as any;
  if (!raw || typeof raw !== "object") return null;
  const vcenter = parseEndpoint(raw.vcenter);
  if (!vcenter) return null;
  return { vcenter, scope: parseScope(raw.scope), snapshot: parseSnapshot(raw.snapshot) };
}

/** True when this device is configured to act as an Infrastructure Gateway. */
export function isGatewayEnabled(cfg: GatewayConfig | null): cfg is GatewayConfig {
  return cfg !== null;
}
