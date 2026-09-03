// src/plugins/scp/providers/windows.ts
//
// Schema 2.0 Windows SCP collector: gathers raw evidence via the
// `security.compliance` PrivSvc method and forwards it verbatim. No
// scoring, no per-check pass/fail decisions — those live server-side in
// the catalog evaluator.
//
// The only "processing" we keep here is the cipher/protocol derivation
// (weakCiphers[], tls1xEnabled booleans) because the catalog rules refer
// to those flags by name and computing them requires understanding the
// Windows-specific cipher inventory format. Doing it here means the
// server-side evaluator stays a generic path/operator engine.

import type { AgentContext } from "../../../core/agent-context";
import type {
  ScpCryptoEvidence,
  ScpNamespace,
  ScpPatchesEvidence
} from "../../../domain/scp-types";

const WEAK_CIPHER_PATTERNS = [
  /RC4/i,
  /\bDES\b/i,
  /3DES/i,
  /Triple DES/i,
  /NULL/i,
  /MD5/i,
  /EXPORT/i
];

function normalizeArray<T = any>(value: unknown): T[] {
  if (Array.isArray(value)) return value as T[];
  if (value && typeof value === "object") return [value as T];
  return [];
}

async function readSecurityCompliance(ctx: AgentContext): Promise<any> {
  const resp = await ctx.priv.call({
    v: 1,
    id: `scp_${Date.now()}`,
    method: "security.compliance",
    params: {
      includeBitlocker: true,
      includeDefender: true,
      includeFirewall: true,
      includeSmb: true,
      includeShares: true,
      includeAntivirus: true,
      includeGpo: true,
      includeCiphers: true,
      includeProtocols: true,
      includePatches: true,
      // Claves de registro que el control plane quiere leídas. Salen de
      // la policy (compliance.registryProbes), no del agente: así una
      // versión nueva de un benchmark CIS es un cambio de backend y no
      // una release. Lista vacía = el PrivSvc no emite el bloque.
      registryProbes: ctx.policyRuntime.getRegistryProbes()
    },
    meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
  });

  if (!resp?.ok) {
    throw new Error(resp?.error?.message || "security.compliance failed");
  }

  return resp.result || {};
}

/**
 * Turn the SCHANNEL cipher inventory into a compact evidence block the
 * catalog rules can evaluate with simple path/operator rules. Raw
 * `cipherItems` and `protocolItems` are preserved untouched for audit.
 */
function buildCryptoEvidence(posture: any): ScpCryptoEvidence {
  const cipherItems = normalizeArray(posture?.ciphers?.items);
  const protocolItems = normalizeArray(posture?.protocols?.items);

  const weakCiphers = cipherItems
    .filter((cipher: any) =>
      cipher?.enabled === true &&
      WEAK_CIPHER_PATTERNS.some((pattern) => pattern.test(String(cipher?.name || "")))
    )
    .map((cipher: any) => String(cipher.name));

  const protocolEnabled = (protocol: string) =>
    protocolItems.some(
      (item: any) => item?.protocol === protocol && item?.enabled === true
    );

  return {
    tls10Enabled: protocolEnabled("TLS 1.0"),
    tls11Enabled: protocolEnabled("TLS 1.1"),
    tls12Enabled: protocolEnabled("TLS 1.2"),
    tls13Enabled: protocolEnabled("TLS 1.3"),
    weakCiphers,
    ciphers: cipherItems,
    protocols: protocolItems
  };
}

function buildPatchesEvidence(posture: any): ScpPatchesEvidence {
  const items = normalizeArray(posture?.patches?.items);

  return {
    items,
    count: Number(posture?.patches?.count ?? items.length) || items.length,
    lastScanUtc: posture?.patches?.lastScanUtc ?? undefined
  };
}

export async function collectWindowsScp(ctx: AgentContext): Promise<ScpNamespace> {
  let posture: any = {};
  let collectorError: ScpNamespace["collectorError"] | undefined;

  try {
    posture = await readSecurityCompliance(ctx);
  } catch (err: any) {
    // Report the failure as a diagnostic block instead of fabricating
    // evidence blocks. The catalog evaluator will correctly mark
    // downstream rules as `not_applicable` because the relevant paths
    // (firewall.*, defender.*, …) simply won't be present.
    collectorError = {
      message: err?.message || String(err),
      phase: "security.compliance"
    };
  }

  // Promote a per-section failure surfaced INSIDE the privsvc response
  // (e.g. `posture.collectorError = { phase: "patches", reason:
  // "powershell_timeout", message: "..." }`) to the top-level
  // collectorError field IF we don't already have an outright IPC
  // failure. Without this, a privsvc that took 50s on the patches
  // PowerShell script and gave up — but still returned every other
  // section successfully — would deliver evidence where `patches` is
  // an empty shell (`{count: 0, items: []}`) AND no error signal at
  // the top level. The backend's stale-preservation gate keys on the
  // top-level collectorError, so without surfacing it here the
  // dashboard would still regress to "Last patch = unknown".
  if (!collectorError && posture?.collectorError) {
    const inner = posture.collectorError;
    collectorError = {
      message: String(inner?.message ?? "privsvc reported a section failure"),
      phase: String(inner?.phase ?? "security.compliance")
    };
  }

  return {
    schemaVersion: "2.0",
    collector: {
      plugin: "scp",
      version: ctx.config.agentVersion
    },
    hasChanges: true, // scheduler will overwrite after the hash diff

    // Raw evidence, passed through verbatim. These shapes match the
    // paths referenced by the catalog (`firewall.profiles.*`,
    // `defender.serviceEnabled`, `bitlocker.status`, …). If PrivSvc is
    // ever extended with richer output, the evaluator picks it up
    // automatically — no agent change required.
    firewall: posture?.firewall,
    defender: posture?.defender,
    bitlocker: posture?.bitlocker,
    smb: posture?.smb,
    shares: posture?.shares,
    antivirus: posture?.antivirus ?? posture?.defender,
    domain: posture?.domain,
    // Platform integrity — TPM + UEFI Secure Boot. Forwarded verbatim; absent
    // until the privsvc collector (SecurityCompliance.cs) emits them, in which
    // case the backend catalog checks activate automatically (schema 2.0).
    tpm: posture?.tpm,
    secureBoot: posture?.secureBoot,
    // Sprint 4 — machine-scoped screen lock policy (parity with the
    // macOS screenLock block). Allowlist: name it or it never ships.
    screenLock: posture?.screenLock,
    // Platform parity — secedit-derived local password policy
    // (windows.password_policy.* catalog checks, gated 1.1.46).
    passwordPolicy: posture?.passwordPolicy,
    // Valores de registro leídos por el PrivSvc a petición del control
    // plane (compliance.registryProbes). Se reenvían tal cual: el
    // veredicto es del catálogo. Allowlist — si no se nombra, no viaja.
    registry: posture?.registry,

    // Derived crypto + patches blocks (see helpers above).
    crypto: buildCryptoEvidence(posture),
    patches: buildPatchesEvidence(posture),

    ...(collectorError ? { collectorError } : {})
  };
}
