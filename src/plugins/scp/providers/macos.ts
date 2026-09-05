// src/plugins/scp/providers/macos.ts
//
// Schema 2.0 macOS SCP collector. Same contract as the Windows provider:
// pass the raw posture from PrivSvc through as evidence. The server-side
// catalog evaluator decides pass/fail against its own rule set.

import type { AgentContext } from "../../../core/agent-context";
import type { ScpNamespace, ScpPatchesEvidence } from "../../../domain/scp-types";

function asArray<T = any>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

async function readSecurityCompliance(ctx: AgentContext): Promise<any> {
  const resp = await ctx.priv.call({
    v: 1,
    id: `scp_${Date.now()}`,
    method: "security.compliance",
    // Sondas genéricas que pide el control plane (policy
    // compliance.macosProbes). Lista vacía = el PrivSvc no emite el bloque.
    params: { macosProbes: ctx.policyRuntime.getMacosProbes() },
    meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
  });

  if (!resp?.ok) {
    throw new Error(resp?.error?.message || "security.compliance failed");
  }

  return resp.result || {};
}

function buildPatchesEvidence(posture: any): ScpPatchesEvidence {
  const items = asArray(posture?.patches?.items);

  return {
    items,
    count: Number(posture?.patches?.securityCount ?? items.length) || items.length,
    lastScanUtc: posture?.patches?.lastScanUtc ?? posture?.collectedAtUtc ?? undefined
  };
}

export async function collectMacosScp(ctx: AgentContext): Promise<ScpNamespace> {
  let posture: any = {};
  let collectorError: ScpNamespace["collectorError"] | undefined;

  try {
    posture = await readSecurityCompliance(ctx);
  } catch (err: any) {
    collectorError = {
      message: err?.message || String(err),
      phase: "security.compliance"
    };
  }

  return {
    schemaVersion: "2.0",
    collector: {
      plugin: "scp",
      version: ctx.config.agentVersion
    },
    hasChanges: true,

    // Raw evidence blocks — paths chosen to match the macOS catalog
    // entries in certusws-tracenium/db/migrations/20260422_compliance_catalog_seed.sql
    // (filevault.status, gatekeeper.status, sip.status, screenLock.*,
    //  services.remoteLogin, smb.smb1.enabled, softwareUpdate.autoCheck,
    //  accounts.guestEnabled). Those catalog rows are gated by
    //  collector_version_min so they stay not_applicable until PrivSvc
    //  actually ships the evidence — the type signature is forward-
    //  compatible for that rollout.
    firewall: posture?.firewall,
    filevault: posture?.filevault,
    gatekeeper: posture?.gatekeeper,
    sip: posture?.sip,
    screenLock: posture?.screenLock,
    services: posture?.services,
    smb: posture?.smb,
    shares: posture?.shares,
    antivirus: posture?.antivirus,
    softwareUpdate: posture?.softwareUpdate,
    accounts: posture?.accounts,
    domain: posture?.domain,
    // Platform parity — pwpolicy-derived password policy
    // (macos.password_policy.min_length catalog check, gated 1.1.46).
    passwordPolicy: posture?.passwordPolicy,
    // SSH crypto/hardening posture — same shape as Linux, so the shared SSH
    // crypto catalog rules evaluate on macOS (replaces the former crypto stub).
    ssh: posture?.ssh,
    // Fase 3 CIS — sondas genéricas. Sólo si el PrivSvc lo emitió (un null
    // viajaría como bloque presente y la guarda onMissingRequires fallaría).
    ...(posture?.probes ? { probes: posture.probes } : {}),

    patches: buildPatchesEvidence(posture),

    ...(collectorError ? { collectorError } : {})
  };
}
