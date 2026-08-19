// src/plugins/scp/providers/linux.ts
//
// Schema 2.0 Linux SCP collector. Mirrors the macOS provider shape
// almost line-for-line — same contract: shell out to privsvc for
// the privileged checks (sshd -T, getenforce, aa-status, firewall
// probes, /etc/login.defs read), pass the raw posture through as
// evidence, let the backend catalog evaluator decide pass/fail.
//
// We don't precompute crypto evidence here the way the Windows
// provider does (`crypto.tls10Enabled`, `crypto.weakCiphers`) —
// that's a Schannel concept on Windows. The equivalent on Linux is
// per-service config (sshd_config Ciphers/MACs/KexAlgorithms,
// nginx/apache TLS settings) which the catalog evaluates from the
// raw `ssh.kexAlgorithms`/`ssh.ciphers` blocks directly. If a future
// catalog rule needs derived crypto flags we add them here as a
// computed block alongside the raw evidence.

import type { AgentContext } from "../../../core/agent-context";
import type { ScpNamespace } from "../../../domain/scp-types";

async function readSecurityCompliance(ctx: AgentContext): Promise<any> {
  const resp = await ctx.priv.call({
    v: 1,
    id: `scp_${Date.now()}`,
    method: "security.compliance",
    params: {},
    meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId },
  });

  if (!resp?.ok) {
    throw new Error(resp?.error?.message || "security.compliance failed");
  }

  return resp.result || {};
}

export async function collectLinuxScp(ctx: AgentContext): Promise<ScpNamespace> {
  let posture: any = {};
  let collectorError: ScpNamespace["collectorError"] | undefined;

  try {
    posture = await readSecurityCompliance(ctx);
  } catch (err: any) {
    // Phase 4 / fresh install case: privsvc is up but the agent
    // gets an IPC error mid-reconnect. Or Phase 5 deploy lag where
    // the privsvc is older and doesn't support the method. Either
    // way, surface as a collectorError block — the backend treats
    // every catalog entry as not_applicable for this snapshot
    // instead of inventing synthetic findings.
    collectorError = {
      message: err?.message || String(err),
      phase: "security.compliance",
    };
  }

  return {
    schemaVersion: "2.0",
    collector: {
      plugin: "scp",
      version: ctx.config.agentVersion,
    },
    hasChanges: true,

    // Raw evidence blocks shaped by privsvc/linux/src/security-
    // posture.ts. Path keys map directly to catalog evidence
    // selectors — when a Linux compliance rule lands in
    // certusws-tracenium/db/migrations/*_compliance_catalog_seed.sql,
    // it'll reference paths like `linux.ssh.passwordAuthentication`
    // or `linux.firewall.status`.
    firewall: posture?.firewall,
    ssh: posture?.ssh,
    selinux: posture?.selinux,
    apparmor: posture?.apparmor,
    passwordPolicy: posture?.passwordPolicy,
    auditd: posture?.auditd,
    updates: posture?.updates,
    sysctl: posture?.sysctl,
    smb: posture?.smb,
    shares: posture?.shares,
    mounts: posture?.mounts,
    pwquality: posture?.pwquality,
    // Sprint 4 — encryption-at-rest (lsblk crypt-layer detection).
    // ⚠️ This literal is an ALLOWLIST: a block the privsvc emits but
    // isn't named here never reaches the wire (see the AMP builder's
    // scar-tissue comment for how many releases that pattern has
    // cost). If you add a block in security-posture.ts, add it here.
    diskEncryption: posture?.diskEncryption,

    ...(collectorError ? { collectorError } : {}),
  };
}
