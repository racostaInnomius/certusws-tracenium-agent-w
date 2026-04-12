// src/plugins/scp/providers/windows.ts
import type { AgentContext } from "../../../core/agent-context";
import type { ScpFinding, ScpNamespace, ScpStatus } from "../../../domain/scp-types";

function statusFromEnabled(value: unknown): ScpStatus {
  if (value === true || value === "enabled") return "pass";
  if (value === false || value === "disabled") return "fail";
  return "unknown";
}

function scoreFromFindings(findings: ScpFinding[]): number {
  if (findings.length === 0) return 100;

  const weights: Record<string, number> = {
    critical: 35,
    high: 25,
    medium: 15,
    low: 5,
    info: 0
  };

  const penalty = findings.reduce((sum, finding) => {
    if (finding.status !== "fail") return sum;
    return sum + (weights[finding.severity] ?? 0);
  }, 0);

  return Math.max(0, 100 - penalty);
}

async function readSecurityPosture(ctx: AgentContext): Promise<any> {
  const resp = await ctx.priv.call({
    v: 1,
    id: `scp_${Date.now()}`,
    method: "security.posture",
    params: { includeBitlocker: true, includeDefender: true, includeFirewall: true },
    meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
  });

  if (!resp?.ok) {
    throw new Error(resp?.error?.message || "security.posture failed");
  }

  return resp.result || {};
}

export async function collectWindowsScp(ctx: AgentContext): Promise<ScpNamespace> {
  let posture: any = {};
  const findings: ScpFinding[] = [];

  try {
    posture = await readSecurityPosture(ctx);
  } catch (err: any) {
    findings.push({
      checkId: "windows.security.posture.available",
      category: "collector",
      severity: "high",
      status: "fail",
      title: "Windows security posture could not be collected",
      evidence: { error: err?.message || String(err) },
      remediation: {
        type: "manual",
        summary: "Verify Tracenium PrivSvc is running and can execute security posture checks."
      }
    });
  }

  const firewallStatus = statusFromEnabled(posture?.firewall?.status);
  findings.push({
    checkId: "windows.firewall.enabled",
    category: "firewall",
    severity: "high",
    status: firewallStatus,
    title: "Windows Firewall should be enabled",
    evidence: posture?.firewall ?? {},
    remediation: {
      type: firewallStatus === "pass" ? "none" : "manual",
      summary: firewallStatus === "pass" ? "No remediation required." : "Enable Windows Firewall for all applicable profiles."
    }
  });

  const defenderStatus = statusFromEnabled(posture?.defender?.status);
  findings.push({
    checkId: "windows.defender.enabled",
    category: "antimalware",
    severity: "high",
    status: defenderStatus,
    title: "Microsoft Defender should be enabled",
    evidence: posture?.defender ?? {},
    remediation: {
      type: defenderStatus === "pass" ? "none" : "manual",
      summary: defenderStatus === "pass" ? "No remediation required." : "Enable Microsoft Defender or verify an approved AV provider is active."
    }
  });

  const bitlockerStatus = statusFromEnabled(posture?.bitlocker?.status);
  findings.push({
    checkId: "windows.bitlocker.enabled",
    category: "disk_encryption",
    severity: "medium",
    status: bitlockerStatus,
    title: "BitLocker should be enabled on fixed drives",
    evidence: posture?.bitlocker ?? {},
    remediation: {
      type: bitlockerStatus === "pass" ? "none" : "manual",
      summary: bitlockerStatus === "pass" ? "No remediation required." : "Enable BitLocker according to the organization's encryption policy."
    }
  });

  const score = scoreFromFindings(findings);
  const hasFailures = findings.some(f => f.status === "fail");
  const hasUnknown = findings.some(f => f.status === "unknown");

  return {
    schemaVersion: "1.0",
    collector: {
      plugin: "scp",
      version: ctx.config.agentVersion
    },
    hasChanges: true,
    overall: {
      status: hasFailures ? "fail" : hasUnknown ? "unknown" : "pass",
      score
    },
    checks: findings,
    patches: {
      status: "unknown",
      missingCount: undefined,
      lastScanUtc: undefined,
      items: undefined
    },
    crypto: {
      status: "unknown",
      tls10Enabled: undefined,
      tls11Enabled: undefined,
      weakCiphers: undefined
    }
  };
}
