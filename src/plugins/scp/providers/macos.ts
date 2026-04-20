import type { AgentContext } from "../../../core/agent-context";
import type { ScpFinding, ScpNamespace, ScpStatus } from "../../../domain/scp-types";

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

function complianceStatus(value: unknown): ScpStatus {
  if (value === "enabled" || value === true) return "pass";
  if (value === "disabled" || value === false) return "fail";
  return "unknown";
}

function remediation(status: ScpStatus, summary: string) {
  return {
    type: status === "pass" ? "none" : "manual",
    summary: status === "pass" ? "No remediation required." : summary
  } as const;
}

function asArray<T = any>(value: unknown): T[] {
  return Array.isArray(value) ? value as T[] : [];
}

async function readSecurityCompliance(ctx: AgentContext): Promise<any> {
  const resp = await ctx.priv.call({
    v: 1,
    id: `scp_${Date.now()}`,
    method: "security.compliance",
    params: {},
    meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
  });

  if (!resp?.ok) {
    throw new Error(resp?.error?.message || "security.compliance failed");
  }

  return resp.result || {};
}

export async function collectMacosScp(ctx: AgentContext): Promise<ScpNamespace> {
  let posture: any = {};
  const findings: ScpFinding[] = [];

  try {
    posture = await readSecurityCompliance(ctx);
    findings.push({
      checkId: "macos.security.compliance.available",
      category: "collector",
      severity: "info",
      status: "pass",
      title: "macOS security compliance data was collected successfully",
      evidence: {
        collectedAtUtc: posture?.collectedAtUtc
      },
      remediation: {
        type: "none",
        summary: "No remediation required."
      }
    });
  } catch (err: any) {
    findings.push({
      checkId: "macos.security.compliance.available",
      category: "collector",
      severity: "high",
      status: "fail",
      title: "macOS security compliance could not be collected",
      evidence: { error: err?.message || String(err) },
      remediation: {
        type: "manual",
        summary: "Verify Tracenium PrivSvc is running and can execute security compliance checks on macOS."
      }
    });
  }

  const fileVaultStatus = complianceStatus(posture?.filevault?.status);
  findings.push({
    checkId: "macos.filevault.enabled",
    category: "disk_encryption",
    severity: "high",
    status: fileVaultStatus,
    title: "FileVault should be enabled",
    evidence: posture?.filevault ?? {},
    remediation: remediation(fileVaultStatus, "Enable FileVault according to the organization's disk encryption policy.")
  });

  const firewallStatus = complianceStatus(posture?.firewall?.status);
  findings.push({
    checkId: "macos.firewall.enabled",
    category: "firewall",
    severity: "high",
    status: firewallStatus,
    title: "macOS Application Firewall should be enabled",
    evidence: posture?.firewall ?? {},
    remediation: remediation(firewallStatus, "Enable the macOS Application Firewall.")
  });

  const gatekeeperStatus = complianceStatus(posture?.gatekeeper?.status);
  findings.push({
    checkId: "macos.gatekeeper.enabled",
    category: "application_control",
    severity: "medium",
    status: gatekeeperStatus,
    title: "Gatekeeper should be enabled",
    evidence: posture?.gatekeeper ?? {},
    remediation: remediation(gatekeeperStatus, "Enable Gatekeeper to restrict unsigned or untrusted applications.")
  });

  const sipStatus = complianceStatus(posture?.sip?.status);
  findings.push({
    checkId: "macos.sip.enabled",
    category: "platform_integrity",
    severity: "high",
    status: sipStatus,
    title: "System Integrity Protection should be enabled",
    evidence: posture?.sip ?? {},
    remediation: remediation(sipStatus, "Re-enable System Integrity Protection from macOS Recovery.")
  });

  const patchItems = asArray(posture?.patches?.items);
  const patchInventoryStatus: ScpStatus = patchItems.length > 0 ? "pass" : "unknown";
  findings.push({
    checkId: "macos.security_patches.inventory_available",
    category: "patching",
    severity: "medium",
    status: patchInventoryStatus,
    title: "Installed security updates should be reported on macOS",
    evidence: posture?.patches ?? {},
    remediation: remediation(patchInventoryStatus, "Verify software update history can be read from PrivSvc on macOS.")
  });

  const avInstalledCount = Number(posture?.antivirus?.installedCount ?? 0);
  const antivirusStatus: ScpStatus = avInstalledCount > 0 ? "pass" : "unknown";
  findings.push({
    checkId: "macos.antivirus.inventory_available",
    category: "antimalware",
    severity: "medium",
    status: antivirusStatus,
    title: "Built-in macOS malware protections should report update metadata",
    evidence: posture?.antivirus ?? {},
    remediation: remediation(antivirusStatus, "Verify XProtect and MRT package receipts are available on the endpoint.")
  });

  const riskyShareCount = Number(posture?.shares?.riskyCount ?? 0);
  const shareInventoryKnown = posture?.shares?.status === "available";
  findings.push({
    checkId: "macos.shares.everyone_write_absent",
    category: "network_sharing",
    severity: "high",
    status: !shareInventoryKnown ? "unknown" : riskyShareCount > 0 ? "fail" : "pass",
    title: "Shared paths should not expose broad write access",
    evidence: posture?.shares ?? {},
    remediation: {
      type: !shareInventoryKnown || riskyShareCount > 0 ? "manual" : "none",
      summary: !shareInventoryKnown
        ? "Verify local share inventory can be collected on macOS."
        : riskyShareCount > 0
          ? "Review shared path ACLs and remove Everyone-style write access."
          : "No remediation required."
    }
  });

  const smbKnown = posture?.smb?.status === "enabled" || posture?.smb?.status === "disabled";
  findings.push({
    checkId: "macos.smb.inventory_available",
    category: "network_sharing",
    severity: "medium",
    status: smbKnown ? "pass" : "unknown",
    title: "SMB service state should be reported on macOS",
    evidence: posture?.smb ?? {},
    remediation: remediation(smbKnown ? "pass" : "unknown", "Verify SMB service status can be inspected from PrivSvc.")
  });

  const profileInventoryKnown = posture?.domain?.profiles?.status === "available";
  findings.push({
    checkId: "macos.identity_policy.inventory_available",
    category: "identity_policy",
    severity: "low",
    status: profileInventoryKnown ? "pass" : "unknown",
    title: "Directory binding and profile inventory should be available on macOS",
    evidence: posture?.domain ?? {},
    remediation: remediation(profileInventoryKnown ? "pass" : "unknown", "Verify profiles and directory binding inspection can run on macOS.")
  });

  findings.push({
    checkId: "macos.crypto.inventory_pending",
    category: "cryptography",
    severity: "medium",
    status: "unknown",
    title: "TLS protocol and cipher inventory model is still pending for macOS",
    evidence: {
      phase: "phase_2",
      collector: "pending_model_definition"
    },
    remediation: {
      type: "manual",
      summary: "Define the supported macOS cryptography inventory model before collecting TLS/cipher data."
    }
  });

  const score = scoreFromFindings(findings);
  const hasFailures = findings.some(f => f.status === "fail");
  const hasUnknown = findings.some(f => f.status === "unknown");
  const hasWarnings = findings.some(f => f.status === "warning");

  return {
    schemaVersion: "1.0",
    collector: {
      plugin: "scp",
      version: ctx.config.agentVersion
    },
    hasChanges: true,
    overall: {
      status: hasFailures ? "fail" : hasUnknown ? "unknown" : hasWarnings ? "warning" : "pass",
      score
    },
    checks: findings,
    patches: {
      status: patchItems.length > 0 ? "pass" : "unknown",
      installedCount: Number(posture?.patches?.securityCount ?? patchItems.length),
      missingCount: undefined,
      lastScanUtc: posture?.patches?.lastScanUtc ?? posture?.collectedAtUtc,
      items: patchItems
    },
    crypto: {
      status: "unknown",
      tls10Enabled: undefined,
      tls11Enabled: undefined,
      tls12Enabled: undefined,
      tls13Enabled: undefined,
      weakCiphers: [],
      ciphers: [],
      protocols: []
    },
    smb: posture?.smb,
    shares: posture?.shares,
    antivirus: posture?.antivirus,
    domain: posture?.domain
  };
}
