// src/plugins/scp/providers/windows.ts
import type { AgentContext } from "../../../core/agent-context";
import type { ScpFinding, ScpNamespace, ScpStatus } from "../../../domain/scp-types";

const WEAK_CIPHER_PATTERNS = [/RC4/i, /\bDES\b/i, /3DES/i, /Triple DES/i, /NULL/i, /MD5/i, /EXPORT/i];

function statusFromEnabled(value: unknown): ScpStatus {
  if (value === true || value === "enabled") return "pass";
  if (value === false || value === "disabled") return "fail";
  return "unknown";
}

function normalizeArray(value: unknown): any[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === "object") return [value];
  return [];
}

function boolValue(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
  }
  return undefined;
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
      includePatches: true
    },
    meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
  });

  if (!resp?.ok) {
    throw new Error(resp?.error?.message || "security.compliance failed");
  }

  return resp.result || {};
}

export async function collectWindowsScp(ctx: AgentContext): Promise<ScpNamespace> {
  let posture: any = {};
  const findings: ScpFinding[] = [];

  try {
    posture = await readSecurityCompliance(ctx);
  } catch (err: any) {
    findings.push({
      checkId: "windows.security.compliance.available",
      category: "collector",
      severity: "high",
      status: "fail",
      title: "Windows security compliance could not be collected",
      evidence: { error: err?.message || String(err) },
      remediation: {
        type: "manual",
        summary: "Verify Tracenium PrivSvc is running and can execute security compliance checks."
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

  const smb1Status = posture?.smb?.smb1?.status === "disabled"
    ? "pass"
    : posture?.smb?.smb1?.status === "enabled"
      ? "fail"
      : "unknown";
  findings.push({
    checkId: "windows.smbv1.disabled",
    category: "network_sharing",
    severity: "high",
    status: smb1Status,
    title: "SMBv1 should be disabled",
    evidence: posture?.smb ?? {},
    remediation: {
      type: smb1Status === "pass" ? "none" : "manual",
      summary: smb1Status === "pass" ? "No remediation required." : "Disable SMBv1 through Windows Features or security baseline policy."
    }
  });

  const riskyShareCount = Number(posture?.shares?.riskyCount ?? 0);
  findings.push({
    checkId: "windows.shares.everyone_full_control_absent",
    category: "network_sharing",
    severity: "critical",
    status: riskyShareCount > 0 ? "fail" : "pass",
    title: "Shares should not grant Everyone full control",
    evidence: posture?.shares ?? {},
    remediation: {
      type: riskyShareCount > 0 ? "manual" : "none",
      summary: riskyShareCount > 0 ? "Review share ACLs and remove Everyone full-control grants." : "No remediation required."
    }
  });

  const antivirusEvidence = posture?.antivirus ?? posture?.defender ?? {};
  const avEnabled = boolValue(posture?.defender?.antivirusEnabled) ?? posture?.defender?.status === "enabled";
  const hasSignature = Boolean(posture?.defender?.signatureVersion || posture?.defender?.engineVersion);
  findings.push({
    checkId: "windows.antivirus.current",
    category: "antimalware",
    severity: "high",
    status: avEnabled && hasSignature ? "pass" : avEnabled ? "warning" : "fail",
    title: "Antivirus should be enabled and report engine/signature versions",
    evidence: antivirusEvidence,
    remediation: {
      type: avEnabled && hasSignature ? "none" : "manual",
      summary: avEnabled && hasSignature ? "No remediation required." : "Verify AV health, engine version, signatures, and scan telemetry."
    }
  });

  const computerGpos = normalizeArray(posture?.domain?.appliedComputerGpos);
  const userGpos = normalizeArray(posture?.domain?.appliedUserGpos);
  const isDomainJoined = posture?.domain?.partOfDomain === true;
  findings.push({
    checkId: "windows.domain.gpo_inventory_available",
    category: "identity_policy",
    severity: "medium",
    status: isDomainJoined && computerGpos.length === 0 && userGpos.length === 0 ? "warning" : "pass",
    title: "Applied GPO inventory should be available for domain-joined devices",
    evidence: posture?.domain ?? {},
    remediation: {
      type: isDomainJoined && computerGpos.length === 0 && userGpos.length === 0 ? "manual" : "none",
      summary: isDomainJoined && computerGpos.length === 0 && userGpos.length === 0 ? "Run gpresult under an account/session that can read applied GPOs." : "No remediation required."
    }
  });

  const cipherItems = normalizeArray(posture?.ciphers?.items);
  const weakCiphers = cipherItems
    .filter((cipher: any) => cipher?.enabled === true && WEAK_CIPHER_PATTERNS.some(pattern => pattern.test(String(cipher?.name || ""))))
    .map((cipher: any) => String(cipher.name));
  findings.push({
    checkId: "windows.crypto.weak_ciphers_disabled",
    category: "cryptography",
    severity: "high",
    status: weakCiphers.length > 0 ? "fail" : "pass",
    title: "Weak SCHANNEL ciphers should be disabled",
    evidence: { weakCiphers, ciphers: cipherItems },
    remediation: {
      type: weakCiphers.length > 0 ? "manual" : "none",
      summary: weakCiphers.length > 0 ? "Disable weak ciphers such as RC4, DES, 3DES, NULL, MD5, and EXPORT suites." : "No remediation required."
    }
  });

  const protocolItems = normalizeArray(posture?.protocols?.items);
  const protocolEnabled = (protocol: string) =>
    protocolItems.some((item: any) => item?.protocol === protocol && item?.enabled === true);
  const tls10Enabled = protocolEnabled("TLS 1.0");
  const tls11Enabled = protocolEnabled("TLS 1.1");
  const tls12Enabled = protocolEnabled("TLS 1.2");
  const tls13Enabled = protocolEnabled("TLS 1.3");
  findings.push({
    checkId: "windows.crypto.legacy_tls_disabled",
    category: "cryptography",
    severity: "high",
    status: tls10Enabled || tls11Enabled ? "fail" : "pass",
    title: "TLS 1.0 and TLS 1.1 should be disabled",
    evidence: { tls10Enabled, tls11Enabled, tls12Enabled, tls13Enabled, protocols: protocolItems },
    remediation: {
      type: tls10Enabled || tls11Enabled ? "manual" : "none",
      summary: tls10Enabled || tls11Enabled ? "Disable TLS 1.0 and TLS 1.1 in SCHANNEL client and server protocol keys." : "No remediation required."
    }
  });

  const patchItems = normalizeArray(posture?.patches?.items);
  findings.push({
    checkId: "windows.security_patches.inventory_available",
    category: "patching",
    severity: "medium",
    status: patchItems.length > 0 ? "pass" : "unknown",
    title: "Installed security patches should be reported",
    evidence: posture?.patches ?? {},
    remediation: {
      type: patchItems.length > 0 ? "none" : "manual",
      summary: patchItems.length > 0 ? "No remediation required." : "Verify Windows Update / Get-HotFix access from PrivSvc."
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
      installedCount: Number(posture?.patches?.count ?? patchItems.length),
      missingCount: undefined,
      lastScanUtc: undefined,
      items: patchItems
    },
    crypto: {
      status: weakCiphers.length > 0 || tls10Enabled || tls11Enabled ? "fail" : hasWarnings ? "warning" : "pass",
      tls10Enabled,
      tls11Enabled,
      tls12Enabled,
      tls13Enabled,
      weakCiphers,
      ciphers: cipherItems,
      protocols: protocolItems
    },
    smb: posture?.smb,
    shares: posture?.shares,
    antivirus: posture?.antivirus ?? posture?.defender,
    domain: posture?.domain
  };
}
