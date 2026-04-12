// src/domain/scp-types.ts

export type ScpStatus = "pass" | "fail" | "warning" | "unknown";
export type ScpSeverity = "critical" | "high" | "medium" | "low" | "info";

export type ScpFinding = {
  checkId: string;
  category: string;
  severity: ScpSeverity;
  status: ScpStatus;
  title: string;
  evidence?: Record<string, unknown>;
  remediation?: {
    type: "manual" | "automated" | "none";
    summary?: string;
  };
};

export type ScpNamespace = {
  schemaVersion: "1.0";
  collector: {
    plugin: "scp";
    version: string;
  };
  hasChanges: boolean;
  overall: {
    status: ScpStatus;
    score: number;
  };
  checks: ScpFinding[];
  patches?: {
    status: ScpStatus;
    installedCount?: number;
    missingCount?: number;
    lastScanUtc?: string;
    items?: unknown[];
  };
  crypto?: {
    status: ScpStatus;
    tls10Enabled?: boolean;
    tls11Enabled?: boolean;
    tls12Enabled?: boolean;
    tls13Enabled?: boolean;
    weakCiphers?: string[];
    ciphers?: unknown[];
    protocols?: unknown[];
  };
  smb?: unknown;
  shares?: unknown;
  antivirus?: unknown;
  domain?: unknown;
};
