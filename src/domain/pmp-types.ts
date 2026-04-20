export type PmpOverallStatus =
  | "idle"
  | "inventory_only"
  | "scan_pending"
  | "updates_available"
  | "installing"
  | "reboot_required"
  | "healthy"
  | "error";

export type PmpRemediationStatus =
  | "idle"
  | "success"
  | "partial"
  | "failed";

export type PmpScanItem = {
  hotFixId?: string;
  title?: string;
  installedBy?: string;
  installedOn?: string;
  source?: string;
};

export type PmpNamespace = {
  schemaVersion: "1.0";
  collector: {
    plugin: "pmp";
    version: string;
  };
  hasChanges: boolean;
  overall: {
    status: PmpOverallStatus;
    score?: number;
  };
  scan?: {
    scannedAtUtc?: string;
    source: "windows_security_compliance_inventory" | "windows_update_agent";
    mode: "inventory_only";
    installedPatchCount: number;
    securityPatchCount: number;
    items?: PmpScanItem[];
  };
  remediation?: {
    status: PmpRemediationStatus;
    rebootRequired?: boolean;
    installedCount?: number;
    failedCount?: number;
    results?: Array<{
      updateId?: string;
      kb?: string;
      title?: string;
      result: "installed" | "downloaded" | "failed" | "skipped";
      hresult?: string;
      message?: string;
    }>;
  };
};
