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
  | "in_progress"
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
    source: "windows_update_agent" | "apple_software_update" | "patch_management_unavailable";
    mode: "inventory_only";
    installedPatchCount: number;
    securityPatchCount: number;
    items?: PmpScanItem[];
  };
  remediation?: {
    status: PmpRemediationStatus;
    mode?: "download" | "install";
    startedAtUtc?: string;
    finishedAtUtc?: string;
    rebootRequired?: boolean;
    installedCount?: number;
    failedCount?: number;
    selectedCount?: number;
    lastError?: string;
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
