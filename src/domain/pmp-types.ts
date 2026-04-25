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

// Severity bucket for an available patch. We canonicalize to four
// values + "unknown" for cross-platform consistency:
//   - critical / important / moderate / low: the set Microsoft uses
//     for `IUpdate.MsrcSeverity` (also matches CVSS bucketing well
//     enough for ops triage). Apple's `softwareupdate --list` does
//     not expose severity at all, so macOS items default to
//     "unknown" until we cross-reference against a CVE feed.
//   - unknown: provider couldn't determine it (Apple today; future
//     Linux distros without a clear severity field).
export type PmpSeverity = "critical" | "important" | "moderate" | "low" | "unknown";

export type PmpScanItem = {
  hotFixId?: string;
  title?: string;
  severity?: PmpSeverity;
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
