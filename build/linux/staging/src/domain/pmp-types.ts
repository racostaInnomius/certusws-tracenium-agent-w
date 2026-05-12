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
  // Reused for Linux as the `<package>-<version>` identifier (apt) or
  // the advisory id (dnf RHSA-/RHBA-/RHEA-, zypper SUSE-SU-). Naming
  // stayed `hotFixId` to avoid a wire-schema break — the field is a
  // free-form identifier as far as the backend is concerned.
  hotFixId?: string;
  title?: string;
  severity?: PmpSeverity;
  installedBy?: string;
  installedOn?: string;
  source?: string;
  // Linux-specific extras. All optional + tolerant of absence so the
  // backend's existing PmpScanItem ingestion stays compatible.
  // `cveIds`: from `dnf updateinfo --list-cves` / parsed from apt
  //   changelog when available; primary use is the Patch Management
  //   v2 dashboard's CVE drilldown.
  // `type`:   advisory class. dnf uses "security"|"bugfix"|"enhancement";
  //   apt-via-unattended-upgrades surfaces only the "security" subset
  //   so non-security entries fall under the catch-all "update".
  // `rebootRequired`: best-effort per-item flag. apt: kernel/glibc
  //   updates; dnf: items annotated with reboot=Yes in updateinfo.
  cveIds?: string[];
  type?: "security" | "bugfix" | "enhancement" | "update";
  rebootRequired?: boolean;
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
    source:
      | "windows_update_agent"
      | "apple_software_update"
      | "linux_apt"
      | "linux_dnf"
      | "linux_zypper"
      | "patch_management_unavailable";
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
