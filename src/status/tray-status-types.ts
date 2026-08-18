export type TrayGrpcStatus = {
  connected: boolean;
  lastConnectedAtUtc?: string;
  lastDisconnectedAtUtc?: string;
  lastHeartbeatAtUtc?: string;
};

export type TrayPolicyStatus = {
  version: string;
  hash?: string | null;
  plugins: string[];
  modules: string[];
  // Subset of policy feature flags the tray apps act on. Today only
  // deviceInfoWidget (gates the Windows top-center flyout). Optional so
  // older snapshots deserialize fine in both tray apps.
  features?: {
    deviceInfoWidget?: boolean;
    // macOS only. CoreLocation can only be reached from a real .app bundle in
    // the console user's session — which is exactly what the status app is —
    // so the daemon publishes the switch here and the app does the collecting.
    locationTracking?: boolean;
  };
};

// Static device identity for the support "Device Info" widget. Collected
// once at startup by the agent (systeminformation) and refreshed on each
// startup snapshot — these fields effectively never change while the
// service is running. Fields the tray can read better from the USER
// session (logged-in user, screen resolution) are intentionally absent:
// the agent runs as root/SYSTEM in session 0 and its view of "the user"
// or "the screen" is unreliable, so each tray app fills those locally.
export type TrayDeviceInfo = {
  hostname?: string;
  domain?: string;
  fqdn?: string;
  ipv4?: string;
  ipv6?: string;
  mac?: string;
  osName?: string;      // e.g. "Windows 11 Pro" / "macOS Sequoia"
  osVersion?: string;   // release, e.g. "15.5" / "10.0.26100"
  osBuild?: string;
  manufacturer?: string;
  model?: string;
  serial?: string;
  cpu?: string;         // brand + core summary, e.g. "Apple M3 Pro (11 cores)"
  memoryGb?: number;    // total physical RAM in GB, 1 decimal
};

// The job actively executing right now, if any. Present only between
// markJobStarted() and the matching markJobFinished() — absent/null
// otherwise. Drives the tray apps' "Active Job" tab and the menu bar /
// status-bar badge. Deliberately minimal: the agent has no notion of
// job progress (RunJob over gRPC carries only jobId/jobType/payload —
// see proto/controlplane.proto — no timeout or step count), so the UI
// side can only show elapsed time and an indeterminate spinner, not a
// real percentage.
export type TrayCurrentJob = {
  jobId: string;
  jobType: string;
  startedAtUtc: string;
};

export type TrayJobStatus = {
  lastJobType?: string;
  lastJobStatus?: string;
  lastJobAtUtc?: string;
  current?: TrayCurrentJob | null;
};

export type TrayUpdateStatus = {
  status?: string;
  lastCheckedAtUtc?: string;
  lastCompletedAtUtc?: string;
  lastError?: string;
};

export type TrayPatchStatus = {
  status?: string;
  lastScanAtUtc?: string;
  rebootRequired?: boolean;
  lastError?: string;
};

export type TrayStatusSnapshot = {
  updatedAtUtc: string;
  agentVersion: string;
  coreVersion?: string;
  deviceId: string;
  tenantId: string;
  hostname: string;
  grpc: TrayGrpcStatus;
  policy: TrayPolicyStatus;
  jobs: TrayJobStatus;
  update: TrayUpdateStatus;
  patch: TrayPatchStatus;
  device?: TrayDeviceInfo;
};
