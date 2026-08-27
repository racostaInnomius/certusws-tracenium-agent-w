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

// One entry in the self-service Software Catalog tray tab. Mirrors
// proto SoftwareCatalogItem — see controlplane.proto's "SOFTWARE
// CATALOG (self-service)" doc block for why this is the one
// agent-initiated exception to the admin-push job model.
export type TrayCatalogItem = {
  packageId: string;
  name: string;
  vendor?: string;
  version: string;
  description?: string;
  requiresReboot?: boolean;
};

export type TrayCatalogStatus = {
  updatedAtUtc?: string;
  // Hash from the last CatalogResponse. Lets the tray (and this
  // store's update()) short-circuit when the eligible set hasn't
  // actually changed since the last write.
  catalogVersion?: string;
  items: TrayCatalogItem[];
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

/**
 * Sesión de control remoto en curso. La bandeja la usa para mostrar un
 * indicador PERMANENTE mientras dure.
 *
 * Por qué existe (ADR-0012): un aviso que se cierra no informa de nada — la
 * persona lo descarta y se olvida de que la están viendo. Lo que protege de
 * verdad no es el diálogo inicial sino saber, en todo momento, que hay alguien
 * mirando y poder cortarlo. Un consentimiento que no se puede retirar es una
 * casilla, no un consentimiento.
 *
 * Ausente = no hay sesión. La bandeja trata la ausencia y `active:false`
 * igual, para que un snapshot viejo no deje el indicador encendido.
 */
export type TrayRemoteSession = {
  active: boolean;
  sessionId: string;
  /** rcp.screen | rcp.shell | rcp.file — hoy solo screen muestra indicador. */
  capability: string;
  startedAtUtc: string;
  /** El operador puede estar controlando además de viendo. */
  controlling?: boolean;
  /** Si el tenant tiene la grabación activa. La persona tiene derecho a
   *  saberlo mientras ocurre, no solo al aceptar. */
  recording?: boolean;
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
  // Absent on older snapshots (pre self-service catalog) — the tray
  // treats a missing block the same as an empty catalog.
  catalog?: TrayCatalogStatus;
  // Ausente en snapshots anteriores al indicador de sesión; la bandeja lo
  // trata como "sin sesión".
  remoteSession?: TrayRemoteSession;
};
