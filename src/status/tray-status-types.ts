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
};

export type TrayJobStatus = {
  lastJobType?: string;
  lastJobStatus?: string;
  lastJobAtUtc?: string;
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
};
