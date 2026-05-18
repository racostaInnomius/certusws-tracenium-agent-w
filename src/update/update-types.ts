// src/update/update-types.ts

export type AgentBinaryPlatform = "windows" | "macos" | "linux";
export type AgentBinaryFormat = "msi" | "exe" | "pkg" | "deb" | "rpm";
export type AgentBinaryArch = "x64" | "arm64";

export interface AgentBinaryFileMetadata {
  size: number;
  hash?: string;
}

export interface AgentMetadataResponse {
  latestVersion: string;
  minSupportedVersion?: string;
  forceUpdate?: boolean;
  allowDowngrade?: boolean;
  files: {
    exe?: Record<AgentBinaryArch, AgentBinaryFileMetadata>;
    msi?: Record<AgentBinaryArch, AgentBinaryFileMetadata>;
    pkg?: Record<AgentBinaryArch, AgentBinaryFileMetadata>;
    // Phase 10 — Linux OTA. The backend metadata endpoint returns
    // these for `platform=linux` queries, keyed by arch. update-task
    // resolves which one to pick at runtime via detectFamily()
    // (debian → deb, rhel/suse → rpm).
    deb?: Record<AgentBinaryArch, AgentBinaryFileMetadata>;
    rpm?: Record<AgentBinaryArch, AgentBinaryFileMetadata>;
  };
}

export interface AgentDownloadResponse {
  downloadUrl: string;
  expiresIn: number;
}

export interface UpdateCheckResult {
  available: boolean;
  currentVersion: string;
  latestVersion: string;
  reason?:
    | "up_to_date"
    | "invalid_remote_version"
    | "missing_binary_metadata"
    | "same_version"
    | "downgrade_blocked"
    | "new_version_available"
    | "forced_update"
    | "min_supported_breach";
  metadata?: AgentMetadataResponse;
}

export interface DownloadedUpdateInfo {
  filePath: string;
  fileName: string;
  sha256: string;
  size: number;
  latestVersion: string;
}

export interface RunUpdateResult {
  started: boolean;
  command: string;
  args: string[];
}
