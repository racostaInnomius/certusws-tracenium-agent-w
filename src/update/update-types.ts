// src/update/update-types.ts

export type AgentBinaryPlatform = "windows" | "macos" | "linux";
export type AgentBinaryFormat = "msi" | "exe" | "pkg";
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
