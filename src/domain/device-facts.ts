// src/domain/device-facts.ts

import type { AmpNamespace } from "./amp-types";
import type { CdpNamespace } from "./cdp-types";
import type { PmpNamespace } from "./pmp-types";
import type { ScpNamespace } from "./scp-types";

export type AgentCapability =
  | "realtime"
  | "remote-exec"
  | "file-transfer"
  | "self-update"
  | (string & {});

export interface DeviceFacts {
  schemaVersion: string;
  collectedAtUtc: string;

  agent: AgentInfo;
  device: DeviceIdentity;
  namespaces: Namespaces;

  _meta?: {
    baselineHash: string;
    forceBaseline?: boolean;
    sequence?: number;
    partial?: boolean;
  };
}

export interface AgentInfo {
  agentVersion: string;
  coreVersion: string;

  osProvider: "windows" | "macos" | "linux";
  // CPU architecture the agent is running on — canonicalized to match
  // the values the /binaries/agent/metadata endpoint accepts ("arm64",
  // "x64"). The backend needs this to pick the right binary when the
  // operator fires an agent_update job: an arm64 Windows box must NOT
  // be offered an x64 MSI and vice versa.
  arch: "arm64" | "x64" | string;
  capabilities: AgentCapability[];

  install: {
    installId: string;
    channel: "stable" | "beta" | "pilot";
    firstSeenAtUtc: string;
  };
}

export interface DeviceIdentity {
  deviceId: string;
  tenantId: string;

  hostname: string;
  fqdn?: string;
  domain?: string;

  platform: "windows" | "macos" | "linux";
}

export interface Namespaces {
  // Plugin namespaces
  amp?: AmpNamespace;
  scp?: ScpNamespace;
  pmp?: PmpNamespace;
  cdp?: CdpNamespace;
  rcm?: unknown;
}
