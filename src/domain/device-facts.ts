// src/domain/device-facts.ts

import type { AmmNamespace } from "./amm-types";

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
  // Plugins (modules)
  amm: AmmNamespace;
  scm?: unknown;
  pmm?: unknown;
  rcm?: unknown;
}