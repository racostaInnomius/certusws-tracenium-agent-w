// src/domain/device-facts.ts

export interface DeviceFacts {
  schemaVersion: "1.0";
  collectedAtUtc: string;

  agent: AgentInfo;
  device: DeviceIdentity;
  namespaces: Namespaces;
}

export interface AgentInfo {
  agentVersion: string;
  coreVersion: string;

  osProvider: "windows" | "macos" | "linux";
  capabilities: string[];

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

  platform: "win32" | "darwin" | "linux";
}

export interface Namespaces {
  amm?: any;
  scm?: any;
  pmm?: any;
  rcm?: any;
}