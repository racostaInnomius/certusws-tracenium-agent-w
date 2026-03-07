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

  os: {
    family: "windows" | "macos" | "linux";
    edition?: string;
    version?: string;
    build?: string;
    arch: "x64" | "arm64" | "x86";
  };

  hardware: {
    manufacturer?: string;
    model?: string;
    serialNumber?: string;
    uuid?: string;

    cpu?: {
      vendor?: string;
      model?: string;
      cores?: number;
      threads?: number;
    };

    memoryBytes?: number;
    isVirtualMachine?: boolean;
  };

  network: {
    interfaces: NetworkInterface[];
  };
}

export interface NetworkInterface {
  name: string;
  mac?: string;
  ipv4?: string[];
  ipv6?: string[];
  gateway?: string;
  dns?: string[];
}

export interface Namespaces {
  amm?: any;
  scm?: any;
  pmm?: any;
  rcm?: any;
}