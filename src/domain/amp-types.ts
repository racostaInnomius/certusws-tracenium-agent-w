// src/domain/amp-types.ts

import type { SoftwareDelta } from "./software-inventory-delta";
import type { SoftwareApplication } from "./normalize-app";

export type HardwareStatic = {
  system?: any;
  baseboard?: any;
  chassis?: any;
  bios?: any;

  os?: {
    platform: "windows" | "macos" | "linux";
    distro?: string;
    release?: string;
    kernel?: string;
  };

  uuid?: string;

  cpu?: {
    vendor?: string;
    model?: string;
    cores?: number;
    threads?: number;
  };

  graphics?: any;
  memLayout?: any[];
  diskLayout?: any[];

  versions?: Record<string, string>;
};

export type HardwareRuntime = {
  memoryBytes?: number;

  disks?: Array<{
    name?: string;
    type?: string;
    sizeBytes?: number;
  }>;

  filesystems?: Array<{
    fs?: string;
    type?: string;
    sizeBytes?: number;
    usedBytes?: number;
    mount?: string;
  }>;

  isVirtualMachine?: boolean;
};

/**
 * Security posture (L2)
 * Values should come from PrivSvc or OS-native collectors
 */
export type SecurityInfo = {
  bitlocker?: {
    status: "enabled" | "disabled" | "unknown";
    drives?: string[];
  };

  defender?: {
    status: "enabled" | "disabled" | "unknown";
  };

  firewall?: {
    status: "enabled" | "disabled" | "unknown";
  };
};

/**
 * Software inventory model
 */
export type SoftwareInventory = {
  count: number;

  /**
   * Present ONLY when hasChanges = true OR forced (baseline/requestFacts)
   */
  items?: SoftwareApplication[];

  /**
   * Optional delta (only when changes detected)
   */
  delta?: SoftwareDelta | null;

  /**
   * CRITICAL: driver for scheduler decision
   */
  hasChanges: boolean;
};

/**
 * AMP namespace (Asset Management Plugin)
 */
export type AmpNamespace = {
  hardware: {
    static: HardwareStatic;
    runtime: HardwareRuntime;
  };
  security: SecurityInfo;
  software: SoftwareInventory;
};
