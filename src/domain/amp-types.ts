// src/domain/amp-types.ts

import type { SoftwareDelta } from "./software-inventory-delta";
import type { SoftwareApplication } from "./normalize-app";
import type { Printer } from "./printer";
import type { PrinterDelta } from "./printer-inventory-delta";

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
    manufacturer?: string;
    brand?: string;
    vendor?: string;
    model?: string;
    cores?: number;
    physicalCores?: number;
    speed?: number;
  };

  graphics?: {
    controllers?: Array<{ vendor?: string; model?: string; vramMb?: number }>;
  };

  memLayout?: Array<{
    sizeBytes?: number;
    type?: string;
    clockSpeed?: number;
    manufacturer?: string;
  }>;

  diskLayout?: Array<{
    name?: string;
    type?: string;
    vendor?: string;
    sizeBytes?: number;
    interfaceType?: string;
  }>;

  users?: Array<{
    user: string;
    domain?: string | null;
    raw?: string;
    isLoggedIn?: boolean;
    lastLogon?: string | null;
  }>;

  networkInterfaces?: Array<{
    name?: string;
    displayName?: string;
    mac?: string;
    ip4?: string | null;
    ip6?: string | null;
    internal?: boolean;
    default?: boolean;
    type?: string;
  }>;

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
   * Present ONLY when hasChanges = true OR forced (baseline/manual facts snapshot)
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
 * Printer inventory model. Same shape as SoftwareInventory: count is
 * always present, items[] only when hasChanges=true (or first run /
 * forced baseline), delta only when a non-first-run cycle detected
 * changes. The backend mirrors software's projection pattern — a
 * `device_printers` table maintained incrementally by add/remove/
 * update events.
 */
export type PrinterInventory = {
  count: number;

  /**
   * Present ONLY when hasChanges = true OR forced (baseline snapshot).
   * On a no-changes cycle we elide this to keep FACTS_SNAPSHOT slim;
   * the backend already knows the current state via its projection.
   */
  items?: Printer[];

  /**
   * Optional delta. Only populated on cycles where a baseline already
   * exists locally AND changes were detected.
   */
  delta?: PrinterDelta | null;

  /**
   * Scheduler driver — same role as SoftwareInventory.hasChanges.
   */
  hasChanges: boolean;
};

/**
 * AMP namespace (Asset Management Plugin)
 *
 * `printers` is intentionally OPTIONAL. Agents that don't yet collect
 * printers (older builds, platforms with no collector) simply omit the
 * field, and the backend ignores its absence — keeps the wire schema
 * additive and lets us roll out collector + backend in either order.
 */
/**
 * OS-reported position. Optional and usually absent: it requires the tenant to
 * switch on `features.locationTracking` AND the endpoint's location service to
 * be available. An agent that reports nothing here looks exactly like every
 * agent did before the feature existed.
 */
export type AmpGeo = {
  lat: number;
  lon: number;
  accuracyM: number | null;
  collectedAtUtc: string;
};

export type AmpNamespace = {
  hardware: {
    static: HardwareStatic;
    runtime: HardwareRuntime;
  };
  security: SecurityInfo;
  software: SoftwareInventory;
  printers?: PrinterInventory;
  geo?: AmpGeo;
  /** Why `geo` is present or absent. See GeoStatus in providers/geo.ts. */
  geoStatus?: string;
};
