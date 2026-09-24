// src/domain/amp-types.ts

import type { SoftwareDelta } from "./software-inventory-delta";
import type { SoftwareApplication } from "./normalize-app";
import type { Printer } from "./printer";
import type { PrinterDelta } from "./printer-inventory-delta";
import type { BrowserExtension } from "./browser-extension";
import type { BrowserExtensionDelta } from "./browser-extension-inventory-delta";
import type { PolicyListResult } from "../plugins/amp/providers/extension-policy-enforcer";

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
    /**
     * Arquitectura de la MÁQUINA ("x64" | "arm64"). Es la que el portal pinta
     * en Hardware Inventory y la que ADR-0016 usa para elegir el binario de un
     * paquete, así que tiene que ser la del sistema y no la del proceso: hasta
     * 1.1.70 era `os.arch()` y un Windows 11 ARM64 con el agente emulado se
     * publicaba como x64. Ver domain/os-arch.ts.
     */
    arch?: string;
    /**
     * Arquitectura del PROCESO del agente (`os.arch()`). Viaja junto a `arch`,
     * no en su lugar: si difieren, el agente corre emulado — y eso es un dato
     * de diagnóstico, no una contradicción.
     */
    processArch?: string;
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

  /**
   * La batería: presencia, carga y alimentación. En `runtime` porque la carga
   * cambia cada minuto y `static` es lo que el backend hashea para deduplicar.
   * Ausente = no se pudo leer. Ver domain/battery.ts.
   */
  battery?: import("./battery").BatteryRuntime;

  /**
   * Cuándo arrancó el sistema operativo (ISO 8601 UTC, redondeado al minuto),
   * y el contador crudo de segundos encendido.
   *
   * ⚠️ Son DOS campos porque responden dos preguntas distintas y en Windows no
   * coinciden: el contador no cuenta el tiempo suspendido, y el instante que
   * declara el sistema choca con el Inicio rápido. Ver domain/boot-time.ts.
   * `null` significa que no se pudo determinar, nunca "acaba de arrancar".
   */
  bootTimeUtc?: string | null;
  uptimeSeconds?: number | null;
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
   * POR QUÉ este inventario está vacío, cuando lo está.
   *
   * ⚠️ Mismo motivo que `geoStatus`: hasta 2026-09-10 un fallo de lectura y un
   * equipo sin impresoras producían la MISMA fila, y el portal enseñaba cero
   * como si fuera un hecho sobre la empresa. En Windows hay DOS lecturas y
   * pueden fallar por separado — la de máquina (`Get-Printer` desde el
   * servicio) y la de usuario (conexiones de red en HKEY_USERS).
   *
   * Valores de máquina: collected | timeout | empty_output | unavailable.
   * Valores de usuario: collected | no_user_hive | unavailable.
   * Ausentes en macOS y Linux, donde sólo hay una lectura.
   */
  machineScope?: string;
  userScope?: string;

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

/**
 * Extensiones de Chrome, Edge y Firefox de todos los perfiles del equipo.
 * Misma forma que PrinterInventory. `scope` dice por qué la lista está como
 * está (collected | unsupported | unavailable) — ver
 * providers/browser-extensions.ts.
 */
export type BrowserExtensionInventory = {
  count: number;
  items?: BrowserExtension[];
  delta?: BrowserExtensionDelta | null;
  hasChanges: boolean;
  scope: "collected" | "unsupported" | "unavailable";
  profiles: number;
  profileErrors: number;
  /**
   * Resultado de aplicar las listas de Chrome/Edge que pide la política, en
   * este mismo ciclo. Ausente si la política no pide nada ni hay nada nuestro
   * que retirar, o fuera de Windows.
   */
  policy?: PolicyListResult[];
};

export type AmpNamespace = {
  hardware: {
    static: HardwareStatic;
    runtime: HardwareRuntime;
  };
  security: SecurityInfo;
  software: SoftwareInventory;
  printers?: PrinterInventory;
  browserExtensions?: BrowserExtensionInventory;
  geo?: AmpGeo;
  /** Why `geo` is present or absent. See GeoStatus in providers/geo.ts. */
  geoStatus?: string;
};
