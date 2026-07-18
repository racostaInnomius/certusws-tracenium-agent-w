// src/domain/device-facts-builder.ts
import os from "os";
import si from "systeminformation";
import { execFile } from "child_process";
import { promisify } from "util";
import type { AgentContext } from "../core/agent-context";
import type { DeviceFacts, Namespaces, AgentCapability } from "./device-facts";
import crypto from "crypto";
import type {
  AmpNamespace,
  HardwareStatic,
  HardwareRuntime,
  SecurityInfo,
  SoftwareInventory,
  PrinterInventory
} from "./amp-types";

import {
  normalizeCpu,
  normalizeGraphics,
  normalizeMemLayout,
  normalizeDiskLayout
} from "./normalize-hardware";

const execFileAsync = promisify(execFile);

type NormalizedUser = {
  user: string;
  domain?: string | null;
  raw?: string;
  isLoggedIn?: boolean;
  lastLogon?: string | null;
};

type NormalizedNetworkInterface = {
  name?: string;
  displayName?: string;
  mac?: string;
  ip4?: string | null;
  ip6?: string | null;
  internal?: boolean;
  default?: boolean;
  type?: string;
};


function isIgnorableUser(value?: string | null): boolean {
  const v = String(value || "").trim().toLowerCase();

  return (
    !v ||
    v === "root" ||
    v === "system" ||
    v === "localservice" ||
    v === "networkservice" ||
    v === "_mbsetupuser" ||
    v === "loginwindow"
  );
}

function parseUserIdentity(raw?: string | null): NormalizedUser | null {
  const value = String(raw || "").trim();

  if (!value) return null;

  // Windows usually returns DOMAIN\username from Win32_ComputerSystem.UserName.
  const slashMatch = value.match(/^([^\\]+)\\(.+)$/);
  if (slashMatch) {
    const domain = slashMatch[1]?.trim() || null;
    const user = slashMatch[2]?.trim() || "";

    if (isIgnorableUser(user)) return null;

    return {
      user,
      domain,
      raw: value,
      isLoggedIn: true,
      lastLogon: null
    };
  }

  // Keep user@domain useful, but split it when it looks like a login identity.
  const atMatch = value.match(/^([^@\s]+)@([^@\s]+)$/);
  if (atMatch) {
    const user = atMatch[1]?.trim() || "";
    const domain = atMatch[2]?.trim() || null;

    if (isIgnorableUser(user)) return null;

    return {
      user,
      domain,
      raw: value,
      isLoggedIn: true,
      lastLogon: null
    };
  }

  if (isIgnorableUser(value)) return null;

  return {
    user: value,
    domain: null,
    raw: value,
    isLoggedIn: true,
    lastLogon: null
  };
}

async function runCommand(command: string, args: string[], timeout = 2500): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync(command, args, {
      timeout,
      windowsHide: true,
      maxBuffer: 1024 * 128
    });

    const value = String(stdout || "").trim();
    return value.length > 0 ? value : null;
  } catch {
    return null;
  }
}

async function getInteractiveUserFromOs(): Promise<NormalizedUser | null> {
  const platform = os.platform();

  if (platform === "win32") {
    const ps = await runCommand("powershell.exe", [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-Command",
      "try { (Get-CimInstance Win32_ComputerSystem).UserName } catch { $null }"
    ], 3500);

    const fromPs = parseUserIdentity(ps);
    if (fromPs) return fromPs;

    const whoami = await runCommand("whoami.exe", [], 2500);
    return parseUserIdentity(whoami);
  }

  if (platform === "darwin") {
    // Works when the agent runs as LaunchDaemon/root: it returns the console user, not root.
    const consoleUser = await runCommand("/usr/bin/stat", ["-f", "%Su", "/dev/console"], 2500);
    const fromConsole = parseUserIdentity(consoleUser);
    if (fromConsole) return fromConsole;

    const whoami = await runCommand("/usr/bin/whoami", [], 2500);
    return parseUserIdentity(whoami);
  }

  // Linux: prefer an active login session when available.
  const who = await runCommand("who", [], 2500);
  if (who) {
    const firstLine = who.split("\n").map(x => x.trim()).filter(Boolean)[0];
    const firstUser = firstLine?.split(/\s+/)[0];
    const fromWho = parseUserIdentity(firstUser);
    if (fromWho) return fromWho;
  }

  const logname = await runCommand("logname", [], 2500);
  const fromLogname = parseUserIdentity(logname);
  if (fromLogname) return fromLogname;

  const whoami = await runCommand("whoami", [], 2500);
  return parseUserIdentity(whoami);
}

function normalizeSiUsers(siUsers: any): NormalizedUser[] {
  if (!Array.isArray(siUsers)) return [];

  const users: NormalizedUser[] = [];

  for (const entry of siUsers) {
    const raw = entry?.user || entry?.name || entry?.username;
    const normalized = parseUserIdentity(raw);

    if (!normalized) continue;

    const date = entry?.date ? String(entry.date) : null;
    const time = entry?.time ? String(entry.time) : null;

    users.push({
      ...normalized,
      raw: normalized.raw || String(raw),
      isLoggedIn: true,
      lastLogon: date && time ? `${date} ${time}` : null
    });
  }

  return users;
}

function dedupeUsers(users: NormalizedUser[]): NormalizedUser[] {
  const seen = new Set<string>();
  const out: NormalizedUser[] = [];

  for (const user of users) {
    const key = `${user.domain || ""}\\${user.user}`.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(user);
  }

  return out;
}

async function buildLoggedInUsers(siUsers: any): Promise<NormalizedUser[]> {
  const preferred = await getInteractiveUserFromOs();
  const fromSi = normalizeSiUsers(siUsers);

  return dedupeUsers([
    ...(preferred ? [preferred] : []),
    ...fromSi
  ]);
}

function isPrivateIpv4(ip?: string | null): boolean {
  if (!ip) return false;

  if (/^10\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;

  const m = ip.match(/^172\.(\d{1,2})\./);
  if (m) {
    const second = Number(m[1]);
    return second >= 16 && second <= 31;
  }

  return false;
}

function isUsableIpv4(ip?: string | null): boolean {
  if (!ip) return false;
  if (ip === "127.0.0.1") return false;
  if (ip.startsWith("169.254.")) return false;
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip);
}

function inferInterfaceType(iface: any): string | undefined {
  const text = `${iface?.iface || ""} ${iface?.ifaceName || ""} ${iface?.name || ""} ${iface?.type || ""}`.toLowerCase();

  if (text.includes("wi-fi") || text.includes("wifi") || text.includes("wireless") || /^en0\b/.test(text) || /^wlan/.test(text)) {
    return "wifi";
  }

  if (text.includes("ethernet") || /^eth/.test(text) || /^en\d+\b/.test(text)) {
    return "ethernet";
  }

  if (text.includes("vpn") || text.includes("utun") || text.includes("tun") || text.includes("tap")) {
    return "vpn";
  }

  if (text.includes("loopback") || text.includes("lo0") || text === "lo") {
    return "loopback";
  }

  return iface?.type ? String(iface.type) : undefined;
}

function normalizeNetworkInterfaces(net: any, defaultInterface?: string | null): NormalizedNetworkInterface[] {
  if (!Array.isArray(net)) return [];

  const defaultName = String(defaultInterface || "").trim().toLowerCase();

  const normalized = net
    .map((iface: any): NormalizedNetworkInterface => {
      const name = String(iface?.iface || iface?.name || iface?.ifaceName || "").trim() || undefined;
      const displayName = String(iface?.ifaceName || iface?.name || iface?.iface || "").trim() || name;
      const ip4 = String(iface?.ip4 || iface?.ipv4 || "").trim() || null;
      const ip6 = String(iface?.ip6 || iface?.ipv6 || "").trim() || null;
      const mac = String(iface?.mac || "").trim() || undefined;
      const internal = Boolean(iface?.internal);
      const isDefault = Boolean(defaultName && name && name.toLowerCase() === defaultName);

      return {
        name,
        displayName,
        mac,
        ip4,
        ip6,
        internal,
        default: isDefault,
        type: inferInterfaceType(iface)
      };
    })
    .filter(iface => iface.name || iface.ip4 || iface.ip6 || iface.mac);

  const preferredIndex = normalized.findIndex(iface =>
    !iface.internal &&
    Boolean(iface.default) &&
    isUsableIpv4(iface.ip4)
  );

  const privateIndex = normalized.findIndex(iface =>
    !iface.internal &&
    isUsableIpv4(iface.ip4) &&
    isPrivateIpv4(iface.ip4)
  );

  const usableIndex = normalized.findIndex(iface =>
    !iface.internal &&
    isUsableIpv4(iface.ip4)
  );

  const selectedIndex = preferredIndex >= 0
    ? preferredIndex
    : privateIndex >= 0
    ? privateIndex
    : usableIndex;

  if (selectedIndex >= 0) {
    normalized.forEach((iface, index) => {
      iface.default = index === selectedIndex;
    });

    const selected = normalized.splice(selectedIndex, 1)[0];
    normalized.unshift(selected);
  }

  return normalized;
}

function buildDeviceIdentity(ctx: AgentContext) {
  const nodePlatform = os.platform();
  const platform: "windows" | "macos" | "linux" =
    nodePlatform === "win32"
      ? "windows"
      : nodePlatform === "darwin"
      ? "macos"
      : "linux";
  return {
    deviceId: ctx.enrollment.deviceId,
    tenantId: ctx.enrollment.tenantId,
    hostname: os.hostname(),
    fqdn: os.hostname(),
    domain: platform === "windows" ? process.env.USERDOMAIN || undefined : undefined,
    platform
  };
}

async function buildHardwareNamespace(): Promise<{ static: HardwareStatic; runtime: HardwareRuntime }> {
  // Only the si.* calls whose results actually land in HardwareStatic/HardwareRuntime.
  // Historically this fanned out to 24 calls (audio/bluetooth/usb/printer/battery/wifi/
  // networkStats/time/cpuCurrentSpeed + an inetLatency ping to 8.8.8.8 every tick) whose
  // results were collected and then discarded — pure waste on the endpoint. Trimmed.
  const [
    osInfo,
    system,
    baseboard,
    chassis,
    bios,
    cpu,
    mem,
    memLayout,
    diskLayout,
    graphics,
    net,
    defaultNetworkInterface,
    users,
    fsSize
  ] = await Promise.all([
    si.osInfo(),
    si.system(),
    si.baseboard(),
    si.chassis(),
    si.bios(),
    si.cpu(),
    si.mem(),
    si.memLayout(),
    si.diskLayout(),
    si.graphics(),
    si.networkInterfaces().catch(() => [] as any[]),
    si.networkInterfaceDefault().catch(() => null as any),
    si.users().catch(() => [] as any[]),
    si.fsSize()
  ]);

  const isVirtual =
    system.virtual === true ||
    (typeof system.virtual === "string" &&
      String(system.virtual).toLowerCase().includes("virtual"));

  const normalizedUsers = await buildLoggedInUsers(users);
  const networkInterfaces = normalizeNetworkInterfaces(net, defaultNetworkInterface);

  const staticPart: HardwareStatic = {
    system: {
      manufacturer: system.manufacturer,
      model: system.model,
      version: system.version,
      serial: system.serial,
      uuid: system.uuid,
      sku: system.sku,
      virtual: isVirtual
    },
    baseboard,
    chassis,
    bios: [bios],
    os: {
      platform: ((): "windows" | "macos" | "linux" => {
        const p = os.platform();
        return p === "win32" ? "windows" : p === "darwin" ? "macos" : "linux";
      })(),
      distro: osInfo.distro,
      release: osInfo.release,
      kernel: osInfo.kernel
    },
    uuid: system.uuid,
    versions: {
      kernel: osInfo.kernel,
      node: process.version,
      v8: process.versions.v8
    },
    // Normalized to stable, slim shapes (see normalize-hardware.ts). Preserves
    // the cpu fields consumers read (brand/manufacturer/vendor/model/
    // physicalCores); graphics/memLayout/diskLayout are slimmed to identifying
    // fields (no serving path reads them). Runtime disks below still derive
    // from the RAW si.diskLayout, so they are unaffected.
    cpu: normalizeCpu(cpu),
    graphics: normalizeGraphics(graphics),
    memLayout: normalizeMemLayout(memLayout),
    diskLayout: normalizeDiskLayout(diskLayout),
    users: normalizedUsers,
    networkInterfaces
  };

  const runtimePart: HardwareRuntime = {
    memoryBytes: mem?.total,

    disks: Array.isArray(diskLayout)
      ? diskLayout.map(d => ({
          name: d.name,
          type: d.type,
          sizeBytes: d.size
        }))
      : undefined,

    filesystems: Array.isArray(fsSize)
      ? fsSize.map(f => ({
          fs: f.fs,
          type: f.type,
          sizeBytes: f.size,
          usedBytes: f.used,
          mount: f.mount
        }))
      : undefined,

    isVirtualMachine: isVirtual
  };

  return {
    static: staticPart,
    runtime: runtimePart
  };
}

// Canonicalize Node's `os.arch()` to the string values the backend's
// binaries metadata API accepts ("arm64" / "x64"). We don't filter
// unknown values — if a new arch shows up (riscv64, etc.) it flows
// through as-is so the backend can log it and we can decide whether
// to ship binaries for it.
function canonicalArch(): string {
  const raw = os.arch();
  if (raw === "x64") return "x64";
  if (raw === "arm64") return "arm64";
  // Legacy/edge values that modern Node can still emit.
  if (raw === "ia32") return "x64";        // 32-bit Windows agent is rare, treat as x64 for blob lookup
  return raw;
}

function buildAgentInfo(ctx: AgentContext) {
  const nodePlatform = os.platform();
  const platform: "windows" | "macos" | "linux" =
    nodePlatform === "win32"
      ? "windows"
      : nodePlatform === "darwin"
      ? "macos"
      : "linux";

  const capabilities = Array.from(new Set([
    ...(ctx.enrollment.bootstrap.capabilities || []),
    ...ctx.policyRuntime.getEnabledPlugins()
  ])) as AgentCapability[];

  return {
    agentVersion: ctx.config.agentVersion,
    coreVersion: ctx.config.coreVersion,
    osProvider: platform,
    arch: canonicalArch(),
    capabilities,
    install: {
      // Nota v1: installId podría ser distinto a deviceId; lo dejamos así por ahora.
      installId: ctx.enrollment.deviceId,
      channel: ctx.enrollment.bootstrap.channel,
      firstSeenAtUtc: ctx.enrollment.enrolledAtUtc
    }
  };
}

function stableStringify(obj: unknown): string {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(stableStringify).join(",")}]`;
  const keys = Object.keys(obj).sort();
  return `{${keys.map(k => `"${k}":${stableStringify((obj as any)[k])}`).join(",")}}`;
}

function hashObject(obj: unknown): string {
  const json = stableStringify(obj);
  return "sha256:" + crypto.createHash("sha256").update(json).digest("hex");
}

export function buildDeviceBaseline(
  ctx: AgentContext,
  hardware: { static: any; runtime: any }
) {
  const device = buildDeviceIdentity(ctx);
  const agent = buildAgentInfo(ctx);

  const baseline = {
    device,
    agent,
    hardware: hardware.static // ONLY static part participates in baseline
  };

  return {
    baseline,
    baselineHash: hashObject(baseline)
  };
}

export async function buildDeviceDelta(
  ctx: AgentContext,
  namespaces: Namespaces
) {
  return {
    namespaces,
    collectedAtUtc: new Date().toISOString()
  };
}

export async function buildDeviceFacts(
  ctx: AgentContext,
  namespaces: Namespaces
): Promise<DeviceFacts> {
  const hardware = await buildHardwareNamespace();
  const { baseline, baselineHash } = buildDeviceBaseline(ctx, hardware);
  const outNamespaces: Namespaces = { ...namespaces };

  if (namespaces.amp) {
    const ampIn: AmpNamespace = namespaces.amp;
    const swIn = ampIn.software;

    const software: SoftwareInventory = swIn
      ? {
          count: swIn.count ?? 0,
          delta: swIn.delta ?? null,
          items: Array.isArray(swIn.items) ? [...swIn.items] : undefined,
          hasChanges: swIn.hasChanges ?? false
        }
      : {
          count: 0,
          delta: null,
          items: undefined,
          hasChanges: false
        };

    const security: SecurityInfo = (ampIn.security ?? {}) as SecurityInfo;

    // Preserve the printers inventory the provider collected. Same shape and
    // slim-delta discipline as software (elided items[] on no-change cycles,
    // full items[] on first-run/forced). Previously dropped here, which left
    // the entire printers pipeline (providers + backend applyPrinterDelta +
    // device_printers table + UI) collecting/expecting data that never shipped.
    const printers: PrinterInventory | undefined = ampIn.printers
      ? {
          count: ampIn.printers.count ?? 0,
          delta: ampIn.printers.delta ?? null,
          items: Array.isArray(ampIn.printers.items) ? [...ampIn.printers.items] : undefined,
          hasChanges: ampIn.printers.hasChanges ?? false
        }
      : undefined;

    outNamespaces.amp = {
      hardware: {
        static: hardware.static,
        runtime: hardware.runtime
      },
      security,
      software,
      ...(printers ? { printers } : {})
    };
  }

  return {
    schemaVersion: "1.0",
    collectedAtUtc: new Date().toISOString(),
    agent: baseline.agent,
    device: {
      deviceId: baseline.device.deviceId,
      tenantId: baseline.device.tenantId,
      hostname: baseline.device.hostname,
      fqdn: baseline.device.fqdn,
      domain: baseline.device.domain,
      platform: baseline.device.platform
    },
    namespaces: outNamespaces,
    _meta: {
      baselineHash
    }
  };
}
