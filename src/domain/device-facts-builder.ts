// src/domain/device-facts-builder.ts
import os from "os";
import si from "systeminformation";
import type { AgentContext } from "../core/agent-context";
import type { DeviceFacts, Namespaces, AgentCapability } from "./device-facts";
import crypto from "crypto";
import type {
  AmmNamespace,
  HardwareStatic,
  HardwareRuntime,
  SecurityInfo,
  SoftwareInventory
} from "./amm-types";

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
    time,
    cpuCurrentSpeed,
    audio,
    bluetooth,
    usb,
    printer,
    users,
    battery,
    fsSize,
    wifiNetworks,
    networkStats,
    inetLatency
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
    si.networkInterfaces(),
    si.time(),
    si.cpuCurrentSpeed(),
    si.audio(),
    si.bluetoothDevices(),
    si.usb(),
    si.printer(),
    si.users(),
    si.battery(),
    si.fsSize(),
    si.wifiNetworks(),
    si.networkStats(),
    si.inetLatency("8.8.8.8")
  ]);

  const isVirtual =
    system.virtual === true ||
    (typeof system.virtual === "string" &&
      String(system.virtual).toLowerCase().includes("virtual"));

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
    cpu,
    graphics,
    memLayout,
    diskLayout
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

function buildAgentInfo(ctx: AgentContext) {
  const nodePlatform = os.platform();
  const platform: "windows" | "macos" | "linux" =
    nodePlatform === "win32"
      ? "windows"
      : nodePlatform === "darwin"
      ? "macos"
      : "linux";

  return {
    agentVersion: ctx.config.agentVersion,
    coreVersion: ctx.config.coreVersion,
    osProvider: platform,
    capabilities: ctx.enrollment.bootstrap.capabilities as AgentCapability[],
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
    namespaces: {
      ...namespaces,
      amm: (() => {
        const ammIn: AmmNamespace | undefined = namespaces?.amm;
        const swIn = ammIn?.software;

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

        const security: SecurityInfo = (ammIn?.security ?? {}) as SecurityInfo;

        const ammOut: AmmNamespace = {
          hardware: {
            static: hardware.static,
            runtime: hardware.runtime
          },
          security,
          software
        };

        return ammOut;
      })()
    },
    _meta: {
      baselineHash
    }
  };
}
