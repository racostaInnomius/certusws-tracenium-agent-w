// src/domain/device-facts-builder.ts
import os from "os";
import si from "systeminformation";
import type { AgentContext } from "../core/agent-context";
import type { DeviceFacts } from "./device-facts";
import crypto from "crypto";

function buildDeviceIdentity(ctx: AgentContext) {
  const platform = os.platform() as "win32" | "darwin" | "linux";
  return {
    deviceId: ctx.enrollment.deviceId,
    tenantId: ctx.enrollment.tenantId,
    hostname: os.hostname(),
    fqdn: os.hostname(),
    domain: platform === "win32" ? process.env.USERDOMAIN || undefined : undefined,
    platform
  };
}

async function buildHardwareNamespace() {
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
    currentLoad,
    cpuCurrentSpeed,
    temp,
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
    si.currentLoad(),
    si.cpuCurrentSpeed(),
    si.cpuTemperature(),
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

  const staticPart = {
    version: {},
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
      platform: os.platform(),
      distro: osInfo.distro,
      release: osInfo.release,
      kernel: osInfo.kernel,
      arch: os.arch(),
      hostname: os.hostname()
    },
    uuid: {
      os: (osInfo as any).uuid ?? undefined,
      hardware: system.uuid
    },
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

  const runtimePart = {
    networkInterfaces: net,
    audio,
    bluetooth,
    usb,
    printer,
    time,
    cpuCurrentSpeed,
    currentLoad,
    temp,
    users,
    battery,
    mem,
    fsSize,
    inetLatency,
    wifiNetworks,
    networkStats
  };

  return {
    static: staticPart,
    runtime: runtimePart
  };
}

function buildAgentInfo(ctx: AgentContext) {
  const platform = os.platform() as "win32" | "darwin" | "linux";

  const osProvider: "windows" | "macos" | "linux" =
    platform === "win32"
      ? "windows"
      : platform === "darwin"
      ? "macos"
      : "linux";

  return {
    agentVersion: ctx.config.agentVersion,
    coreVersion: ctx.config.coreVersion,
    osProvider,
    capabilities: ctx.enrollment.bootstrap.capabilities,
    install: {
      // Nota v1: installId podría ser distinto a deviceId; lo dejamos así por ahora.
      installId: ctx.enrollment.deviceId,
      channel: ctx.enrollment.bootstrap.channel,
      firstSeenAtUtc: ctx.enrollment.enrolledAtUtc
    }
  };
}

function stableStringify(obj: any): string {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(stableStringify).join(",")}]`;
  const keys = Object.keys(obj).sort();
  return `{${keys.map(k => `"${k}":${stableStringify(obj[k])}`).join(",")}}`;
}

function hashObject(obj: any): string {
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
  namespaces: Record<string, any>
) {
  return {
    namespaces,
    collectedAtUtc: new Date().toISOString()
  };
}

export async function buildDeviceFacts(
  ctx: AgentContext,
  namespaces: Record<string, any>
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
      amm: {
        ...(namespaces.amm || {}),
        hardware: {
          ...hardware.static,
          ...hardware.runtime
        },
        software: namespaces.amm?.software
      }
    },
    _meta: {
      baselineHash
    }
  } as any;
}
