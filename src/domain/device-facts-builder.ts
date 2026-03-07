// src/domain/device-facts-builder.ts
import os from "os";
import si from "systeminformation";
import type { AgentContext } from "../core/agent-context";
import type { DeviceFacts } from "./device-facts";

async function buildDeviceIdentity(ctx: AgentContext) {
  const osInfo = await si.osInfo();
  const system = await si.system();
  const cpu = await si.cpu();
  const mem = await si.mem();
  const net = await si.networkInterfaces();

  const platform = os.platform() as "win32" | "darwin" | "linux";
  const family: "windows" | "macos" | "linux" =
    platform === "win32"
      ? "windows"
      : platform === "darwin"
      ? "macos"
      : "linux";

  return {
    deviceId: ctx.enrollment.deviceId,
    tenantId: ctx.enrollment.tenantId,

    hostname: os.hostname(),
    fqdn: undefined,
    domain: process.env.USERDOMAIN || undefined,

    platform,

    os: {
      family,
      edition: osInfo.distro || undefined,
      version: osInfo.release || undefined,
      build: osInfo.build || undefined,
      arch: os.arch() as "x64" | "arm64" | "x86"
    },

    hardware: {
      manufacturer: system.manufacturer || undefined,
      model: system.model || undefined,
      serialNumber: system.serial || undefined,
      uuid: system.uuid || undefined,
      cpu: {
        vendor: cpu.manufacturer || undefined,
        model: cpu.brand || undefined,
        cores: cpu.cores || undefined,
        threads: cpu.physicalCores || undefined
      },
      memoryBytes: mem.total || undefined,
      isVirtualMachine: Boolean(system.virtual)
    },

    network: {
      interfaces: net
        .filter((i) => !i.internal)
        .map((i) => ({
          name: i.iface,
          mac: i.mac || undefined,
          ipv4: i.ip4 ? [i.ip4] : [],
          ipv6: i.ip6 ? [i.ip6] : [],
          gateway: (i as any).gateway || undefined,
          dns: []
        }))
    }
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

export async function buildDeviceFacts(
  ctx: AgentContext,
  namespaces: Record<string, any>
): Promise<DeviceFacts> {
  return {
    schemaVersion: "1.0",
    collectedAtUtc: new Date().toISOString(),
    agent: buildAgentInfo(ctx),
    device: await buildDeviceIdentity(ctx),
    namespaces
  };
}
