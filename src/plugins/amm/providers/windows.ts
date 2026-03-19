// src/plugins/amm/providers/windows.ts
import os from "os";
import si from "systeminformation";
import type { AgentContext } from "../../../core/agent-context";
import { normalizeApp } from "../../../domain/normalize-app";
import { computeSoftwareDelta } from "../../../domain/software-inventory-delta";
import { loadSoftwareBaseline, saveSoftwareBaseline } from "../../../domain/software-baseline-repo";

export type AmmNamespace = {
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
    disks?: Array<{
      name?: string;
      type?: string;
      sizeBytes?: number;
      serial?: string;
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

  security: {
    /**
     * "unknown" until we implement win.security.posture in PrivSvc.
     * Keep these fields stable now; backend can accept partials.
     */
    bitlocker?: { status: "enabled" | "disabled" | "unknown"; drives?: string[] };
    defender?: { status: "enabled" | "disabled" | "unknown" };
    firewall?: { status: "enabled" | "disabled" | "unknown" };
  };

  software: {
    count: number;
    delta: any;
  };
};

type RawApp = {
  name?: string | null;
  version?: string | null;
  publisher?: string | null;
  installLocation?: string | null;
  packageFamilyName?: string | null;
  source?: string | null;
};

/**
 * L2: device + hardware (non-privileged reads via systeminformation)
 */
async function collectWindowsDeviceAndHardware(): Promise<
  Pick<AmmNamespace, "hardware">
> {
  const [osInfo, system, cpu, mem, diskLayout, fsSize] = await Promise.all([
    si.osInfo(),
    si.system(),
    si.cpu(),
    si.mem(),
    si.diskLayout().catch(() => [] as any[]),
    si.fsSize().catch(() => [] as any[])
  ]);

  const arch = os.arch() as "x64" | "arm64" | "x86";

  return {
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
      isVirtualMachine: Boolean((system as any).virtual),

      disks: (diskLayout || []).map((d: any) => ({
        name: d.name || d.device || undefined,
        type: d.type || undefined,
        sizeBytes: typeof d.size === "number" ? d.size : undefined,
        serial: d.serialNum || d.serial || undefined
      })),

      filesystems: (fsSize || []).map((f: any) => ({
        fs: f.fs || undefined,
        type: f.type || undefined,
        sizeBytes: typeof f.size === "number" ? f.size : undefined,
        usedBytes: typeof f.used === "number" ? f.used : undefined,
        mount: f.mount || undefined
      }))
    }
  };
}

/**
 * L2: security posture should come from PrivSvc (admin boundary).
 * For now we attempt a call if implemented; otherwise default to "unknown".
 */
async function collectWindowsSecurity(ctx: AgentContext): Promise<AmmNamespace["security"]> {
  const unknown: AmmNamespace["security"] = {
    bitlocker: { status: "unknown" },
    defender: { status: "unknown" },
    firewall: { status: "unknown" }
  };

  // If PrivSvc isn't available yet (or method not implemented), keep unknown.
  try {
    const resp = await ctx.priv.call({
      v: 1,
      id: `sec_${Date.now()}`,
      method: "win.security.posture",
      params: { includeBitlocker: true, includeDefender: true, includeFirewall: true },
      meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
    });

    if (!resp.ok) return unknown;

    const r = resp.result || {};
    return {
      bitlocker: r.bitlocker ?? unknown.bitlocker,
      defender: r.defender ?? unknown.defender,
      firewall: r.firewall ?? unknown.firewall
    };
  } catch {
    return unknown;
  }
}

export async function collectWindowsSoftwareInventory(ctx: AgentContext) {
  const resp = await ctx.priv.call({
    v: 1,
    id: `inv_${Date.now()}`,
    method: "win.software.inventory",
    params: { includeStoreApps: true },
    meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
  });

  if (!resp.ok) {
    throw new Error(
      `PrivSvc inventory failed: ${resp.error?.code} ${resp.error?.message}`
    );
  }

  const apps = (resp.result?.apps ?? []) as RawApp[];

  const normalized = apps
    .map((a) =>
      normalizeApp({
        name: a.name ?? null,
        version: a.version ?? null,
        publisher: a.publisher ?? null,
        installLocation: a.installLocation ?? null,
        packageFamilyName: a.packageFamilyName ?? null,
        source: a.source ?? "win32-registry"
      })
    )
    .filter((x) => x && x.name);

  return {
    count: normalized.length,
    apps: normalized
  };
}

export const windowsProvider = {
  async collect(ctx: AgentContext): Promise<AmmNamespace> {
    if (os.platform() !== "win32") {
      throw new Error("windowsProvider.collect() called on non-Windows platform");
    }

    // Device + hardware should be reliable even if PrivSvc is down.
    const base = await collectWindowsDeviceAndHardware();

    // Security + software rely on PrivSvc; degrade gracefully.
    let security: AmmNamespace["security"] = {
      bitlocker: { status: "unknown" },
      defender: { status: "unknown" },
      firewall: { status: "unknown" }
    };

    let software: any = { count: 0, delta: null };

    try {
      security = await collectWindowsSecurity(ctx);
    } catch {
      // keep unknown
    }

    try {
      const result = await collectWindowsSoftwareInventory(ctx);

      const previous = loadSoftwareBaseline();
      const deltaResult = computeSoftwareDelta(result.apps as any, previous);

      if (deltaResult.hasChanges) {
        saveSoftwareBaseline(result.apps as any);
      }

      software = {
        count: deltaResult.currentCount,
        delta: deltaResult.delta
      };
    } catch {
      // keep empty
    }

    return {
      hardware: base.hardware,
      security,
      software
    };
  }
};