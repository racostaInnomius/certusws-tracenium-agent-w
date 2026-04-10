// src/plugins/amp/providers/windows.ts
import os from "os";
import si from "systeminformation";
import type { AgentContext } from "../../../core/agent-context";
import { normalizeApp } from "../../../domain/normalize-app";
import { computeSoftwareDelta, toBaselineOps } from "../../../domain/software-inventory-delta";
import { loadSoftwareBaseline, upsertSoftwareBaseline, deleteSoftwareByIds } from "../../../domain/software-baseline-repo";
import type { AmpNamespace } from "../../../domain/amp-types";
import type { SoftwareApplication } from "../../../domain/normalize-app";

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
  Pick<AmpNamespace, "hardware">
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
      static: {
        system: {
          manufacturer: system.manufacturer || undefined,
          model: system.model || undefined,
          version: system.version || undefined,
          serial: system.serial || undefined,
          uuid: system.uuid || undefined,
          virtual: Boolean((system as any).virtual)
        } as any,
        cpu: {
          manufacturer: cpu.manufacturer || undefined,
          brand: cpu.brand || undefined,
          cores: cpu.cores || undefined,
          physicalCores: cpu.physicalCores || undefined
        } as any,
        memLayout: undefined,
        diskLayout: diskLayout || undefined
      } as any,
      runtime: {
        mem: mem ? { total: mem.total } : undefined,
        fsSize: fsSize || undefined
      } as any
    }
  };
}

/**
 * L2: security posture should come from PrivSvc (admin boundary).
 * For now we attempt a call if implemented; otherwise default to "unknown".
 */
async function collectWindowsSecurity(ctx: AgentContext): Promise<AmpNamespace["security"]> {
  const unknown: AmpNamespace["security"] = {
    bitlocker: { status: "unknown" },
    defender: { status: "unknown" },
    firewall: { status: "unknown" }
  };

  // If PrivSvc isn't available yet (or method not implemented), keep unknown.
  try {
    const resp = await ctx.priv.call({
      v: 1,
      id: `sec_${Date.now()}`,
      method: "security.posture",
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
    method: "software.inventory",
    params: { includeStoreApps: true },
    meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
  });

  // FIX: support both "apps" (old contract) and "items" (current PrivSvc contract)
  const apps = (resp.result?.items ?? resp.result?.apps ?? []) as RawApp[];

  console.log("[WINDOWS] RAW INVENTORY", {
    hasItems: Array.isArray(resp.result?.items),
    hasApps: Array.isArray(resp.result?.apps),
    countItems: resp.result?.items?.length,
    countApps: resp.result?.apps?.length
  });

  if (!resp.ok) {
    throw new Error(
      `PrivSvc inventory failed: ${resp.error?.code} ${resp.error?.message}`
    );
  }

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

  console.log("[WINDOWS] NORMALIZED INVENTORY", {
    inputCount: apps.length,
    normalizedCount: normalized.length
  });

  return {
    count: normalized.length,
    apps: normalized
  };
}

export const windowsProvider = {
  async collect(ctx: AgentContext): Promise<AmpNamespace> {
    if (os.platform() !== "win32") {
      throw new Error("windowsProvider.collect() called on non-Windows platform");
    }

    // Device + hardware should be reliable even if PrivSvc is down.
    const base = await collectWindowsDeviceAndHardware();

    // Security + software rely on PrivSvc; degrade gracefully.
    let security: AmpNamespace["security"] = {
      bitlocker: { status: "unknown" },
      defender: { status: "unknown" },
      firewall: { status: "unknown" }
    };

    let software: AmpNamespace["software"] = {
      count: 0,
      items: undefined,
      delta: null,
      hasChanges: false
    };

    try {
      security = await collectWindowsSecurity(ctx);
    } catch {
      // keep unknown
    }

    try {
      const result = await collectWindowsSoftwareInventory(ctx);
      // ensure typing
      const apps: SoftwareApplication[] = result.apps as SoftwareApplication[];

      if (!apps || apps.length === 0) {
        console.warn("[AGENT] EMPTY INVENTORY RECEIVED — CLEARING BASELINE");

        const previous: SoftwareApplication[] = loadSoftwareBaseline() ?? [];
        const ids = previous
          .map(x => x.installId)
          .filter((id): id is string => Boolean(id));
        deleteSoftwareByIds(ids);

        return {
          hardware: base.hardware,
          security,
          software: {
            count: 0,
            items: [],
            delta: null,
            hasChanges: true
          }
        };
      }

      console.log("[AGENT] INVENTORY BEFORE BASELINE", {
        count: apps.length,
        //sample: apps.slice(0, 3)
      });

      // Ensure deterministic ordering before delta + hashing
      apps.sort((a: SoftwareApplication, b: SoftwareApplication) =>
        (a.installId ?? "").localeCompare(b.installId ?? "")
      );

      const previous: SoftwareApplication[] = loadSoftwareBaseline() ?? [];
      const isFirstRun = previous.length === 0;

      if (isFirstRun) {
        console.log("[AGENT] SOFTWARE BASELINE (first run)", {
          count: apps.length
        });

        software = {
          count: apps.length,
          items: apps,
          delta: null,
          hasChanges: true
        };

        upsertSoftwareBaseline(apps);

      } else {
        const deltaResult = computeSoftwareDelta(apps, previous);

        if (deltaResult.hasChanges) {
          console.log("[AGENT] SOFTWARE DELTA", {
            added: deltaResult.delta?.added?.length ?? 0,
            removed: deltaResult.delta?.removed?.length ?? 0,
            updated: deltaResult.delta?.updated?.length ?? 0
          });

          const { upserts, deletes } = toBaselineOps(deltaResult.delta);

          if (upserts.length > 0) {
            upsertSoftwareBaseline(upserts);
          }

          if (deletes.length > 0) {
            deleteSoftwareByIds(deletes);
          }

          software = {
            count: deltaResult.currentCount,
            items: apps, // CRITICAL: NEVER drop items
            delta: deltaResult.delta,
            hasChanges: true
          };
        } else {
          console.log("[AGENT] SOFTWARE NO CHANGES — SKIP PAYLOAD");

          software = {
            count: deltaResult.currentCount,
            items: undefined, // avoid affecting baseline hash / payload
            delta: null,
            hasChanges: false
          };

          // Do not update baseline, do not trigger downstream send
          return {
            hardware: base.hardware,
            security,
            software
          };
        }
      }

      console.log("[AGENT] software payload ready", {
        count: software.count,
        hasItems: !!software.items,
        items: software.items?.length,
        hasDelta: !!software.delta
      });

      console.log("[AGENT] payload size estimate (software only)", {
        approxBytes: JSON.stringify(software).length
      });

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