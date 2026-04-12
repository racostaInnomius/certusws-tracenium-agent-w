// src/plugins/amp/providers/macos.ts
import os from "os";
import si from "systeminformation";
import { exec } from "child_process";
import { promisify } from "util";
import fs from "fs";

import type { AgentContext } from "../../../core/agent-context";
import type { AmpNamespace } from "../../../domain/amp-types";
import type { SoftwareApplication } from "../../../domain/normalize-app";

import { normalizeApp } from "../../../domain/normalize-app";
import { computeSoftwareDelta, toBaselineOps } from "../../../domain/software-inventory-delta";
import {
  loadSoftwareBaseline,
  upsertSoftwareBaseline,
  deleteSoftwareByIds
} from "../../../domain/software-baseline-repo";

const execAsync = promisify(exec);

type RawMacApp = {
  name?: string | null;
  version?: string | null;
  bundleId?: string | null;
  installLocation?: string | null;
};

/**
 * Enterprise-grade hybrid macOS software collector (Applications, Utilities, User Apps, Homebrew, pkgutil)
 */
async function collectMacSoftware(): Promise<SoftwareApplication[]> {
  try {
    const appDirs = [
      "/Applications",
      "/Applications/Utilities",
      `${os.homedir()}/Applications`
    ];

    const appPaths: string[] = [];

    for (const dir of appDirs) {
      try {
        if (!fs.existsSync(dir)) continue;

        const entries = fs.readdirSync(dir);
        for (const entry of entries) {
          if (entry.endsWith(".app")) {
            appPaths.push(`${dir}/${entry}`);
          }
        }
      } catch {
        // ignore directory errors
      }
    }

    // Deduplicate paths
    const uniquePaths = Array.from(new Set(appPaths));

    // Parallel mdls with concurrency limit
    const concurrency = 5;
    const results: SoftwareApplication[] = [];

    async function processBatch(batch: string[]) {
      await Promise.all(
        batch.map(async (appPath) => {
          const appName = appPath.split("/").pop() || "";
          const name = appName.replace(/\.app$/, "");

          let bundleId: string | null = null;

          try {
            const safePath = appPath.replace(/"/g, '\\"');
            const { stdout } = await execAsync(
              `mdls -name kMDItemCFBundleIdentifier -raw "${safePath}"`,
              { timeout: 5000 }
            );
            bundleId = stdout.trim() || null;
          } catch {
            bundleId = null;
          }

          const normalized = normalizeApp({
            name,
            version: null,
            publisher: null,
            installLocation: appPath,
            packageFamilyName: bundleId,
            source: "macos-app-bundle"
          });

          if (normalized && normalized.name) {
            results.push(normalized as SoftwareApplication);
          }
        })
      );
    }

    for (let i = 0; i < uniquePaths.length; i += concurrency) {
      const batch = uniquePaths.slice(i, i + concurrency);
      await processBatch(batch);
    }

    // --- Homebrew packages ---
    try {
      const { stdout } = await execAsync("brew list --versions", {
        maxBuffer: 1024 * 1024 * 5,
        timeout: 5000
      });

      const lines = stdout.split("\n").map(l => l.trim()).filter(Boolean);

      for (const line of lines) {
        const [name, version] = line.split(" ");

        const normalized = normalizeApp({
          name,
          version,
          publisher: "homebrew",
          installLocation: "/opt/homebrew",
          packageFamilyName: name,
          source: "homebrew"
        });

        if (normalized && normalized.name) {
          results.push(normalized as SoftwareApplication);
        }
      }
    } catch {
      // brew not installed
    }

    // --- pkgutil packages ---
    try {
      const { stdout } = await execAsync("pkgutil --pkgs", {
        maxBuffer: 1024 * 1024 * 5,
        timeout: 5000
      });

      const pkgs = stdout.split("\n").map(p => p.trim()).filter(Boolean);

      for (const pkg of pkgs) {
        const normalized = normalizeApp({
          name: pkg,
          version: null,
          publisher: "pkgutil",
          installLocation: "/",
          packageFamilyName: pkg,
          source: "pkgutil"
        });

        if (normalized && normalized.name) {
          results.push(normalized as SoftwareApplication);
        }
      }
    } catch {
      // ignore
    }

    // Deduplicate by installId
    const map = new Map<string, SoftwareApplication>();
    for (const app of results) {
      if (!app.installId) continue;
      map.set(app.installId, app);
    }

    return Array.from(map.values());
  } catch (err) {
    console.warn("[MACOS] enterprise collector failed", err);
    return [];
  }
}

/**
 * Hardware collection (cross-platform via systeminformation)
 */
async function collectMacHardware(): Promise<AmpNamespace["hardware"]> {
  const [system, cpu, mem, diskLayout, fsSize] = await Promise.all([
    si.system(),
    si.cpu(),
    si.mem(),
    si.diskLayout().catch(() => [] as any[]),
    si.fsSize().catch(() => [] as any[])
  ]);

  return {
    static: {
      system: {
        manufacturer: system.manufacturer || "Apple",
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
  };
}

async function collectMacSecurity(ctx: AgentContext): Promise<AmpNamespace["security"]> {
  const unknown: AmpNamespace["security"] = {
    bitlocker: { status: "unknown" },
    defender: { status: "unknown" },
    firewall: { status: "unknown" }
  };

  try {
    const resp = await ctx.priv.call({
      v: 1,
      id: `security-posture-${Date.now()}`,
      method: "security.compliance",
      params: {},
      meta: {
        tenantId: ctx.enrollment.tenantId,
        deviceId: ctx.enrollment.deviceId
      }
    } as any);

    if (!resp?.ok) return unknown;

    const posture = resp.result || {};
    return {
      bitlocker: {
        status: posture.filevault?.status ?? "unknown",
        raw: posture.filevault
      } as any,
      defender: {
        status: posture.gatekeeper?.status ?? "unknown",
        raw: {
          gatekeeper: posture.gatekeeper,
          sip: posture.sip
        }
      } as any,
      firewall: {
        status: posture.firewall?.status ?? "unknown",
        raw: posture.firewall
      } as any
    };
  } catch {
    return unknown;
  }
}

export const macProvider = {
  async collect(ctx: AgentContext): Promise<AmpNamespace> {
    if (os.platform() !== "darwin") {
      throw new Error("macosProvider called on non-macOS platform");
    }

    const hardware = await collectMacHardware();
    const security = await collectMacSecurity(ctx);

    let software: AmpNamespace["software"] = {
      count: 0,
      items: undefined,
      delta: null,
      hasChanges: false
    };

    try {
      const apps = await collectMacSoftware();

      if (!apps || apps.length === 0) {
        console.warn("[MACOS] EMPTY INVENTORY");

        const previous = loadSoftwareBaseline() ?? [];
        if (previous.length > 0) {
          deleteSoftwareByIds(previous.map(x => x.installId).filter(Boolean) as string[]);
        }

        return {
          hardware,
          security,
          software: {
            count: 0,
            items: [],
            delta: null,
            hasChanges: true
          }
        };
      }

      // Deterministic ordering
      apps.sort((a, b) =>
        (a.installId ?? "").localeCompare(b.installId ?? "")
      );

      const previous = loadSoftwareBaseline() ?? [];
      const isFirstRun = previous.length === 0;

      if (isFirstRun) {
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
          const { upserts, deletes } = toBaselineOps(deltaResult.delta);

          if (upserts.length > 0) {
            upsertSoftwareBaseline(upserts);
          }

          if (deletes.length > 0) {
            deleteSoftwareByIds(deletes);
          }

          software = {
            count: deltaResult.currentCount,
            items: apps,
            delta: deltaResult.delta,
            hasChanges: true
          };
        } else {
          software = {
            count: deltaResult.currentCount,
            items: undefined,
            delta: null,
            hasChanges: false
          };

          return {
            hardware,
            security,
            software
          };
        }
      }

    } catch (err) {
      console.error("[MACOS] collection failed", err);
    }

    return {
      hardware,
      security,
      software
    };
  }
};
