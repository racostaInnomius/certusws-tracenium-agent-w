// src/plugins/amp/providers/linux.ts
import os from "os";
import si from "systeminformation";
import { exec } from "child_process";
import { promisify } from "util";

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

let cachedPM: {
  hasDpkg: boolean;
  hasRpm: boolean;
  hasSnap: boolean;
  hasFlatpak: boolean;
} | null = null;

async function collectLinuxHardware(): Promise<AmpNamespace["hardware"]> {
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
  };
}

function collectLinuxSecurity(): AmpNamespace["security"] {
  return {
    bitlocker: { status: "unknown" },
    defender: { status: "unknown" },
    firewall: { status: "unknown" }
  };
}

async function run(cmd: string) {
  try {
    const { stdout } = await execAsync(cmd, {
      maxBuffer: 1024 * 1024 * 10,
      timeout: 5000
    });
    return stdout;
  } catch {
    return "";
  }
}

async function detectPackageManagers() {
  if (cachedPM) return cachedPM;

  const checks = await Promise.all([
    run("test -x /usr/bin/dpkg && echo yes"),
    run("test -x /usr/bin/rpm && echo yes"),
    run("test -x /usr/bin/snap && echo yes"),
    run("test -x /usr/bin/flatpak && echo yes")
  ]);

  cachedPM = {
    hasDpkg: checks[0].includes("yes"),
    hasRpm: checks[1].includes("yes"),
    hasSnap: checks[2].includes("yes"),
    hasFlatpak: checks[3].includes("yes")
  };

  return cachedPM;
}

async function collectDpkg(): Promise<SoftwareApplication[]> {
  const out = await run("dpkg -l");
  const lines = out.split("\n").slice(5);
  const res: SoftwareApplication[] = [];

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 3) continue;

    // Only installed packages (ii)
    if (parts[0] !== "ii") continue;

    const name = parts[1];
    const version = parts[2];

    const n = normalizeApp({
      name,
      version,
      publisher: "dpkg",
      installLocation: "/",
      packageFamilyName: name,
      source: "dpkg"
    });

    if (n && n.name) res.push(n as SoftwareApplication);
  }

  return res;
}

async function collectRpm(): Promise<SoftwareApplication[]> {
  const out = await run("rpm -qa --qf '%{NAME} %{VERSION}\\n'");
  const lines = out.split("\n").filter(Boolean);
  const res: SoftwareApplication[] = [];

  for (const line of lines) {
    const [name, version] = line.split(" ");

    const n = normalizeApp({
      name,
      version,
      publisher: "rpm",
      installLocation: "/",
      packageFamilyName: name,
      source: "rpm"
    });

    if (n && n.name) res.push(n as SoftwareApplication);
  }

  return res;
}

async function collectSnap(): Promise<SoftwareApplication[]> {
  const out = await run("snap list");
  const lines = out.split("\n").slice(1);
  const res: SoftwareApplication[] = [];

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 2) continue;

    const name = parts[0];
    const version = parts[1];

    const n = normalizeApp({
      name,
      version,
      publisher: "snap",
      installLocation: "/snap",
      packageFamilyName: name,
      source: "snap"
    });

    if (n && n.name) res.push(n as SoftwareApplication);
  }

  return res;
}

async function collectFlatpak(): Promise<SoftwareApplication[]> {
  const out = await run("flatpak list --columns=application,version");
  const lines = out.split("\n").filter(Boolean);
  const res: SoftwareApplication[] = [];

  for (const line of lines) {
    const [name, version] = line.split("\t");

    const n = normalizeApp({
      name,
      version,
      publisher: "flatpak",
      installLocation: "/var/lib/flatpak",
      packageFamilyName: name,
      source: "flatpak"
    });

    if (n && n.name) res.push(n as SoftwareApplication);
  }

  return res;
}

async function collectLinuxSoftware(): Promise<SoftwareApplication[]> {
  const pm = await detectPackageManagers();

  const results: SoftwareApplication[] = [];

  if (pm.hasDpkg) {
    results.push(...await collectDpkg());
  }

  if (pm.hasRpm) {
    results.push(...await collectRpm());
  }

  if (pm.hasSnap) {
    results.push(...await collectSnap());
  }

  if (pm.hasFlatpak) {
    results.push(...await collectFlatpak());
  }

  const all = results;

  const map = new Map<string, SoftwareApplication>();
  for (const app of all) {
    if (!app.installId) continue;
    map.set(app.installId, app);
  }

  return Array.from(map.values());
}

export const linuxProvider = {
  async collect(ctx: AgentContext): Promise<AmpNamespace> {
    if (os.platform() !== "linux") {
      throw new Error("linuxProvider called on non-Linux platform");
    }

    const hardware = await collectLinuxHardware();
    const security = collectLinuxSecurity();

    let software: AmpNamespace["software"] = {
      count: 0,
      items: undefined,
      delta: null,
      hasChanges: false
    };

    try {
      const apps: SoftwareApplication[] = await collectLinuxSoftware();

      if (!apps || apps.length === 0) {
        console.warn("[LINUX] EMPTY INVENTORY — CLEARING BASELINE");

        const previous: SoftwareApplication[] = loadSoftwareBaseline() ?? [];
        if (previous.length > 0) {
          const ids = previous
            .map(x => x.installId)
            .filter((id): id is string => Boolean(id));
          deleteSoftwareByIds(ids);
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

      apps.sort((a: SoftwareApplication, b: SoftwareApplication) =>
        (a.installId ?? "").localeCompare(b.installId ?? "")
      );

      const previous: SoftwareApplication[] = loadSoftwareBaseline() ?? [];
      const isFirstRun = previous.length === 0;

      if (isFirstRun) {
        software = {
          count: apps.length,
          items: apps,
          delta: null,
          hasChanges: true
        };

        upsertSoftwareBaseline(apps as SoftwareApplication[]);

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

          return { hardware, security, software };
        }
      }

    } catch (err) {
      console.error("[LINUX] collection failed", err);
    }

    return { hardware, security, software };
  }
};