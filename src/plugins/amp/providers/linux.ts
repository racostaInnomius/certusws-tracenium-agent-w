// src/plugins/amp/providers/linux.ts
//
// Linux AMP (Asset Management Plugin) provider. Collects software
// inventory via dpkg/rpm/snap/flatpak and reports security posture
// (currently stubbed — Phase 5 wires it to privsvc security.compliance).
//
// Architectural note for future readers:
//   The `hardware` block this provider returns is OVERWRITTEN by
//   `buildDeviceFacts` in src/domain/device-facts-builder.ts (~line
//   266) which builds its own hardware namespace via systeminformation
//   cross-platform. So the `collectLinuxHardware()` work below is
//   effectively dead code on the wire — the only fields that survive
//   to FACTS_SNAPSHOT are software + security. We keep the hardware
//   collection here because it's cheap and matches the macOS/windows
//   provider shape, in case the builder is ever refactored to defer
//   to providers for OS-specific details.
import os from "os";
import si from "systeminformation";
import { execFile } from "child_process";
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

// execFile takes an argv array — no shell interpolation, so package
// names returned by dpkg/rpm/snap/flatpak that happen to contain shell
// metacharacters are harmless. (Previous version used `exec` with
// shell strings, mirroring a small attack surface for any future
// caller that ever passed user-controlled arguments. Migrating
// matches the macOS provider's safer pattern.)
const execFileAsync = promisify(execFile);

// Software-listing commands on big systems can take noticeable time.
// On a stock RHEL 9 box with ~4 000 RPMs `rpm -qa` runs ~6-9 s; on a
// 10 000-package developer workstation we've seen 12 s. The previous
// 5 s timeout was tight enough to occasionally truncate the inventory
// silently (run() returns "" on timeout → empty list → DELETE BASELINE
// path, which churns deltas). Bump to 30 s — still well below the
// scheduler tick window so a hung subprocess can't stall heartbeats.
const PKG_LIST_TIMEOUT_MS = 30_000;

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

// Mirrors the macOS provider shape: when privsvc has a
// security.compliance handler it'll return real values; until Phase 5
// lands those handlers on Linux, this stays "unknown" and the
// dashboard treats the device as security-posture-pending. The
// agent-side fallback here is cheap and consistent with how macOS
// behaved before its own security-posture handler shipped.
async function collectLinuxSecurity(ctx: AgentContext): Promise<AmpNamespace["security"]> {
  const unknown: AmpNamespace["security"] = {
    bitlocker: { status: "unknown" },
    defender: { status: "unknown" },
    firewall: { status: "unknown" },
  };

  try {
    const resp = await ctx.priv.call({
      v: 1,
      id: `security-posture-${Date.now()}`,
      method: "security.compliance",
      params: {},
      meta: {
        tenantId: ctx.enrollment.tenantId,
        deviceId: ctx.enrollment.deviceId,
      },
    } as any);

    // Phase 3 ships before Phase 5, so the privsvc handler returns
    // `not_implemented` (router.ts) and resp.ok is false. That's not
    // an error — silently fall back to "unknown" so the agent doesn't
    // log noise at every inventory tick.
    if (!resp?.ok) return unknown;

    const posture = resp.result || {};

    // Map Linux-specific fields into the cross-platform shape. Once
    // Phase 5's security-posture.ts lands, the fields below will be:
    //   posture.firewall  →  { status: "enabled"|"disabled", impl: "ufw"|"firewalld"|"nftables"|"iptables" }
    //   posture.selinux   →  { mode: "enforcing"|"permissive"|"disabled" }   (rhel-family)
    //   posture.apparmor  →  { mode: "enforcing"|"complain"|"disabled" }     (debian-family)
    //
    // bitlocker/defender don't apply on Linux — they stay "unknown",
    // which is the documented signal for "this control is not
    // applicable on this OS" rather than a real unknown.
    return {
      bitlocker: { status: "unknown" },
      defender: { status: "unknown" },
      firewall: {
        status: posture.firewall?.status ?? "unknown",
        raw: posture.firewall,
      } as any,
    };
  } catch {
    // priv.call can throw if the IPC pipe is mid-reconnect. That's a
    // transient state — return unknown rather than letting it bubble
    // up and abort the entire AMP collection (which would cost us
    // the software inventory too).
    return unknown;
  }
}

// Wraps execFile with our standard timeout + maxBuffer + swallow-on-
// error semantics. Returns empty string on any failure so callers can
// uniformly check `out.length === 0` without try/catch noise.
async function run(bin: string, args: string[], timeoutMs = PKG_LIST_TIMEOUT_MS): Promise<string> {
  try {
    const { stdout } = await execFileAsync(bin, args, {
      maxBuffer: 1024 * 1024 * 10,
      timeout: timeoutMs,
    });
    return stdout;
  } catch {
    return "";
  }
}

// Cheap binary-presence check via fs.existsSync (no fork). The
// previous `test -x ... && echo yes` shell trick worked but spawned
// 4 shells per agent boot for nothing.
function hasExecutable(path: string): boolean {
  try {
    const stat = require("fs").statSync(path);
    // 0o111 = any execute bit (owner | group | other)
    return stat.isFile() && (stat.mode & 0o111) !== 0;
  } catch {
    return false;
  }
}

async function detectPackageManagers() {
  if (cachedPM) return cachedPM;

  cachedPM = {
    hasDpkg: hasExecutable("/usr/bin/dpkg") || hasExecutable("/bin/dpkg"),
    hasRpm: hasExecutable("/usr/bin/rpm") || hasExecutable("/bin/rpm"),
    hasSnap: hasExecutable("/usr/bin/snap") || hasExecutable("/snap/bin/snap"),
    hasFlatpak: hasExecutable("/usr/bin/flatpak") || hasExecutable("/var/lib/flatpak/bin/flatpak"),
  };

  return cachedPM;
}

async function collectDpkg(): Promise<SoftwareApplication[]> {
  // -W is the machine-readable form; `-f` controls the field layout.
  // Tab-separated so we can split on \t (package names never contain
  // tabs, but they CAN contain spaces in `Description` — old format).
  // We don't ask for description here.
  const out = await run("/usr/bin/dpkg-query", [
    "-W",
    "-f=${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n",
  ]);
  const lines = out.split("\n").filter(Boolean);
  const res: SoftwareApplication[] = [];

  for (const line of lines) {
    const parts = line.split("\t");
    if (parts.length < 3) continue;

    // Status-Abbrev is 3 chars: "ii " (installed) / "rc " (config files
    // only after remove) / "un " (never installed) etc. We only want
    // "ii" — fully installed and configured.
    const status = parts[0].trim();
    if (status !== "ii") continue;

    const name = parts[1];
    const version = parts[2];

    const n = normalizeApp({
      name,
      version,
      publisher: "dpkg",
      installLocation: "/",
      packageFamilyName: name,
      source: "dpkg",
    });

    if (n && n.name) res.push(n as SoftwareApplication);
  }

  return res;
}

async function collectRpm(): Promise<SoftwareApplication[]> {
  // Tab-separated — RPM names never contain tabs, but spaces can
  // appear in version strings of unusual packages so we avoid
  // space-splitting which broke parsing previously.
  const out = await run("/usr/bin/rpm", [
    "-qa",
    "--qf",
    "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n",
  ]);
  const lines = out.split("\n").filter(Boolean);
  const res: SoftwareApplication[] = [];

  for (const line of lines) {
    const [name, version] = line.split("\t");
    if (!name) continue;

    // Filter `gpg-pubkey-*`: rpm tracks imported GPG keys via the same
    // `rpm -qa` query, but they're not packages — they're trust
    // material in the rpmdb. Including them as "software" inflates the
    // inventory and creates spurious deltas every time a vendor adds
    // a new repo signing key. They appear as e.g.:
    //   gpg-pubkey  ec9c4172-65a90b91  (none)
    if (name.startsWith("gpg-pubkey")) continue;

    const n = normalizeApp({
      name,
      version,
      publisher: "rpm",
      installLocation: "/",
      packageFamilyName: name,
      source: "rpm",
    });

    if (n && n.name) res.push(n as SoftwareApplication);
  }

  return res;
}

async function collectSnap(): Promise<SoftwareApplication[]> {
  const out = await run("/usr/bin/snap", ["list"]);
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
      source: "snap",
    });

    if (n && n.name) res.push(n as SoftwareApplication);
  }

  return res;
}

async function collectFlatpak(): Promise<SoftwareApplication[]> {
  // --columns=application,version pairs application id with version,
  // tab-separated. We force the column order so a future flatpak
  // version that changes default column ordering won't break parsing.
  const out = await run("/usr/bin/flatpak", [
    "list",
    "--columns=application,version",
  ]);
  const lines = out.split("\n").filter(Boolean);
  const res: SoftwareApplication[] = [];

  for (const line of lines) {
    const [name, version] = line.split("\t");
    if (!name) continue;

    const n = normalizeApp({
      name,
      version,
      publisher: "flatpak",
      installLocation: "/var/lib/flatpak",
      packageFamilyName: name,
      source: "flatpak",
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
    const security = await collectLinuxSecurity(ctx);

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