// src/plugins/amp/providers/macos.ts
import os from "os";
import si from "systeminformation";
import { execFile } from "child_process";
import { promisify } from "util";
import fs from "fs";

import type { AgentContext } from "../../../core/agent-context";
import type { AmpNamespace } from "../../../domain/amp-types";
import type { SoftwareApplication } from "../../../domain/normalize-app";

import { normalizeApp } from "../../../domain/normalize-app";
import { computeSoftwareDelta, toBaselineOps } from "../../../domain/software-inventory-delta";
import { collectCupsPrinters } from "./printers-cups";
import {
  buildPrinterInventoryWithBaseline,
  emptyPrinterInventory
} from "./printers-pipeline";
import {
  loadSoftwareBaseline,
  upsertSoftwareBaseline,
  deleteSoftwareByIds
} from "../../../domain/software-baseline-repo";

// execFile does not spawn a shell — arguments are passed directly to the
// binary. This is critical for `mdls -name ... "$appPath"`: the path comes
// from filesystem enumeration and could contain shell metacharacters
// (backticks, $(…), newlines, ;) which would be interpreted if we used
// exec. execFile sidesteps the shell entirely, so path injection via a
// crafted .app directory name is not possible.
const execFileAsync = promisify(execFile);

/**
 * Order two Homebrew version directory names.
 *
 * Homebrew versions are dotted numbers with an optional `_N` revision
 * (`3.6.3`, `21.0.9`, `1.2.3_1`) and occasionally a non-numeric suffix.
 * A plain string sort puts "10" before "9", which would report the wrong
 * version as newest — so compare component by component, numerically
 * where both sides are numbers.
 */
export function compareBrewVersions(a: string, b: string): number {
  const parts = (v: string) => v.split(/[._-]/);
  const pa = parts(a);
  const pb = parts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = Number(pa[i]);
    const nb = Number(pb[i]);
    if (Number.isFinite(na) && Number.isFinite(nb)) {
      if (na !== nb) return na - nb;
      continue;
    }
    const sa = pa[i] ?? "";
    const sb = pb[i] ?? "";
    if (sa !== sb) return sa < sb ? -1 : 1;
  }
  return 0;
}



type RawMacApp = {
  name?: string | null;
  version?: string | null;
  bundleId?: string | null;
  installLocation?: string | null;
};

/**
 * Prefixes of Apple system-internal pkgutil receipts that should never
 * appear in a user-facing software inventory.
 *
 * Rules for adding a prefix here:
 *   - The package is system-owned and installed by macOS/SoftwareUpdate,
 *     not by a user action.
 *   - Dropping it doesn't hide any real user-installed app (Apple's
 *     user-facing apps have separate receipts OR come through the
 *     /Applications .app bundle collector).
 *
 * Matched by `startsWith`, case-sensitive — Apple's pkg ids are
 * consistently lowercase under `com.apple.pkg.*`.
 */
const APPLE_PKGUTIL_NOISE_PREFIXES = [
  "com.apple.pkg.MAContent10_",            // GarageBand / Logic sample libraries (hundreds of entries)
  "com.apple.pkg.XProtectPayloads_",       // XProtect malware definition bundles
  "com.apple.pkg.XProtectPlistConfigData_",// XProtect configuration plists
  "com.apple.pkg.MRTConfigData_",          // Malware Removal Tool config
  "com.apple.pkg.MobileAssets",            // On-demand assets (Siri voices, language packs…)
  "com.apple.pkg.CLTools_",                // Xcode Command Line Tools component receipts
  "com.apple.pkg.FirmwareUpdate",          // Firmware update receipts
  "com.apple.pkg.InputMethod_",            // Input method bundles
  "com.apple.pkg.GarageBand_AppStore",     // covered by .app bundle at /Applications/GarageBand.app
  "com.apple.pkg.iMovie_AppStore",         // same — user-facing, captured via .app
  "com.apple.pkg.XcodeSystemResources",    // Xcode internal receipt
  "com.apple.pkg.XcodeExtensionSupport"    // Xcode internal receipt
];

/**
 * Suffix patterns for arch-tagged sub-component receipts. macOS pkg-based
 * SDKs (notably .NET, but the same shape shows up for the JDK and a few
 * VS components) install each runtime piece as its own pkgutil receipt
 * carrying the version + target arch in the bundle id, e.g.
 *   com.microsoft.dotnet.hostfxr.10.0.3.component.osx.arm64
 *   com.microsoft.dotnet.aspnetcore.10.0.3.component.osx.arm64
 *   com.microsoft.dotnet.runtime.10.0.3.component.osx.arm64
 *   com.microsoft.dotnet.targetingpacks.10.0.3.component.osx.arm64
 *   ...one entry per shared library, per version still on disk
 *
 * These are NEVER user-installed apps — they're internal artifacts of
 * the SDK installer. They:
 *   1. drown the legitimate inventory (a single .NET install adds
 *      15-20 receipts; old versions accumulate forever);
 *   2. churn on every Microsoft patch so the software delta sees
 *      `added/removed` entries that aren't real installs and trigger
 *      spurious FACTS_SNAPSHOT sends;
 *   3. cause the visible package count to fluctuate (137↔138 in our
 *      test fleet) because a partial scan of `/usr/local/share/dotnet`
 *      sometimes catches a stale receipt mid-deletion.
 *
 * Matching by suffix instead of prefix is intentional — Microsoft,
 * Oracle, and a few open-source projects all use the `.component.<arch>`
 * convention, so one rule covers all of them.
 */
const PKGUTIL_NOISE_SUFFIX_PATTERNS = [
  /\.component\.osx\.(arm64|x86_64)$/i,    // .NET SDK component receipts
  /\.component\.(arm64|x86_64)$/i,         // legacy variant without ".osx."
  /\.component\.universal2?$/i             // universal binary component receipts
];

function isApplePkgutilNoise(pkgId: string): boolean {
  if (!pkgId) return false;
  for (const prefix of APPLE_PKGUTIL_NOISE_PREFIXES) {
    if (pkgId.startsWith(prefix)) return true;
  }
  for (const re of PKGUTIL_NOISE_SUFFIX_PATTERNS) {
    if (re.test(pkgId)) return true;
  }
  return false;
}


function canonicalizePkgutilId(pkgId: string): { canonical: string; version: string | null } {
  if (!pkgId) return { canonical: pkgId, version: null };

  // Match: optional ".<non-numeric-suffix>" then capture .<num>(.<num>)+
  // anywhere from the middle to the end.
  const re = /\.(\d+(?:\.\d+){1,3})(?=\.|$)/;
  const m = pkgId.match(re);

  if (!m) return { canonical: pkgId, version: null };

  const version = m[1];

  const canonical = pkgId.slice(0, m.index) + pkgId.slice((m.index ?? 0) + m[0].length);

  return {
    canonical: canonical.replace(/\.{2,}/g, ".").replace(/\.$/, ""),
    version
  };
}


async function collectMacSoftware(): Promise<SoftwareApplication[]> {
  try {
    const appDirs = [
      "/Applications",
      "/Applications/Utilities",
      `${os.homedir()}/Applications`
    ];

    const appPaths: string[] = [];

    // Why async fs here: the inventory pipeline runs on the same event
    // loop as the gRPC heartbeat and the IPC server. `/Applications`
    // on a well-used Mac has 200+ entries, and `readdirSync` on a
    // spinning-disk external volume (people mount these as extra Apps
    // dirs) can stall the loop for 100-400 ms. Missing a heartbeat
    // window by that margin is enough for the server-side keepalive
    // watcher to mark the device offline. `fs.promises.readdir` yields
    // during the syscall so the gRPC socket stays responsive.
    for (const dir of appDirs) {
      try {
        const entries = await fs.promises.readdir(dir).catch(() => null);
        if (!entries) continue; // ENOENT / EACCES — just skip the dir

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
            // Arguments passed as an array — no shell interpolation,
            // so metacharacters inside appPath are harmless.
            const { stdout } = await execFileAsync(
              "/usr/bin/mdls",
              ["-name", "kMDItemCFBundleIdentifier", "-raw", appPath],
              { timeout: 5000 }
            );

            const rawBundleId = stdout.trim();

            bundleId =
              rawBundleId &&
              rawBundleId !== "(null)" &&
              rawBundleId.toLowerCase() !== "null"
                ? rawBundleId
                : null;
          } catch {
            bundleId = null;
          }

          const normalized = normalizeApp({
            name,
            version: null,
            publisher: undefined,
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
    //
    // Read the Cellar off disk instead of shelling out to `brew`.
    //
    // WHY. This used to run `brew list --versions` with a 5s timeout and
    // swallow every failure under a `catch {}` commented "brew not
    // installed" — a comment that asserted a cause nobody had checked.
    // The agent runs as a LaunchDaemon (root), and Homebrew refuses to
    // run as root against a prefix it does not own, which is the normal
    // install. Measured 2026-08-18: not one row with `source=homebrew`
    // in ANY tenant, across a fleet with several Macs — while CDP's Java
    // collector was happily reading `/opt/homebrew/Cellar/openjdk@21/...`
    // off the very same disks. So brew WAS installed and readable; only
    // the subprocess was failing, silently, for everyone.
    //
    // The Cellar is the same information in a form we can just read:
    // `<prefix>/Cellar/<formula>/<version>`. No subprocess, so no root
    // refusal, no timeout, and no shell to get wrong.
    //
    // Formulae only, deliberately. Casks install .app bundles that the
    // bundle collector above already reports; adding Caskroom here would
    // list them twice.
    for (const prefix of ["/opt/homebrew", "/usr/local"]) {
      const cellar = `${prefix}/Cellar`;
      let formulae: string[];
      try {
        formulae = await fs.promises.readdir(cellar);
      } catch {
        continue; // this prefix simply has no Homebrew
      }

      let unreadable = 0;
      for (const formula of formulae) {
        if (formula.startsWith(".")) continue;
        try {
          const versions = (await fs.promises.readdir(`${cellar}/${formula}`))
            .filter((v) => !v.startsWith("."))
            .sort(compareBrewVersions);
          // A formula can keep several versions side by side. The newest
          // is the one on PATH, and the one an agility rule should judge.
          const version = versions[versions.length - 1];
          if (!version) continue;

          const normalized = normalizeApp({
            name: formula,
            version,
            publisher: "homebrew",
            installLocation: `${cellar}/${formula}/${version}`,
            packageFamilyName: formula,
            source: "homebrew"
          });
          if (normalized && normalized.name) {
            results.push(normalized as SoftwareApplication);
          }
        } catch {
          unreadable += 1;
        }
      }

      // Say it out loud. The whole reason this was invisible for months
      // is that the previous version had nowhere to report a problem.
      if (unreadable > 0) {
        console.warn(`[MACOS] ${unreadable} unreadable Homebrew formula dir(s) under ${cellar}`);
      }
    }

    // --- pkgutil packages ---
    try {
      const { stdout } = await execFileAsync("/usr/sbin/pkgutil", ["--pkgs"], {
        maxBuffer: 1024 * 1024 * 5,
        timeout: 5000
      });

      const allPkgs = stdout.split("\n").map(p => p.trim()).filter(Boolean);

      // Filter Apple system noise + arch-tagged sub-component receipts
      // BEFORE the orphan-receipt check so we don't burn execs on
      // entries we'd drop anyway. `pkgutil --pkgs` on any normal Mac
      // returns hundreds of `com.apple.pkg.MAContent10_AssetPack_*`
      // (GarageBand/Logic samples), `com.apple.pkg.XProtect*` (security
      // updates), `com.apple.pkg.CLTools_*` (Xcode CLT components),
      // and `*.component.<arch>` (.NET/JDK SDK sub-receipts). Apple's
      // user-facing apps come in via the .app bundle collector above,
      // so dropping these here is safe.
      const candidates = allPkgs.filter(pkg => !isApplePkgutilNoise(pkg));

      // Orphan-receipt check: pkgutil keeps a record of every package
      // ever installed, even after the files are removed manually
      // (rm -rf /Applications/Foo.app, rm /usr/local/bin/foo, etc.).
      // The receipt lingers and the package shows up in the inventory
      // forever as "installed" until somebody runs `pkgutil --forget`.
      // To weed those out we resolve `volume + location` from
      // `pkgutil --pkg-info` and check the path on disk; if it's
      // gone, the receipt is stale and we drop it.
      //
      // Apple's own receipts almost universally use `location: /`
      // (root) so the existence check is a no-op for them — but we
      // still want the metadata read because `pkg-info` returns the
      // proper version string, which is more accurate than the
      // version we can extract from the bundle id alone.
      //
      // Concurrency 10 keeps total time under ~1.5s on a fleet
      // baseline of ~100 receipts after noise filtering.
      type PkgRecord = {
        pkgId: string;
        location: string | null;
        volume: string | null;
        version: string | null;
        installLocationExists: boolean;
      };

      async function readPkgInfo(pkgId: string): Promise<PkgRecord | null> {
        try {
          const { stdout: info } = await execFileAsync(
            "/usr/sbin/pkgutil",
            ["--pkg-info", pkgId],
            { timeout: 3000 }
          );
          // Parse simple "key: value" lines.
          let location: string | null = null;
          let volume: string | null = null;
          let version: string | null = null;

          for (const line of info.split("\n")) {
            const m = line.match(/^([a-z-]+):\s*(.*)$/i);
            if (!m) continue;

            const k = m[1].toLowerCase();
            const v = m[2].trim();

            if (k === "location") location = v;
            else if (k === "volume") volume = v;
            else if (k === "version") version = v;
          }

          // Resolve absolute install path. `volume` is often "/" and
          // `location` is the relative path under it. Empty location
          // for system packages means root install — always exists.
          let installLocationExists = true;

          if (location && location !== "/" && location !== "") {
            const root = volume && volume !== "/" ? volume : "";
            const abs = `${root}/${location}`.replace(/\/+/g, "/");

            installLocationExists = await fs.promises
              .access(abs, fs.constants.F_OK)
              .then(() => true)
              .catch(() => false);
          }

          return {
            pkgId,
            location,
            volume,
            version,
            installLocationExists
          };
        } catch {
          // pkg-info itself failed — receipt is corrupt or vanished
          // between --pkgs and --pkg-info. Treat as orphan.
          return null;
        }
      }

      const pkgRecords: PkgRecord[] = [];
      const PKG_INFO_CONCURRENCY = 10;

      for (let i = 0; i < candidates.length; i += PKG_INFO_CONCURRENCY) {
        const batch = candidates.slice(i, i + PKG_INFO_CONCURRENCY);
        const records = await Promise.all(batch.map(readPkgInfo));

        for (const r of records) {
          if (r) pkgRecords.push(r);
        }
      }

      const orphans = pkgRecords.filter(r => !r.installLocationExists).length;

      if (orphans > 0) {
        console.warn(`[MACOS] dropped ${orphans} orphan pkgutil receipts (install location missing)`);
      }

      for (const rec of pkgRecords) {
        if (!rec.installLocationExists) continue;

        // Use the canonicalized id (without the embedded version) for
        // both `name` and `packageFamilyName` so a future patch — same
        // package, new version — produces the same `installId` and is
        // reported as `updated` instead of `removed+added`. Prefer the
        // version from `pkg-info` over what we can extract from the
        // bundle id; the receipt's recorded version is authoritative.
        const { canonical, version: idVersion } = canonicalizePkgutilId(rec.pkgId);
        const version = rec.version || idVersion;

        const normalized = normalizeApp({
          name: canonical,
          version,
          /**
           * Critical fix:
           * pkgutil is the collector/source, not the publisher.
           * Passing "pkgutil" here makes the dashboard group software
           * under publisher="pkgutil", which is incorrect.
           *
           * The normalizer will infer the real publisher from canonical
           * package ids such as:
           *   com.microsoft.*
           *   com.epson.*
           *   com.apple.*
           *   com.teamviewer.*
           */
          publisher: undefined,
          installLocation: rec.location || "/",
          packageFamilyName: canonical,
          source: "pkgutil"
        });

        if (normalized && normalized.name) {
          results.push(normalized as SoftwareApplication);
        }
      }
    } catch {
      // ignore
    }

    // --------------------------------------------------------------------
    // Two-pass dedup
    // --------------------------------------------------------------------
    // Pass 1 (installId dedup): normalizeApp produces a stable installId
    // from (name|publisher|packageFamilyName|source), so two scans of
    // the same source+app would already collapse here. This is cheap
    // and deterministic; keep it.
    //
    // Pass 2 (cross-source semantic dedup): the SAME logical app often
    // surfaces from multiple collectors:
    //
    //   .app bundle:   name="Microsoft OneNote"         pfn="com.microsoft.onenote.mac"
    //   pkgutil:       name="com.microsoft.onenote.mac" pfn="com.microsoft.onenote.mac"
    //
    // Both produce different `installId`s because `source` is part of
    // the hash. Pass 1 keeps both; Pass 2 merges them by
    // `packageFamilyName` and picks the entry that gives operators the
    // most useful data.
    //
    // Priority: macos-app-bundle > homebrew > pkgutil.
    //   - .app bundle has the human-readable display name and the
    //     user-facing install location.
    //   - homebrew has a version string.
    //   - pkgutil is last-resort identification for things that aren't
    //     bundles (drivers, kexts, receipts for deleted apps).
    const byInstallId = new Map<string, SoftwareApplication>();

    for (const app of results) {
      if (!app.installId) continue;
      byInstallId.set(app.installId, app);
    }

    const SOURCE_PRIORITY: Record<string, number> = {
      "macos-app-bundle": 3,
      "homebrew": 2,
      "pkgutil": 1
    };

    const sourceRank = (s: string) => SOURCE_PRIORITY[s?.toLowerCase?.() || ""] ?? 0;

    const byPfn = new Map<string, SoftwareApplication>();
    const unkeyed: SoftwareApplication[] = [];

    for (const app of byInstallId.values()) {
      const pfn = app.packageFamilyName?.toLowerCase?.() || "";

      if (!pfn) {
        // No packageFamilyName to merge on — keep as-is. Anything
        // without a PFN is rare (nping from /Applications with "(null)"
        // bundle id, a handful of sideloaded apps); these stay.
        unkeyed.push(app);
        continue;
      }

      const existing = byPfn.get(pfn);

      if (!existing || sourceRank(app.source) > sourceRank(existing.source)) {
        byPfn.set(pfn, app);
      }
    }

    return [...byPfn.values(), ...unkeyed];
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

    // Printers collected here (BEFORE software) so both return paths
    // below — the no-changes early return inside the software try-
    // block AND the final return — can include them. If we put this
    // after software, the no-changes early return would skip
    // printers entirely on every steady-state cycle.
    let printers = emptyPrinterInventory();
    try {
      const raw = await collectCupsPrinters();
      printers = buildPrinterInventoryWithBaseline(raw);
    } catch (err: any) {
      console.warn("[MACOS] printer collection failed, shipping empty", err?.message || err);
    }

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

          // Phase B: drop items[] on delta sends. See windows.ts
          // for the full rationale (~50 lines of context kept there
          // to avoid triplicating it here).
          software = {
            count: deltaResult.currentCount,
            items: undefined,
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
            software,
            printers
          };
        }
      }
    } catch (err) {
      console.error("[MACOS] collection failed", err);
    }

    return {
      hardware,
      security,
      software,
      printers
    };
  }
};