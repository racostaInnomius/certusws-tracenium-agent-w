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
import fs from "fs";
import os from "os";
import si from "systeminformation";
import { execFile } from "child_process";
import { promisify } from "util";

import type { AgentContext } from "../../../core/agent-context";
import type { AmpNamespace } from "../../../domain/amp-types";
import { readBootTime } from "../../../domain/boot-time";
import type { SoftwareApplication } from "../../../domain/normalize-app";

import { normalizeApp } from "../../../domain/normalize-app";
import { parsePackagePublisher } from "../../../domain/package-publisher";
import { computeSoftwareDelta, toBaselineOps } from "../../../domain/software-inventory-delta";
import {
  loadSoftwareBaseline,
  upsertSoftwareBaseline,
  deleteSoftwareByIds
} from "../../../domain/software-baseline-repo";
import { collectCupsPrinters } from "./printers-cups";
import {
  buildPrinterInventoryWithBaseline,
  emptyPrinterInventory
} from "./printers-pipeline";

// execFile takes an argv array — no shell interpolation, so package
// names returned by dpkg/rpm/snap/flatpak that happen to contain shell
// metacharacters are harmless. (Previous version used `exec` with
// shell strings, mirroring a small attack surface for any future
// caller that ever passed user-controlled arguments. Migrating
// matches the macOS provider's safer pattern.)
const execFileAsync = promisify(execFile);

// ── Noise filtering ──────────────────────────────────────────────
// Linux package managers expose every transitive library, every
// language locale, every debug-symbol bundle as a "package". An
// untouched Ubuntu 24 server reports ~1100-1500 packages; almost
// all of them are kernel internals, dev headers, docs, locale
// data, and library shims that no operator thinks of as
// "applications". Shipping them all to the dashboard buries the
// real user-installed apps in noise.
//
// Two-stage filter:
//
// 1. HARD_NOISE_PATTERNS → drop completely. Things nobody ever
//    needs to see in an inventory dashboard. PMP scan already
//    covers security visibility for these via the patch namespace,
//    so we don't lose any operational signal.
//
// 2. Manual-vs-auto via `apt-mark showmanual` (dpkg) /
//    `dnf history userinstalled` (rpm). Only ship the manual side.
//    Auto-installed transitive deps are shadow infrastructure —
//    visible to the package manager, invisible to operators.
//
// Snap + flatpak escape both filters: their entire premise is
// "operator-installed apps", so by construction they're already the
// userFacing set. We ship them whole.
const HARD_NOISE_PATTERNS: RegExp[] = [
  // Development packages — only relevant on developer machines, and
  // the SDKs themselves (e.g. `gcc`, `python3`) are tracked separately.
  /^.+-dev$/,
  /^.+-dev:[^:]+$/,            // multi-arch suffix variant
  /^.+-doc$/,
  /^.+-dbg$/,
  /^.+-dbgsym$/,
  /^.+-source$/,
  /^.+-data$/,                 // pkgname-data is universally locale/data
  // Kernel infrastructure — not operator-managed software, drives
  // up package count by 5-15 per kernel version pinned on disk.
  /^linux-headers-/,
  /^linux-image-/,
  /^linux-modules-/,
  /^linux-tools-/,
  /^linux-cloud-tools-/,
  /^linux-aws$/,
  /^linux-azure$/,
  /^linux-gcp$/,
  /^kernel-headers$/,
  /^kernel-devel$/,
  /^kernel-tools$/,
  /^kernel-modules-/,
  // Language pack locale data. `language-pack-en-base` etc.
  /^language-pack-/,
  /^locales-all$/,
  // GObject introspection bindings — never user-relevant on a server.
  /^gir1\.2-/,
  // Per-arch firmware blobs.
  /^firmware-/,
  /^.*-firmware$/,
  // tzdata, ca-certificates, base-files etc are essential plumbing
  // operators don't think of as installed apps. The dashboard's
  // PMP/SCP namespaces already track them for security purposes.
  /^base-files$/,
  /^base-passwd$/,
  /^debconf$/,
  /^debconf-i18n$/,
  /^tzdata$/,
  /^ca-certificates$/,
  /^iso-codes$/,
  /^ucf$/,
  /^xkb-data$/,
  /^console-setup-linux$/,
  /^console-setup$/,
  /^keyboard-configuration$/,
];

function isHardNoise(pkgName: string): boolean {
  for (const re of HARD_NOISE_PATTERNS) {
    if (re.test(pkgName)) return true;
  }
  return false;
}

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
      fsSize: fsSize || undefined,
      // Cuando arrancó el sistema. En Linux manda `/proc/stat`, que da el
      // epoch exacto del arranque y —a diferencia del contador— no se ve
      // afectado por la suspensión. Ver boot-time.ts.
      ...readBootTime({
        nowMs: Date.now(),
        uptimeSeconds: os.uptime(),
        readProcStat: () => {
          try {
            return fs.readFileSync("/proc/stat", "utf8");
          } catch {
            return null;
          }
        }
      })
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

// `apt-mark showmanual` lists packages explicitly installed by the
// operator (or that came in the base distro image and were marked
// manual on first apt run). Everything else was pulled as a
// transitive dependency by another package and is "infrastructure"
// from the operator's perspective.
//
// On a fresh Ubuntu 24 server this typically returns 200-350
// entries vs 800-1200 in the full dpkg list. Combined with the
// HARD_NOISE_PATTERNS filter we settle around ~250 user-facing
// apps.
//
// Returns null on error (apt-mark missing, command failed) — the
// caller falls back to "no manual filter" mode and ships the full
// dpkg list (with HARD_NOISE_PATTERNS still applied). Better to
// over-report than to ship zero apps if apt-mark glitches.
/**
 * Packages that must survive the manual-only filter.
 *
 * The filter exists to hide the transitive-dependency graph, and it is
 * right about almost everything. But the TLS library is precisely a
 * transitive dependency — `libssl3` is pulled in by whatever needs it and
 * is therefore ALWAYS marked auto, so it was always dropped. The one
 * package that survived was the `openssl` CLI, which measures the command
 * line rather than the library the services actually link: the wrong
 * number, reported confidently.
 *
 * That mattered because the PQC agility check reads exactly this to
 * answer "can this machine do ML-KEM" (OpenSSL 3.5+). With libssl
 * filtered out, the check had nothing to judge on Linux.
 *
 * Deliberately narrow. Every name here is a cryptographic runtime whose
 * version is a migration fact, not a general-purpose escape hatch for
 * things someone finds interesting.
 *
 * The `t64` suffix is not optional trivia: Ubuntu 24.04's 64-bit time_t
 * transition renamed the package to `libssl3t64`, and 24.04 is in the
 * fleet. A pattern without it would have missed the exact distro this
 * was written for.
 */
const CRYPTO_RUNTIME_RE = /^(libssl[0-9.]*(t64)?|openssl|libgnutls[0-9.-]*(t64)?|gnutls-bin|libnss3|libgcrypt[0-9]*(t64)?)$/i;

function isCryptoRuntime(name: string): boolean {
  return CRYPTO_RUNTIME_RE.test(String(name ?? "").trim());
}

async function getDebianManualPackages(): Promise<Set<string> | null> {
  const r = await run("/usr/bin/apt-mark", ["showmanual"]);
  if (!r) return null;
  const lines = r.split("\n").map(s => s.trim()).filter(Boolean);
  if (lines.length === 0) return null;
  return new Set(lines);
}

// RHEL/Fedora equivalent. `dnf history userinstalled` lists
// packages installed by the user (excluding deps). This requires
// the dnf history db to be present — fresh kickstart images
// sometimes ship without it. RHEL 7 uses `yum history info` with
// a much messier output; we don't try to parse that and let RHEL 7
// fall through to "no manual filter" mode.
async function getRhelManualPackages(): Promise<Set<string> | null> {
  const dnfBin = hasExecutable("/usr/bin/dnf") ? "/usr/bin/dnf"
                : hasExecutable("/usr/bin/dnf5") ? "/usr/bin/dnf5"
                : null;
  if (!dnfBin) return null;
  const r = await run(dnfBin, ["history", "userinstalled"]);
  if (!r) return null;
  // Output shape (dnf 4.x): bare list of package names, one per line,
  // with a header line "Packages installed by user:" we drop. dnf 5
  // omits the header.
  const lines = r.split("\n")
    .map(s => s.trim())
    .filter(s => s && !s.toLowerCase().startsWith("packages installed"));
  if (lines.length === 0) return null;
  // Strip arch/version suffixes — dnf sometimes emits NVRA, sometimes
  // bare name. We dedup to the bare-name set so collectRpm's lookup
  // (which uses just `name`) finds matches regardless of dnf format.
  const set = new Set<string>();
  for (const line of lines) {
    const bare = line.split(".")[0].split("-")[0];
    if (bare) set.add(bare);
    set.add(line);
  }
  return set;
}

async function collectDpkg(manualSet: Set<string> | null): Promise<SoftwareApplication[]> {
  // -W is the machine-readable form; `-f` controls the field layout.
  // Tab-separated so we can split on \t (package names never contain
  // tabs, but they CAN contain spaces in `Description` — old format).
  // We don't ask for description here.
  const out = await run("/usr/bin/dpkg-query", [
    "-W",
    // ⚠️ Maintainer se agrega al final a proposito: los campos previos ya
    // tenian consumidores por indice, y anadir en medio los habria corrido.
    // Puede traer espacios pero nunca tabuladores, asi que sigue siendo
    // seguro partir por \t.
    "-f=${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${Maintainer}\n",
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
    // dpkg SI tiene fabricante: el Maintainer. Ver package-publisher.ts —
    // antes aqui viajaba la cadena "dpkg", que es el gestor y no el editor.
    const publisher = parsePackagePublisher(parts[4]);

    // Hard noise filter — dropped completely from inventory. Patterns
    // documented at the top of the file.
    if (isHardNoise(name)) continue;

    // Manual-only mode: when apt-mark gave us a set, only ship
    // packages the operator actually marked manual. Cuts inventory
    // ~3-4x by hiding the deep transitive-dep graph.
    //
    // If manualSet is null (apt-mark unavailable), fall through to
    // ship everything that survived the hard-noise filter — better
    // to over-report than ship a half-empty inventory.
    if (manualSet && !manualSet.has(name) && !isCryptoRuntime(name)) continue;

    const n = normalizeApp({
      name,
      version,
      publisher,
      installLocation: "/",
      packageFamilyName: name,
      source: "dpkg",
    });

    if (n && n.name) {
      // Override the display normalizer's default category (which
      // doesn't know about apt-mark status) with "application" +
      // userFacing=true. We've established by passing the manual-set
      // gate that the operator chose to install this package.
      (n as SoftwareApplication).category = "application";
      (n as SoftwareApplication).userFacing = true;
      res.push(n as SoftwareApplication);
    }
  }

  return res;
}

async function collectRpm(manualSet: Set<string> | null): Promise<SoftwareApplication[]> {
  // Tab-separated — RPM names never contain tabs, but spaces can
  // appear in version strings of unusual packages so we avoid
  // space-splitting which broke parsing previously.
  const out = await run("/usr/bin/rpm", [
    "-qa",
    "--qf",
    "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n",
  ]);
  const lines = out.split("\n").filter(Boolean);
  const res: SoftwareApplication[] = [];

  for (const line of lines) {
    const [name, version, , vendor] = line.split("\t");
    if (!name) continue;

    // Filter `gpg-pubkey-*`: rpm tracks imported GPG keys via the same
    // `rpm -qa` query, but they're not packages — they're trust
    // material in the rpmdb. Including them as "software" inflates the
    // inventory and creates spurious deltas every time a vendor adds
    // a new repo signing key. They appear as e.g.:
    //   gpg-pubkey  ec9c4172-65a90b91  (none)
    if (name.startsWith("gpg-pubkey")) continue;

    // Hard noise filter — same patterns as dpkg, applies to RPM too.
    if (isHardNoise(name)) continue;

    // Manual-only mode: when dnf history gave us a set, only ship
    // packages the operator explicitly installed.
    if (manualSet && !manualSet.has(name)) continue;

    const n = normalizeApp({
      name,
      version,
      // rpm expone %{VENDOR}. Cuando el paquete no lo trae, rpm imprime
      // literalmente "(none)", que parsePackagePublisher descarta.
      publisher: parsePackagePublisher(vendor),
      installLocation: "/",
      packageFamilyName: name,
      source: "rpm",
    });

    if (n && n.name) {
      (n as SoftwareApplication).category = "application";
      (n as SoftwareApplication).userFacing = true;
      res.push(n as SoftwareApplication);
    }
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

    // The `snapd` snap is the daemon itself, plus `core*` snaps are
    // the snap runtime base. Both are infrastructure of the snap
    // system rather than user-installed apps. Skip — operators don't
    // think of `core22` or `snapd` as "apps they installed".
    if (name === "snapd" || /^core[0-9]*$/.test(name) || name === "bare") continue;

    const n = normalizeApp({
      name,
      version,
      // snap no tiene concepto de fabricante en `snap list`. La ausencia es
      // la respuesta correcta; mandar "snap" ponia el gestor en el ranking.
      publisher: undefined,
      installLocation: "/snap",
      packageFamilyName: name,
      source: "snap",
    });

    if (n && n.name) {
      // Snap entries are by design user-installed. The whole snap
      // distribution model is opt-in per-app; nothing is auto-pulled
      // as a transitive dep the way apt does. Tag accordingly.
      (n as SoftwareApplication).category = "application";
      (n as SoftwareApplication).userFacing = true;
      res.push(n as SoftwareApplication);
    }
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
    const [name, version, , vendor] = line.split("\t");
    if (!name) continue;

    const n = normalizeApp({
      name,
      version,
      // Igual que snap: el remote no es un fabricante.
      publisher: undefined,
      installLocation: "/var/lib/flatpak",
      packageFamilyName: name,
      source: "flatpak",
    });

    if (n && n.name) {
      // Same logic as snap: flatpak entries are explicit installs.
      (n as SoftwareApplication).category = "application";
      (n as SoftwareApplication).userFacing = true;
      res.push(n as SoftwareApplication);
    }
  }

  return res;
}

// Source priority for cross-source dedup. When the same app appears
// via multiple package managers (e.g. `docker` from both apt and
// snap), keep the higher-priority source. Lower index = higher
// priority. Order rationale:
//   * apt/dpkg first: it's the system package manager, manages
//     dependencies + security updates natively, integrates with
//     unattended-upgrades. Wins over user-space alternatives.
//   * rpm second: same role on RHEL-family.
//   * snap third: containerized, sandboxed; useful but secondary
//     to the system PM where both have the same app.
//   * flatpak last: same reasoning as snap. Rarely overlaps with
//     apt anyway (flatpak app ids look like `com.spotify.Client`,
//     apt names look like `spotify-client` — dedup is mostly
//     irrelevant in practice).
const SOURCE_PRIORITY: Record<string, number> = {
  dpkg: 0,
  rpm: 1,
  snap: 2,
  flatpak: 3,
};

function canonicalNameForDedup(app: SoftwareApplication): string {
  // We dedup on the lowercased rawName (the package id from the
  // collector, before display normalization). Display name
  // transformations like "Apache2 Bin" → "Apache 2 Bin" would
  // de-correlate dpkg `apache2-bin` from snap `apache2-bin`, so we
  // explicitly use rawName when present.
  const base = (app.rawName || app.name || "").toLowerCase().trim();
  // Strip multi-arch suffixes that dpkg occasionally surfaces:
  // "libc6:amd64" → "libc6". We don't want both arches counted
  // as separate apps.
  return base.split(":")[0];
}

async function collectLinuxSoftware(): Promise<SoftwareApplication[]> {
  const pm = await detectPackageManagers();

  // Fetch the "user-installed" sets in parallel with the manager
  // probes so we don't serialize what's already two separate
  // commands per family. Both can be null on hosts where the tool
  // isn't available — collectors fall back to "ship everything that
  // survived the hard-noise filter" mode.
  const [debianManual, rhelManual] = await Promise.all([
    pm.hasDpkg ? getDebianManualPackages() : Promise.resolve(null),
    pm.hasRpm ? getRhelManualPackages() : Promise.resolve(null),
  ]);

  const results: SoftwareApplication[] = [];

  if (pm.hasDpkg) {
    results.push(...await collectDpkg(debianManual));
  }
  if (pm.hasRpm) {
    results.push(...await collectRpm(rhelManual));
  }
  if (pm.hasSnap) {
    results.push(...await collectSnap());
  }
  if (pm.hasFlatpak) {
    results.push(...await collectFlatpak());
  }

  // Cross-source dedup. Same canonical name → keep the highest-
  // priority source (apt > rpm > snap > flatpak). Without this, an
  // operator who has `docker` via both apt and snap shows up twice
  // in the inventory donut, distorting the app count.
  //
  // We use canonicalNameForDedup (not installId) because installId
  // includes the source string in its hash — two records of the
  // same app from different sources have different installIds and
  // wouldn't collapse with an installId-keyed map.
  const byCanonical = new Map<string, SoftwareApplication>();
  for (const app of results) {
    const key = canonicalNameForDedup(app);
    if (!key) continue;

    const existing = byCanonical.get(key);
    if (!existing) {
      byCanonical.set(key, app);
      continue;
    }

    const existingRank = SOURCE_PRIORITY[existing.source] ?? 99;
    const newRank = SOURCE_PRIORITY[app.source] ?? 99;
    if (newRank < existingRank) {
      byCanonical.set(key, app);
    }
  }

  return Array.from(byCanonical.values());
}

export const linuxProvider = {
  async collect(ctx: AgentContext): Promise<AmpNamespace> {
    if (os.platform() !== "linux") {
      throw new Error("linuxProvider called on non-Linux platform");
    }

    const hardware = await collectLinuxHardware();
    const security = await collectLinuxSecurity(ctx);

    // Printers via CUPS lpstat — see macos.ts for the placement
    // rationale (must be set BEFORE the software try-block because
    // the software no-changes branch returns the whole AmpNamespace
    // early). On headless Linux without CUPS installed this returns
    // an empty inventory cleanly.
    let printers = emptyPrinterInventory();
    try {
      const raw = await collectCupsPrinters();
      printers = buildPrinterInventoryWithBaseline(raw);
    } catch (err: any) {
      console.warn("[LINUX] printer collection failed, shipping empty", err?.message || err);
    }

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

          // Phase B: drop items[] on delta sends. See windows.ts
          // for the full rationale.
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

          return { hardware, security, software, printers };
        }
      }

    } catch (err) {
      console.error("[LINUX] collection failed", err);
    }

    return { hardware, security, software, printers };
  }
};