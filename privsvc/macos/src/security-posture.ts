import { execFile } from "child_process";
import { promisify } from "util";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { success } from "./protocol";
import { parseSshdConfig } from "./ssh-parse";
import { boolFromDefaultsRead, classifyDefaultsRead } from "./defaults-parse";
import { parseSysadminctlScreenLock } from "./screenlock-parse";
import { parsePwpolicyMinimumLength } from "./pwpolicy-parse";

const execFileAsync = promisify(execFile);

type CommandResult = {
  // stdout + stderr combined — what the regex-matching text collectors
  // consume. Some Apple tools (systemsetup, socketfilterfw) put state
  // lines on either stream, so the combined view is deliberate THERE.
  output: string;
  // stdout alone — the only stream a JSON consumer may parse. See
  // runJson below for why the split exists.
  stdout: string;
  ok: boolean;
};

async function run(command: string, args: string[], timeout = 5000): Promise<CommandResult> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, { timeout, maxBuffer: 8 * 1024 * 1024 });
    return {
      output: `${stdout || ""}${stderr || ""}`.trim(),
      stdout: String(stdout || "").trim(),
      ok: true
    };
  } catch (err: any) {
    return {
      output: String(err?.stdout || err?.stderr || err?.message || err || "").trim(),
      stdout: String(err?.stdout || "").trim(),
      ok: false
    };
  }
}

async function runJson<T>(command: string, args: string[], timeout = 10000): Promise<T | null> {
  const result = await run(command, args, timeout);
  // Parse stdout ONLY. The previous version parsed the combined
  // output, and any stderr byte — system_profiler routinely emits
  // warnings there — corrupted the JSON and turned the whole result
  // into null. For patches that meant items:[] / count:0, silently,
  // indistinguishable from a genuinely empty install history.
  if (!result.stdout) return null;

  try {
    return JSON.parse(result.stdout) as T;
  } catch {
    return null;
  }
}

// Sprint 4 — macOS hardening helpers.
// Cap raw command output before it ships in the evidence block. Linux has
// done this since day one (4 KB); Windows and macOS shipped unbounded raw
// (gpresult with usernames + OU topology, `sharing -l`, full
// system_profiler JSON). The catalog rules read parsed fields, never raw
// — raw is diagnostics, and 4 KB of diagnostics is plenty.
const RAW_MAX_BYTES = 4 * 1024;
function truncate(s: string | undefined, max = RAW_MAX_BYTES): string | undefined {
  if (!s) return s;
  if (s.length <= max) return s;
  return s.slice(0, max) + "\n...[truncated]";
}

// Console (GUI) user, or null at the login window / for system accounts.
// `/dev/console` is owned by the logged-in user; `stat -f "%u %Su"` gives
// uid + name in one call. Same technique screen-capture.ts uses.
const MIN_INTERACTIVE_UID = 500;
async function activeConsoleUser(): Promise<{ uid: number; name: string } | null> {
  const r = await run("/usr/bin/stat", ["-f", "%u %Su", "/dev/console"], 2000);
  if (!r.ok) return null;
  const m = /^(\d+)\s+(\S+)$/.exec(r.stdout);
  if (!m) return null;
  const uid = Number(m[1]);
  const name = m[2];
  if (!Number.isInteger(uid) || uid < MIN_INTERACTIVE_UID || name === "root") return null;
  return { uid, name };
}

// Test-only surface for the exec plumbing (see test/privsvc/
// macos-exec.test.ts). Not for production imports.
export const __test__ = { run, runJson, truncate };

function parseDate(value: unknown): string | undefined {
  if (typeof value !== "string" || !value.trim()) return undefined;
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return undefined;
  return dt.toISOString();
}

async function collectFileVault() {
  const result = await run("/usr/bin/fdesetup", ["status"]);
  const output = result.output;
  const enabled = /FileVault is On/i.test(output);
  const disabled = /FileVault is Off/i.test(output);

  return {
    status: enabled ? "enabled" : disabled ? "disabled" : "unknown",
    raw: truncate(output) || undefined
  };
}

async function collectFirewall() {
  // Two separate queries: the `--getglobalstate` flag reports the ALF
  // on/off state, and `--getstealthmode` reports whether the host
  // answers to probe packets (ICMP / TCP SYN to closed ports). CIS
  // 2.5.2.{1,2} treat them as independent controls, so we expose both
  // top-level and the catalog references them via `firewall.status`
  // and `firewall.stealthMode`.
  const [globalResult, stealthResult] = await Promise.all([
    run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]),
    run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getstealthmode"])
  ]);

  const globalOutput = globalResult.output;
  const stealthOutput = stealthResult.output;

  const enabled = /enabled/i.test(globalOutput);
  const disabled = /disabled/i.test(globalOutput);

  // The output of --getstealthmode is literally "Stealth mode
  // enabled" or "Stealth mode disabled". We evaluate "enabled" via a
  // positive match and only report `false` on a positive "disabled"
  // match — absence of both signals `undefined` so the evaluator can
  // differentiate "off" from "not reported".
  let stealthMode: boolean | undefined;
  if (/stealth mode enabled/i.test(stealthOutput)) {
    stealthMode = true;
  } else if (/stealth mode disabled/i.test(stealthOutput)) {
    stealthMode = false;
  }

  return {
    status: enabled ? "enabled" : disabled ? "disabled" : "unknown",
    stealthMode,
    raw: truncate(globalOutput) || undefined,
    stealthRaw: truncate(stealthOutput) || undefined
  };
}

async function collectGatekeeper() {
  const result = await run("/usr/sbin/spctl", ["--status"]);
  const output = result.output;
  const enabled = /assessments enabled/i.test(output);
  const disabled = /assessments disabled/i.test(output);

  return {
    status: enabled ? "enabled" : disabled ? "disabled" : "unknown",
    raw: truncate(output) || undefined
  };
}

async function collectSip() {
  const result = await run("/usr/bin/csrutil", ["status"]);
  const output = result.output;
  const enabled = /enabled/i.test(output);
  const disabled = /disabled/i.test(output);

  return {
    status: enabled ? "enabled" : disabled ? "disabled" : "unknown",
    raw: truncate(output) || undefined
  };
}

type InstallHistoryItem = {
  _name?: string;
  install_date?: string;
  version?: string;
  packageIdentifiers?: string[];
};

async function collectPatches() {
  const profiler = await runJson<{ SPInstallHistoryDataType?: InstallHistoryItem[] }>(
    "/usr/sbin/system_profiler",
    ["SPInstallHistoryDataType", "-json"],
    25000
  );

  const items = Array.isArray(profiler?.SPInstallHistoryDataType) ? profiler!.SPInstallHistoryDataType! : [];
  const normalized = items.map((item) => ({
    name: item?._name || "unknown",
    version: item?.version || undefined,
    installedAtUtc: parseDate(item?.install_date),
    packageIdentifiers: Array.isArray(item?.packageIdentifiers) ? item.packageIdentifiers : []
  }));

  const securityItems = normalized.filter((item) =>
    /security|rapid security response|xprotect|gatekeeper|mrt|malware/i.test(String(item.name))
  );

  return {
    status: normalized.length > 0 ? "available" : "unknown",
    count: normalized.length,
    securityCount: securityItems.length,
    lastScanUtc: new Date().toISOString(),
    lastSecurityInstallUtc: (() => {
      const installs = securityItems
        .map((item) => item.installedAtUtc)
        .filter((item): item is string => Boolean(item))
        .sort();
      return installs.length > 0 ? installs[installs.length - 1] : undefined;
    })(),
    items: securityItems,
    rawCount: normalized.length
  };
}

async function readPkgInfo(packageId: string) {
  const result = await run("/usr/sbin/pkgutil", ["--pkg-info", packageId], 8000);
  const output = result.output;
  if (!output) {
    return {
      packageId,
      installed: false
    };
  }

  const version = output.match(/^version:\s*(.+)$/im)?.[1]?.trim();
  const installTime = output.match(/^install-time:\s*(.+)$/im)?.[1]?.trim();

  return {
    packageId,
    installed: result.ok,
    version: version || undefined,
    installTimeEpoch: installTime ? Number(installTime) : undefined,
    installedAtUtc: installTime && Number.isFinite(Number(installTime))
      ? new Date(Number(installTime) * 1000).toISOString()
      : undefined,
    raw: truncate(output) || undefined
  };
}

async function collectAntivirus() {
  const [xprotectConfig, xprotectPayloads, mrtConfig] = await Promise.all([
    readPkgInfo("com.apple.pkg.XProtectPlistConfigData"),
    readPkgInfo("com.apple.pkg.XProtectPayloads"),
    readPkgInfo("com.apple.pkg.MRTConfigData")
  ]);

  const receipts = [xprotectConfig, xprotectPayloads, mrtConfig];
  const installedCount = receipts.filter((item) => item.installed).length;
  const latestUpdate = receipts
    .map((item) => item.installedAtUtc)
    .filter((item): item is string => Boolean(item))
    .sort();

  return {
    status: installedCount > 0 ? "enabled" : "unknown",
    provider: installedCount > 0 ? "apple_builtin" : "unknown",
    installedCount,
    lastUpdateUtc: latestUpdate.length > 0 ? latestUpdate[latestUpdate.length - 1] : undefined,
    xprotect: {
      config: xprotectConfig,
      payloads: xprotectPayloads
    },
    mrt: mrtConfig,
    receipts
  };
}

function parseSharingBlocks(output: string) {
  const lines = output.split(/\r?\n/);
  const items: Array<Record<string, unknown>> = [];
  let current: Record<string, unknown> | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;

    const nameMatch = line.match(/^name:\s*(.+)$/i);
    if (nameMatch) {
      if (current) items.push(current);
      current = { name: nameMatch[1].trim() };
      continue;
    }

    const pathMatch = line.match(/^path:\s*(.+)$/i);
    if (pathMatch) {
      current = current || {};
      current.path = pathMatch[1].trim();
      continue;
    }

    const smbMatch = line.match(/^smb:\s*(.+)$/i);
    if (smbMatch) {
      current = current || {};
      current.smb = smbMatch[1].trim();
      continue;
    }

    const afpMatch = line.match(/^afp:\s*(.+)$/i);
    if (afpMatch) {
      current = current || {};
      current.afp = afpMatch[1].trim();
      continue;
    }

    const ftpMatch = line.match(/^ftp:\s*(.+)$/i);
    if (ftpMatch) {
      current = current || {};
      current.ftp = ftpMatch[1].trim();
      continue;
    }

    const permissionMatch = line.match(/^users?:\s*(.+)$/i) || line.match(/^groups?:\s*(.+)$/i);
    if (permissionMatch) {
      current = current || {};
      const permissions = Array.isArray(current.permissions) ? current.permissions as string[] : [];
      permissions.push(permissionMatch[1].trim());
      current.permissions = permissions;
    }
  }

  if (current) items.push(current);
  return items;
}

async function inspectShareRisk(path: string) {
  const result = await run("/bin/ls", ["-lde", path], 8000);
  const output = result.output;
  const hasEveryoneWriteAcl = /everyone allow .*?(write|delete|add_file|add_subdirectory|writeattr|writeextattr|chown)/i.test(output);
  const worldWritable = /^[\-d].{7}w/.test(output);

  return {
    path,
    hasEveryoneWriteAcl,
    worldWritable,
    raw: truncate(output) || undefined
  };
}

async function collectShares() {
  const result = await run("/usr/sbin/sharing", ["-l"], 12000);
  const items = parseSharingBlocks(result.output);
  const detailed: Array<Record<string, unknown>> = await Promise.all(items.map(async (item) => {
    const path = typeof item.path === "string" ? item.path : undefined;
    const risk = path ? await inspectShareRisk(path) : null;
    const risky = Boolean(risk?.hasEveryoneWriteAcl || risk?.worldWritable);

    return {
      ...item,
      risky,
      risk: risk || undefined
    };
  }));

  const riskyItems = detailed.filter((item) => item.risky);
  const smbEnabled = detailed.some((item) => String((item as any).smb || "").toLowerCase() === "yes");

  return {
    status: detailed.length > 0 ? "available" : "unknown",
    count: detailed.length,
    riskyCount: riskyItems.length,
    items: detailed,
    raw: truncate(result.output) || undefined,
    smbEnabled
  };
}

async function collectSmb(shares: { smbEnabled?: boolean; raw?: string }) {
  // Three independent reads:
  //   1. launchctl state → is the SMB daemon active right now?
  //   2. /etc/nsmb.conf (client-side SMB config) — if present and
  //      explicitly opts into SMB1 via `protocol_vers_map`, we flag it.
  //   3. System-level SMB server defaults via `defaults read …smb.server
  //      ProtocolVersionMap` — bitmask (1=SMB1, 2=SMB2, 4=SMB3). If
  //      bit 1 is set, SMBv1 is enabled on the server side.
  //
  // Default when nothing opts in: `smb1.enabled = false`. macOS moderno
  // ya no habilita SMB1 por default, pero cualquier opt-in explícito lo
  // detectamos. Para no engañar al evaluator, si ambas fuentes están
  // ausentes (no hay nsmb.conf y defaults no tiene la key) reportamos
  // `false` — es la observación real, no un "no sé".
  const [launchctl, nsmbConf, protocolMap] = await Promise.all([
    run("/bin/launchctl", ["print", "system/com.apple.smbd"], 8000),
    run("/bin/cat", ["/etc/nsmb.conf"], 5000),
    run(
      "/usr/bin/defaults",
      ["read", "/Library/Preferences/SystemConfiguration/com.apple.smb.server", "ProtocolVersionMap"],
      5000
    )
  ]);

  const running =
    /state = running/i.test(launchctl.output) ||
    /active count = [1-9]/i.test(launchctl.output);
  const serviceMissing = /Could not find service|not found/i.test(launchctl.output);

  const nsmbSmb1 = nsmbConf.ok && /protocol_vers_map\s*=\s*(?:0x)?[0-9a-f]*[13579bdf]/i.test(nsmbConf.output);

  const protocolMapValue = protocolMap.ok ? Number.parseInt(String(protocolMap.output).trim(), 10) : NaN;
  // Bit 0 (value 1) → SMBv1 enabled. If bit is clear, SMBv1 is off.
  const defaultsSmb1 = Number.isFinite(protocolMapValue) ? (protocolMapValue & 0x1) === 0x1 : false;

  const smb1Enabled = Boolean(nsmbSmb1 || defaultsSmb1);

  return {
    status: shares.smbEnabled || running ? "enabled" : serviceMissing ? "disabled" : "unknown",
    running,
    smb1: {
      // The catalog rule is `equals path=smb.smb1.enabled expected=false`,
      // so this boolean is the load-bearing field. We keep the source
      // flags alongside it for audit.
      enabled: smb1Enabled,
      nsmbOptIn: nsmbSmb1,
      defaultsProtocolVersionMap: Number.isFinite(protocolMapValue) ? protocolMapValue : undefined
    },
    raw: truncate(launchctl.output || shares.raw),
    nsmbRaw: nsmbConf.ok ? nsmbConf.output || undefined : undefined
  };
}

/**
 * Screen-saver password requirement. Primary source is
 * `sysadminctl -screenLock status`: on modern macOS (Ventura+) the GUI
 * toggle no longer writes `askForPassword` to com.apple.screensaver —
 * verified in the field 2026-08-19: the key does not exist in ANY
 * domain even with the setting ON, so the defaults-based read was
 * structurally not_applicable on every unmanaged Mac. sysadminctl is
 * per-user and prints to stderr (run() combines streams, so the parser
 * sees it). The defaults chain stays as fallback: MDM profiles still
 * land `askForPassword` system-wide, and older macOS still writes the
 * per-user key.
 */
async function collectScreenLock() {
  // ⚠️ privsvc runs as root. Both sysadminctl and `defaults
  // -currentHost read` answer for the INVOKING user — root's prefs, not
  // the console user's — so every per-user read must run in the console
  // user's context via `launchctl asuser <uid> sudo -n -u <name> …`,
  // the same technique screen-capture.ts has proven in the field. At
  // the login window (no console user) there is no per-user value to
  // read: report the system-wide /Library/Preferences fallback only and
  // say so in `source`.
  const user = await activeConsoleUser();

  const runAs = (bin: string, args: string[]) =>
    user
      ? run(
          "/bin/launchctl",
          // `-n`: never prompt — root→user needs no password, and a
          // prompt would hang the collector until the IPC timeout.
          ["asuser", String(user.uid), "sudo", "-n", "-u", user.name, bin, ...args],
          6000
        )
      : run(bin, args, 5000);

  const [screenLockStatus, currentHost, userGlobal, systemGlobal] = await Promise.all([
    user
      ? runAs("/usr/sbin/sysadminctl", ["-screenLock", "status"])
      : Promise.resolve<CommandResult>({ output: "", stdout: "", ok: false }),
    runAs("/usr/bin/defaults", ["-currentHost", "read", "com.apple.screensaver", "askForPassword"]),
    runAs("/usr/bin/defaults", ["read", "com.apple.screensaver", "askForPassword"]),
    // MDM profiles land system-wide; this is the managed-fleet answer.
    run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.screensaver", "askForPassword"], 5000)
  ]);

  const live = parseSysadminctlScreenLock(screenLockStatus.output);
  if (live) {
    return {
      passwordRequired: live.passwordRequired,
      // 0 = immediately. Not evaluated by the current catalog check;
      // carried so a future delay-bounded rule needs no agent change.
      delaySeconds: live.delaySeconds,
      consoleUser: user?.name,
      source: "sysadminctl",
      raw: { sysadminctl: truncate(screenLockStatus.output) }
    };
  }

  // Absent is NOT a verdict here: macOS' default for askForPassword is
  // on in recent releases but varies by version and is overridden by
  // profiles, so "not set" stays undefined → not_applicable.
  const resolved =
    boolFromDefaultsRead(currentHost, undefined) ??
    boolFromDefaultsRead(userGlobal, undefined) ??
    boolFromDefaultsRead(systemGlobal, undefined);

  // "unavailable" used to swallow the common case where every read
  // worked but the key is simply not set ("does not exist" exits
  // non-zero) — misleading in the drawer. Distinguish not_set.
  const reads = [currentHost, userGlobal, systemGlobal];
  const anyValue = reads.some((r) => classifyDefaultsRead(r) === "value");
  const allAbsentOrValue = reads.every((r) => classifyDefaultsRead(r) !== "failed");
  const source = user
    ? anyValue
      ? currentHost.ok ? "user.currentHost" : userGlobal.ok ? "user.global" : "system"
      : allAbsentOrValue ? "not_set" : "unavailable"
    : systemGlobal.ok ? "system" : classifyDefaultsRead(systemGlobal) === "absent" ? "not_set" : "no_console_user";

  return {
    passwordRequired: resolved,
    consoleUser: user?.name,
    source,
    raw: {
      currentHost: currentHost.ok ? truncate(currentHost.output) : undefined,
      global: userGlobal.ok ? truncate(userGlobal.output) : undefined,
      system: systemGlobal.ok ? truncate(systemGlobal.output) : undefined
    }
  };
}

/**
 * Local password policy from `pwpolicy -getaccountpolicies` (global
 * account policies — readable as root, no console-user context needed).
 * Two forms carry the minimum length (the OS-default regex
 * `policyAttributePassword matches '.{4,}+'` and the MDM
 * `minimumLength` integer); parsePwpolicyMinimumLength takes the
 * strictest. Every real Mac has at least the default regex, so unlike
 * the old askForPassword read this yields a verdict fleet-wide.
 */
async function collectPasswordPolicy() {
  const result = await run("/usr/bin/pwpolicy", ["-getaccountpolicies"], 8000);
  const minimumLength = parsePwpolicyMinimumLength(result.output);

  return {
    available: result.ok,
    // undefined when no recognizable policy → the catalog rule lands
    // not_applicable, never a guess.
    minimumLength,
    raw: truncate(result.output) || undefined
  };
}

/**
 * Enumerate the sharing services CIS cares about (Remote Login,
 * Remote Management, etc.). `systemsetup` requires root, which PrivSvc
 * already provides. Output line is `Remote Login: On` / `Remote Login:
 * Off`; we translate to a boolean so the catalog rule
 * `equals path=services.remoteLogin expected=false` works directly.
 */
async function collectServices() {
  const [remoteLogin, remoteAppleEvents] = await Promise.all([
    run("/usr/sbin/systemsetup", ["-getremotelogin"], 8000),
    run("/usr/sbin/systemsetup", ["-getremoteappleevents"], 8000)
  ]);

  const parseOnOff = (out: string): boolean | undefined => {
    if (/:\s*On\b/i.test(out)) return true;
    if (/:\s*Off\b/i.test(out)) return false;
    return undefined;
  };

  return {
    remoteLogin: parseOnOff(remoteLogin.output),
    remoteAppleEvents: parseOnOff(remoteAppleEvents.output),
    raw: {
      remoteLogin: truncate(remoteLogin.output) || undefined,
      remoteAppleEvents: truncate(remoteAppleEvents.output) || undefined
    }
  };
}

/**
 * macOS Software Update preferences. The CIS control that uses this
 * is `softwareUpdate.autoCheck` — mapped to the system-wide
 * `AutomaticCheckEnabled` key under `/Library/Preferences`. We also
 * read adjacent keys for audit (auto-download, config data install)
 * but only the primary `autoCheck` feeds the catalog rule today.
 */
async function collectSoftwareUpdate() {
  const keys = [
    "AutomaticCheckEnabled",
    "AutomaticDownload",
    "ConfigDataInstall",
    "CriticalUpdateInstall",
    "AutomaticallyInstallMacOSUpdates"
  ];

  const reads = await Promise.all(
    keys.map((key) =>
      run(
        "/usr/bin/defaults",
        ["read", "/Library/Preferences/com.apple.SoftwareUpdate", key],
        5000
      )
    )
  );

  // MDM profiles write these as booleans (`true`/`false`), the GUI as
  // ints (`1`/`0`) — parseDefaultsBool accepts both. Absent stays
  // undefined: Apple's defaults for these keys differ by release.
  const pick = (idx: number): boolean | undefined => boolFromDefaultsRead(reads[idx], undefined);

  return {
    autoCheck: pick(0),
    autoDownload: pick(1),
    configDataInstall: pick(2),
    criticalUpdateInstall: pick(3),
    autoInstallMacosUpdates: pick(4)
  };
}

/**
 * Guest account status. `GuestEnabled` is the load-bearing key; when
 * the key is absent macOS treats it as off, so we normalize
 * "key not found" to `false` rather than `undefined` — this matches
 * the actual user-visible behavior and lets the CIS rule
 * `equals path=accounts.guestEnabled expected=false` pass on a
 * hardened default install.
 */
async function collectAccounts() {
  const guest = await run(
    "/usr/bin/defaults",
    ["read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"],
    5000
  );

  // Absent key → false: guest IS off by default on macOS, and the key
  // only appears once someone turns it on, so absence is informative.
  // But a FAILED read (sandbox denial, corrupt plist) must not become a
  // PASS — classifyDefaultsRead tells "does not exist" from everything
  // else, and only the former maps to false. Until 2026-08-16 any
  // non-zero exit was treated as "off" (fail-open on a security control).
  const guestEnabled = boolFromDefaultsRead(guest, false);

  return {
    guestEnabled,
    raw: guest.ok ? truncate(guest.output) : undefined
  };
}

async function collectProfiles() {
  const [enrollmentResult, listResult] = await Promise.all([
    run("/usr/bin/profiles", ["status", "-type", "enrollment"], 12000),
    run("/usr/bin/profiles", ["list", "-all"], 15000)
  ]);

  const enrollmentOutput = enrollmentResult.output;
  const listOutput = listResult.output;
  const enrolled = /mdm enrollment:\s*yes|enrolled via dep:\s*yes|enrollment state:\s*enrolled/i.test(enrollmentOutput);
  const profileLines = listOutput
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /^attribute:/i.test(line) || /^profile:/i.test(line) || /^identifier:/i.test(line));

  return {
    status: enrollmentOutput || listOutput ? "available" : "unknown",
    mdmEnrolled: enrolled,
    profileLineCount: profileLines.length,
    enrollmentRaw: truncate(enrollmentOutput) || undefined,
    // `profiles list -all` enumerates every installed profile (payload
    // identifiers, org names); diagnostics, not evidence — capped.
    listRaw: truncate(listOutput) || undefined
  };
}

async function collectDirectoryBinding() {
  const result = await run("/usr/sbin/dsconfigad", ["-show"], 10000);
  const output = result.output;
  const bound = result.ok && /Active Directory Domain/i.test(output);
  const domainName = output.match(/Active Directory Domain\s*=\s*(.+)$/im)?.[1]?.trim();
  const computerAccount = output.match(/Computer Account\s*=\s*(.+)$/im)?.[1]?.trim();

  return {
    status: bound ? "bound" : output ? "unbound" : "unknown",
    bound,
    domainName: domainName || undefined,
    computerAccount: computerAccount || undefined,
    raw: truncate(output) || undefined
  };
}

async function collectDomain() {
  const [profiles, directoryBinding] = await Promise.all([
    collectProfiles(),
    collectDirectoryBinding()
  ]);

  return {
    status: profiles.status === "available" || directoryBinding.status !== "unknown" ? "available" : "unknown",
    profiles,
    directoryBinding
  };
}

// ── SSH (crypto parity with Linux) ────────────────────────────────
//
// macOS ships OpenSSH; `sshd -T` dumps the effective config (needs root, which
// PrivSvc has). We parse the same shape as the Linux ssh collector so the shared
// SSH crypto catalog rules (ssh.ciphers / ssh.macs / ssh.kexAlgorithms) evaluate
// on macOS too — this REPLACES the old `crypto: phase_2_pending_model_definition`
// stub. `sshd -T` reports the config even when Remote Login is off (latent
// posture); the `services.remoteLogin` block separately reports exposure.
async function collectSsh() {
  const r = await run("/usr/sbin/sshd", ["-T"], 8000);
  return parseSshdConfig(r.output);
}

export async function handleSecurityPosture(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  // Kick off every independent collector in parallel. They each own a
  // single shell call (or a small fixed set), so running them serially
  // would add up to multi-second tail latency on slow disks.
  const [
    filevault,
    firewall,
    gatekeeper,
    sip,
    patches,
    antivirus,
    shares,
    domain,
    screenLock,
    services,
    softwareUpdate,
    accounts
  ] = await Promise.all([
    collectFileVault(),
    collectFirewall(),
    collectGatekeeper(),
    collectSip(),
    collectPatches(),
    collectAntivirus(),
    collectShares(),
    collectDomain(),
    collectScreenLock(),
    collectServices(),
    collectSoftwareUpdate(),
    collectAccounts()
  ]);

  const passwordPolicy = await collectPasswordPolicy();

  const smb = await collectSmb(shares);
  const ssh = await collectSsh();

  return success(req.id, {
    filevault,
    firewall,
    gatekeeper,
    sip,
    patches,
    antivirus,
    shares,
    smb,
    domain,
    // New evidence blocks introduced alongside the agent bump to
    // collector 1.1.0. These are the paths the macOS catalog entries
    // resolve against — the moment both the agent version and these
    // fields land, the 10 gated macOS checks start evaluating for real.
    screenLock,
    services,
    softwareUpdate,
    accounts,
    // Platform parity — local password policy (Linux ships login.defs /
    // pwquality parity; Windows ships secedit parity). Global account
    // policies are readable as root, no console-user context needed.
    passwordPolicy,
    // SSH crypto/hardening posture — the real replacement for the former
    // `crypto` stub. Same shape as the Linux ssh block, so the shared SSH
    // catalog rules (ssh.ciphers / ssh.macs / ssh.kexAlgorithms) evaluate here.
    ssh,
    collectedAtUtc: new Date().toISOString()
  });
}
