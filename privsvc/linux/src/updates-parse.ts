// privsvc/linux/src/updates-parse.ts
//
// Pure parsers for the Linux `updates` (patch-compliance) evidence block.
// Kept dependency-free so they're unit-testable in isolation without pulling in
// the privsvc logger/protocol/exec machinery.
//
// Patch compliance on Linux is about PENDING updates (what still needs to be
// installed), not installed history like the Windows/macOS `patches` block — so
// this block reports "how many updates are available, how many are security, and
// is a reboot pending" per package manager. Counting is best-effort and the
// exact wire format varies by tool/version, so callers report `raw` alongside
// the parsed numbers and leave a count null (rather than guess 0) when a tool's
// output can't be parsed.

export type LinuxPackageManager = "apt" | "dnf" | "yum" | "zypper";

export interface LinuxUpdatesCounts {
  /** Total pending package updates, or null if the tool couldn't be parsed. */
  updatesAvailable: number | null;
  /** Security-flagged pending updates, or null when the tool can't distinguish. */
  securityUpdatesAvailable: number | null;
}

/**
 * apt-check (`/usr/lib/update-notifier/apt-check`) prints "TOTAL;SECURITY" on
 * STDERR and exits 0. This is the canonical Debian/Ubuntu source and, unlike
 * `apt-get -s`, gives an exact security count. Returns null when the line isn't
 * the expected "N;M" shape.
 */
export function parseAptCheck(stderr: string): { total: number; security: number } | null {
  const m = /(\d+)\s*;\s*(\d+)/.exec(stderr || "");
  if (!m) return null;
  return { total: Number(m[1]), security: Number(m[2]) };
}

/**
 * `apt-get -s upgrade` (simulate, local cache, no network) lists each pending
 * upgrade as an "Inst <pkg> [old] (new <origin> [arch])" line. Total = number of
 * Inst lines; security = those whose origin token names a *-security suite
 * (e.g. "noble-security", "bookworm-security"). The security count is a lower
 * bound (an update can be pulled from a non-security suite yet fix a CVE), hence
 * apt-check is preferred when present.
 */
export function parseAptSimulate(stdout: string): { total: number; security: number } {
  let total = 0;
  let security = 0;
  for (const line of (stdout || "").split("\n")) {
    if (!/^Inst\s/.test(line)) continue;
    total += 1;
    if (/-security[\s/\]]/i.test(line) || /\bsecurity\b/i.test(line.replace(/^Inst\s+\S+/, ""))) {
      security += 1;
    }
  }
  return { total, security };
}

/**
 * `dnf -C check-update` / `yum -C check-update` exit 100 when updates exist, 0
 * when none, anything else = error. On 100 the stdout lists "name.arch  version
 * repo" rows (with an optional "Obsoleting Packages" trailer we must NOT count).
 * Returns the package count, 0 on a clean exit, or null on an error/other code.
 */
export function parseDnfCheckUpdate(stdout: string, code: number | null): number | null {
  if (code === 0) return 0;
  if (code !== 100) return null; // 1/other → error; don't invent a number
  let count = 0;
  for (const raw of (stdout || "").split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    if (/^Obsoleting\s+Packages/i.test(line)) break; // trailer section — stop
    if (/^Last\s+metadata/i.test(line)) continue;
    if (/^(Security|Updating|Loaded|Excluding)/i.test(line)) continue;
    const cols = line.split(/\s+/);
    // A package row is "name.arch  version  repo" — first token carries the
    // ".arch" dot; guards against wrapped continuation lines.
    if (cols.length >= 3 && cols[0].includes(".")) count += 1;
  }
  return count;
}

/**
 * `dnf -C updateinfo list --updates --security` lists one row per pending
 * security update: "ADVISORY  Severity/Sec.  package". Count the rows carrying
 * the "/Sec." severity marker (dnf's stable suffix for security advisories),
 * ignoring metadata/header noise. Returns a count (0 when none).
 */
export function parseDnfSecurityCount(stdout: string): number {
  let count = 0;
  for (const raw of (stdout || "").split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    if (/^Last\s+metadata/i.test(line)) continue;
    if (/\/Sec\.?/i.test(line)) count += 1;
  }
  return count;
}

/**
 * zypper table output (`zypper -q list-updates` or `list-patches --category
 * security`) is a "S | Repo | Name | ... " table. Count the data rows: lines
 * that start with a "v |" / "  |" cell and contain pipe separators, skipping the
 * header row and its "---+---" separator.
 */
export function parseZypperTableCount(stdout: string): number {
  let count = 0;
  for (const raw of (stdout || "").split("\n")) {
    const line = raw.trim();
    if (!line || !line.includes("|")) continue;
    if (/^-+\+/.test(line) || /-{3,}/.test(line)) continue; // separator row
    if (/^(S\s*\||Repository\s*\||Name\s*\||Category\s*\|)/i.test(line)) continue; // header
    count += 1;
  }
  return count;
}

/**
 * `needs-restarting -r` (dnf-utils / yum-utils) exits 1 when a reboot is
 * required, 0 when not. ENOENT / other codes → null (can't tell).
 */
export function parseNeedsRestarting(code: number | null): boolean | null {
  if (code === 0) return false;
  if (code === 1) return true;
  return null;
}

export interface LinuxUpdatesEvidenceIn {
  applicable: boolean;
  manager: LinuxPackageManager | null;
  source?: string;
  updatesAvailable?: number | null;
  securityUpdatesAvailable?: number | null;
  rebootRequired?: boolean | null;
  raw?: string;
  error?: string;
}

/**
 * Prune the raw collector result into the evidence block we actually ship.
 *
 * CRITICAL for correct scoring: the backend evaluator only marks a check
 * `not_applicable` when the evidence PATH IS ABSENT — a present `null` is treated
 * as a real value (Number(null)===0 would falsely PASS a "no pending security
 * updates" rule; null===false would falsely FAIL a "reboot not required" rule).
 * So we OMIT any evaluated field we couldn't determine, exactly like the
 * selinux/apparmor collectors omit their whole block on the wrong distro family.
 * `applicable`/`manager`/`raw` are kept for diagnostics but no rule reads them.
 */
export function shapeUpdatesEvidence(e: LinuxUpdatesEvidenceIn): Record<string, unknown> {
  const out: Record<string, unknown> = { applicable: e.applicable, manager: e.manager };
  if (e.source) out.source = e.source;
  if (typeof e.updatesAvailable === "number") out.updatesAvailable = e.updatesAvailable;
  if (typeof e.securityUpdatesAvailable === "number") out.securityUpdatesAvailable = e.securityUpdatesAvailable;
  if (typeof e.rebootRequired === "boolean") out.rebootRequired = e.rebootRequired;
  if (e.raw) out.raw = e.raw;
  if (e.error) out.error = e.error;
  return out;
}
