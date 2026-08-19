// privsvc/linux/src/screen-lock-parse.ts
//
// Sprint 4 (SCP) item 1 — Linux screen-lock evidence (parity with the
// macOS `screenLock` block and the new Windows one).
//
// ── Why files, not gsettings ──────────────────────────────────────────
//
// `gsettings get org.gnome.desktop.screensaver lock-enabled` answers for
// the CALLING user's dconf profile. privsvc runs as root, so it would
// read root's (empty) settings — the exact trap the macOS collector fell
// into with `defaults -currentHost read` under root, and the reason the
// Windows collector reads HKLM policy instead of HKCU. Enumerating
// logged-in users and `runuser`-ing gsettings per session is heavy,
// racy, and still misses the "nobody logged in" case.
//
// What an ENTERPRISE actually configures is the system dconf policy:
//   /etc/dconf/db/local.d/*        keyfile fragments (any name)
//   /etc/dconf/db/local.d/locks/*  keys the user may not override
// under [org/gnome/desktop/screensaver] and [org/gnome/desktop/session].
// That is what CIS Ubuntu §1.8.x / STIG UBTU-*-010004… audit, and it's
// readable as plain files by root. So we parse THAT.
//
// ── Absent ≠ compliant ────────────────────────────────────────────────
//
// No dconf policy dir, or no relevant keys in it → the fields are
// OMITTED, not false. A workstation whose lock is set per-user in the
// user's own dconf (the default GNOME experience) will resolve
// not_applicable here — that's honest: we cannot see it from where
// privsvc sits, and claiming "unlocked" would be a lie. `available:
// false` additionally flags "no GNOME/dconf at all" (headless server)
// so the catalog rule doesn't fail a box that has no screen.

export type ScreenLockEvidence = {
  // false when /etc/dconf/db doesn't exist (no dconf → no GNOME desktop
  // policy surface on this host: headless server, KDE-only, …).
  available: boolean;
  // Present only when found in the system policy fragments:
  lockEnabled?: boolean;        // org/gnome/desktop/screensaver lock-enabled
  lockDelaySecs?: number;       // org/gnome/desktop/screensaver lock-delay (uint32 N)
  idleDelaySecs?: number;       // org/gnome/desktop/session idle-delay (uint32 N)
  // Whether the corresponding key is LOCKED (user cannot override) —
  // CIS wants both set AND locked. Present only when a locks/ fragment
  // names the key.
  lockEnabledLocked?: boolean;
  idleDelayLocked?: boolean;
  lockDelayLocked?: boolean;
  // Diagnostics
  sourceFiles?: string[];
  raw?: string;
};

type Kv = Map<string, string>; // "section/key" → raw value

/**
 * Parse one or more dconf keyfile fragments (INI-ish: [section] then
 * key=value). Later fragments override earlier ones for the same key,
 * mirroring dconf's own "last file wins" alphabetical merge. Returns
 * a flat map keyed "org/gnome/desktop/screensaver/lock-enabled".
 */
export function parseDconfKeyfiles(fragments: Array<{ name: string; text: string }>): Kv {
  const out: Kv = new Map();
  const ordered = [...fragments].sort((a, b) => a.name.localeCompare(b.name));
  for (const { text } of ordered) {
    let section = "";
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) continue;
      const sec = /^\[([^\]]+)\]$/.exec(line);
      if (sec) {
        section = sec[1].trim();
        continue;
      }
      const eq = line.indexOf("=");
      if (eq <= 0 || !section) continue;
      const key = line.slice(0, eq).trim();
      const value = line.slice(eq + 1).trim();
      out.set(`${section}/${key}`, value);
    }
  }
  return out;
}

/**
 * Parse dconf lock files: one absolute key path per line, e.g.
 * "/org/gnome/desktop/screensaver/lock-enabled".
 */
export function parseDconfLocks(fragments: Array<{ name: string; text: string }>): Set<string> {
  const out = new Set<string>();
  for (const { text } of fragments) {
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      out.add(line.replace(/^\//, ""));
    }
  }
  return out;
}

// dconf/GVariant literal parsing for the three shapes these keys use.
export function parseGVariantBool(v: string | undefined): boolean | undefined {
  if (v === undefined) return undefined;
  const t = v.trim().toLowerCase();
  if (t === "true") return true;
  if (t === "false") return false;
  return undefined;
}

export function parseGVariantUint(v: string | undefined): number | undefined {
  if (v === undefined) return undefined;
  const m = /^(?:uint32\s+)?(\d+)$/i.exec(v.trim());
  if (!m) return undefined;
  const n = Number(m[1]);
  return Number.isFinite(n) ? n : undefined;
}

export function buildScreenLockEvidence(
  input: {
    dconfDbExists: boolean;
    keyfiles: Array<{ name: string; text: string }>;
    lockfiles: Array<{ name: string; text: string }>;
  }
): ScreenLockEvidence {
  if (!input.dconfDbExists) return { available: false };

  const kv = parseDconfKeyfiles(input.keyfiles);
  const locks = parseDconfLocks(input.lockfiles);
  const ev: ScreenLockEvidence = { available: true };

  const lockEnabled = parseGVariantBool(kv.get("org/gnome/desktop/screensaver/lock-enabled"));
  if (lockEnabled !== undefined) ev.lockEnabled = lockEnabled;
  const lockDelay = parseGVariantUint(kv.get("org/gnome/desktop/screensaver/lock-delay"));
  if (lockDelay !== undefined) ev.lockDelaySecs = lockDelay;
  const idleDelay = parseGVariantUint(kv.get("org/gnome/desktop/session/idle-delay"));
  if (idleDelay !== undefined) ev.idleDelaySecs = idleDelay;

  if (locks.size > 0) {
    ev.lockEnabledLocked = locks.has("org/gnome/desktop/screensaver/lock-enabled");
    ev.idleDelayLocked = locks.has("org/gnome/desktop/session/idle-delay");
    ev.lockDelayLocked = locks.has("org/gnome/desktop/screensaver/lock-delay");
  }

  const sources = [...input.keyfiles, ...input.lockfiles].map((f) => f.name);
  if (sources.length) ev.sourceFiles = sources;
  return ev;
}
