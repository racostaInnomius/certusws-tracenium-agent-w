// privsvc/linux/src/mounts-parse.ts
//
// Pure parser + evidence builder for the Linux `mounts` (filesystem hardening)
// block. Dependency-free so it's unit-testable against a /proc/mounts sample.
//
// CIS Linux §1.1 wants sensitive tmp-style filesystems on SEPARATE mounts with
// nodev / nosuid / noexec. We evaluate the three highest-value, lowest-false-
// positive targets: /dev/shm (essentially always a separate tmpfs), /tmp and
// /var/tmp (separate on many systemd distros, on the root fs elsewhere).
//
// OMIT-FOR-NA: when a target is NOT a separate mount (it lives under its parent
// filesystem), we emit `{ separate: false }` and OMIT the option booleans, so
// the backend marks the option checks not_applicable rather than false-failing a
// host whose /tmp simply isn't a dedicated partition.

export interface MountFacts {
  separate: boolean;
  nodev?: boolean;
  nosuid?: boolean;
  noexec?: boolean;
}

// Sanitized evidence keys (paths carry no dots, but underscores keep catalog
// paths clean, e.g. `mounts.dev_shm.nosuid`).
const TARGETS: ReadonlyArray<readonly [string, string]> = [
  ["tmp", "/tmp"],
  ["var_tmp", "/var/tmp"],
  ["dev_shm", "/dev/shm"],
];

/** Parse /proc/mounts into a mountpoint → option-set map. */
export function parseMounts(text: string): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const raw of (text || "").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    // Fields: device mountpoint fstype options dump pass
    const parts = line.split(/\s+/);
    if (parts.length < 4) continue;
    const mountpoint = parts[1];
    const opts = new Set(parts[3].split(",").map((o) => o.trim()).filter(Boolean));
    // A mountpoint can appear more than once (bind mounts / overmounts); the
    // LAST entry is the effective one, so overwrite.
    out.set(mountpoint, opts);
  }
  return out;
}

function factsFor(mounts: Map<string, Set<string>>, path: string): MountFacts {
  const opts = mounts.get(path);
  if (!opts) return { separate: false }; // not a dedicated mount → options omitted
  return {
    separate: true,
    nodev: opts.has("nodev"),
    nosuid: opts.has("nosuid"),
    noexec: opts.has("noexec"),
  };
}

/** Build the `mounts` evidence tree from raw /proc/mounts content. */
export function buildMountsEvidence(procMountsText: string): Record<string, MountFacts> {
  const mounts = parseMounts(procMountsText);
  const evidence: Record<string, MountFacts> = {};
  for (const [key, path] of TARGETS) {
    evidence[key] = factsFor(mounts, path);
  }
  return evidence;
}
