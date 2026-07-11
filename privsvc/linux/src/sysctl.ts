// privsvc/linux/src/sysctl.ts
//
// Pure helpers for the Linux `sysctl` (kernel/network hardening) evidence block.
// Dependency-free so the tree-building + coercion logic is unit-testable without
// touching /proc.
//
// WHY A NESTED TREE: sysctl keys are dotted (`net.ipv4.conf.all.rp_filter`), and
// the backend evaluator resolves an evidence path by splitting on '.' and
// walking nested objects. So a flat `{ "net.ipv4...": 1 }` map would be
// unaddressable — we must materialise the dotted key into a nested object tree,
// then a catalog rule reads e.g. `sysctl.net.ipv4.conf.all.rp_filter`.
//
// OMIT-FOR-NA: a key whose /proc/sys file is absent (param not present on this
// kernel, IPv6 disabled, container without the knob) is simply left out of the
// tree, so its path resolves to "not reported" → the backend marks the check
// not_applicable rather than scoring a missing knob as a failure.

// The curated hardening keys we read. Deliberately EXCLUDES environment-
// dependent knobs (e.g. net.ipv4.ip_forward, which routers / k8s nodes / NAT
// hosts legitimately enable) to avoid false failures. Each of these is a safe
// default a hardened server should carry.
export const SYSCTL_KEYS: readonly string[] = [
  "net.ipv4.conf.all.accept_redirects",
  "net.ipv4.conf.all.send_redirects",
  "net.ipv4.conf.all.accept_source_route",
  "net.ipv4.conf.all.rp_filter",
  "net.ipv4.conf.all.log_martians",
  "net.ipv4.tcp_syncookies",
  "net.ipv4.icmp_echo_ignore_broadcasts",
  "kernel.randomize_va_space",
];

/** Coerce a raw /proc/sys value: a pure integer → number, otherwise trimmed string. */
export function coerceSysctlValue(raw: string): number | string {
  const t = (raw ?? "").trim();
  return /^-?\d+$/.test(t) ? Number(t) : t;
}

/**
 * Build a nested object tree from dotted-key entries. Missing values (null/
 * undefined) are skipped so their path stays absent (→ not_applicable). Keys are
 * plain identifiers (net/ipv4/conf/all/...) — no prototype-pollution risk, but we
 * still guard the dangerous segment names defensively.
 */
export function buildSysctlTree(
  entries: Array<{ key: string; value: number | string | null | undefined }>
): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  const BLOCKED = new Set(["__proto__", "constructor", "prototype"]);
  for (const { key, value } of entries) {
    if (value === null || value === undefined) continue;
    const parts = key.split(".").filter(Boolean);
    if (parts.length === 0 || parts.some((p) => BLOCKED.has(p))) continue;
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      const seg = parts[i];
      if (typeof node[seg] !== "object" || node[seg] === null) node[seg] = {};
      node = node[seg] as Record<string, unknown>;
    }
    node[parts[parts.length - 1]] = value;
  }
  return root;
}
