// privsvc/linux/src/disk-encryption-parse.ts
//
// Sprint 4 (SCP) item 1 — Linux disk-encryption evidence.
//
// Until this collector existed, a Linux fleet had ZERO encryption-at-rest
// evidence: BitLocker on Windows and FileVault on macOS each fed a
// catalog check, Linux had nothing. Biggest single platform-parity gap
// in the 2026-08 SCP audit.
//
// ── Approach ──────────────────────────────────────────────────────────
//
// `lsblk -J -o NAME,TYPE,FSTYPE,MOUNTPOINT` gives the whole block tree
// as JSON — no text parsing, stable across util-linux versions, and it
// shows dm-crypt/LUKS mappings as `type: "crypt"` children of their
// backing partition. A mountpoint is "encrypted" when ANY ancestor in
// its lsblk chain is `crypt` (LUKS-on-LVM, LVM-on-LUKS and plain
// dm-crypt all satisfy that; so does an encrypted root under a
// `crypt` → `lvm` → mountpoint chain).
//
// Pure functions here (testable on canned lsblk output); the collector
// in security-posture.ts does the exec + the absent≠compliant shaping.
//
// ── Absent ≠ compliant ────────────────────────────────────────────────
//
// If lsblk is missing or its JSON is unparseable we return
// `{ available: false }` and NO per-target facts, so the catalog rule
// resolves not_applicable rather than scoring a false pass. Only a
// successful read of the tree may produce `encrypted: true|false`.

export type LsblkNode = {
  name?: string;
  type?: string;
  fstype?: string | null;
  mountpoint?: string | null;
  // util-linux ≥ 2.37 also emits `mountpoints: []` (plural); we accept
  // both so btrfs-subvolume hosts (multiple mountpoints per device)
  // still resolve.
  mountpoints?: Array<string | null> | null;
  children?: LsblkNode[];
};

export type EncryptionTargetFact = {
  mountpoint: string;
  encrypted: boolean;
  // The device chain from the leaf up to the top-level disk, e.g.
  // ["ubuntu--vg-root", "dm_crypt-0", "nvme0n1p3", "nvme0n1"] — kept
  // as diagnostics so an operator can see WHY we called it encrypted.
  chain: string[];
  cryptLayer: string | null; // name of the crypt node, when present
};

export type DiskEncryptionEvidence = {
  available: boolean;
  // Present only when available: one fact per target mountpoint that
  // exists on the host. Targets that aren't mounted are OMITTED (not
  // false) → catalog not_applicable for e.g. a host with no separate
  // /home. Order = TARGETS order.
  targets?: EncryptionTargetFact[];
  // Flat per-target facts under catalog-friendly keys, so evaluator
  // rules stay plain `equals` on `diskEncryption.root.encrypted` /
  // `diskEncryption.home.encrypted` (dot-path resolution can't index
  // into `targets[]`). Same omission contract as `targets`.
  root?: { encrypted: boolean };
  home?: { encrypted: boolean };
  // Convenience: true when every present target is encrypted, false
  // when any present target is plaintext, absent when no target
  // exists at all.
  allTargetsEncrypted?: boolean;
  raw?: string;
};

// What we care about for a compliance verdict. Root is the one that
// matters (CIS 1.x "ensure disk encryption" targets the OS volume);
// /home is checked separately when it's a dedicated mount because
// user data is the higher-value asset on workstations.
export const TARGETS: readonly string[] = ["/", "/home"];

export function parseLsblkJson(raw: string): LsblkNode[] | null {
  try {
    const parsed = JSON.parse(raw);
    const devices = parsed?.blockdevices;
    return Array.isArray(devices) ? (devices as LsblkNode[]) : null;
  } catch {
    return null;
  }
}

function mountpointsOf(node: LsblkNode): string[] {
  const out: string[] = [];
  if (typeof node.mountpoint === "string" && node.mountpoint) out.push(node.mountpoint);
  if (Array.isArray(node.mountpoints)) {
    for (const mp of node.mountpoints) {
      if (typeof mp === "string" && mp && !out.includes(mp)) out.push(mp);
    }
  }
  return out;
}

/**
 * Walk the tree once and index every mountpoint → its ancestor chain
 * (leaf first). Multiple devices can claim the same mountpoint (btrfs
 * subvolumes, bind-mount artefacts) — first hit wins, which for lsblk's
 * stable ordering is the underlying device.
 */
export function indexMountpoints(devices: LsblkNode[]): Map<string, LsblkNode[]> {
  const idx = new Map<string, LsblkNode[]>();
  const walk = (node: LsblkNode, ancestors: LsblkNode[]) => {
    const chain = [node, ...ancestors];
    for (const mp of mountpointsOf(node)) {
      if (!idx.has(mp)) idx.set(mp, chain);
    }
    for (const child of node.children ?? []) walk(child, chain);
  };
  for (const dev of devices) walk(dev, []);
  return idx;
}

export function buildDiskEncryptionEvidence(
  devices: LsblkNode[] | null,
  raw?: string
): DiskEncryptionEvidence {
  if (!devices) return { available: false, ...(raw ? { raw } : {}) };

  const idx = indexMountpoints(devices);
  const targets: EncryptionTargetFact[] = [];
  for (const mp of TARGETS) {
    const chain = idx.get(mp);
    if (!chain) continue; // not a mount on this host → omit → not_applicable
    const cryptNode = chain.find((n) => String(n.type ?? "").toLowerCase() === "crypt");
    targets.push({
      mountpoint: mp,
      encrypted: Boolean(cryptNode),
      chain: chain.map((n) => String(n.name ?? "?")),
      cryptLayer: cryptNode ? String(cryptNode.name ?? "crypt") : null,
    });
  }

  const evidence: DiskEncryptionEvidence = { available: true, targets };
  for (const t of targets) {
    if (t.mountpoint === "/") evidence.root = { encrypted: t.encrypted };
    if (t.mountpoint === "/home") evidence.home = { encrypted: t.encrypted };
  }
  if (targets.length > 0) {
    evidence.allTargetsEncrypted = targets.every((t) => t.encrypted);
  }
  if (raw) evidence.raw = raw;
  return evidence;
}
