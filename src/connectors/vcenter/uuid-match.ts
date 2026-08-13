/**
 * Endpoint -> vCenter VM correlation.
 *
 * PURE. No I/O. See ADR-0001 (Inc 0 results) for the empirical basis:
 *
 *   agent  static.system.uuid   = dd4f3942-f393-1a50-8614-c6fa55f75468
 *   vCenter config.uuid         = 42394fdd-93f3-501a-8614-c6fa55f75468
 *   agent  static.system.serial = "VMware-42 39 4f dd 93 f3 50 1a-86 14 c6 fa 55 f7 54 68"
 *
 * Two independent correlation keys exist:
 *   1. system.uuid, which on Windows/WMI is byte-swapped in the first three
 *      SMBIOS fields relative to vCenter's config.uuid.
 *   2. system.serial, which carries the raw SMBIOS bytes IN ORDER and therefore
 *      equals config.uuid once the "VMware-" prefix and spaces are stripped.
 *
 * The swap is a property of how the OS surfaces SMBIOS, not of vCenter, so it
 * can differ per platform. We therefore never assume a single form: we emit
 * ordered candidates and let the caller try each. Wrong guess = no match =
 * fail-closed (no snapshot, no patch), never a snapshot of the WRONG VM.
 */

export type MatchCandidateSource = "uuid_raw" | "uuid_swapped" | "serial_smbios";

export interface MatchCandidate {
  /** Canonical lowercase dashed UUID to query vCenter with. */
  uuid: string;
  /** Where this candidate came from — surfaced in diagnostics. */
  source: MatchCandidateSource;
}

/** Lowercase, strip surrounding whitespace/braces. Returns null if not a UUID. */
export function normalizeUuid(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const cleaned = raw.trim().replace(/^[{(]|[})]$/g, "").toLowerCase();
  const hex = cleaned.replace(/-/g, "");
  if (!/^[0-9a-f]{32}$/.test(hex)) return null;
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Swap endianness of the first three UUID fields (4-2-2), leaving the last two
 * untouched. This is the SMBIOS >=2.6 mixed-endian convention. Involutive:
 * byteSwapUuid(byteSwapUuid(x)) === x.
 */
export function byteSwapUuid(raw: string): string | null {
  const u = normalizeUuid(raw);
  if (!u) return null;
  const b = u.replace(/-/g, "").match(/../g)!;
  const f1 = [b[3], b[2], b[1], b[0]].join("");
  const f2 = [b[5], b[4]].join("");
  const f3 = [b[7], b[6]].join("");
  const f4 = [b[8], b[9]].join("");
  const f5 = b.slice(10).join("");
  return `${f1}-${f2}-${f3}-${f4}-${f5}`;
}

/**
 * Parse the SMBIOS system serial as reported by VMware guests, e.g.
 *   "VMware-42 39 4f dd 93 f3 50 1a-86 14 c6 fa 55 f7 54 68"
 * The 16 bytes are in raw order and map directly onto vCenter's config.uuid.
 * Returns null for non-VMware or malformed serials.
 */
export function uuidFromSmbiosSerial(serial: unknown): string | null {
  if (typeof serial !== "string") return null;
  const hex = serial
    .trim()
    .replace(/^vmware-/i, "")
    .replace(/[\s-]/g, "")
    .toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) return null;
  return normalizeUuid(hex);
}

export interface EndpointVmFacts {
  /** static.system.uuid as collected by the agent. */
  uuid?: unknown;
  /** static.system.serial as collected by the agent. */
  serial?: unknown;
  /** static.system.virtual — only virtual machines can be correlated. */
  virtual?: unknown;
}

/**
 * Ordered, de-duplicated list of UUIDs to try against vCenter.
 *
 * Order matters: raw first (cheapest, correct on platforms that don't swap),
 * then swapped (the observed Windows case), then the serial-derived value as a
 * cross-check. Returns [] when the endpoint is not a VM or has no usable facts,
 * which the caller must treat as "not correlatable" — never as "match anything".
 */
export function buildMatchCandidates(facts: EndpointVmFacts): MatchCandidate[] {
  if (facts.virtual !== true && String(facts.virtual).toLowerCase() !== "true") return [];

  const out: MatchCandidate[] = [];
  const seen = new Set<string>();
  const push = (uuid: string | null, source: MatchCandidateSource) => {
    if (!uuid || seen.has(uuid)) return;
    seen.add(uuid);
    out.push({ uuid, source });
  };

  const raw = normalizeUuid(facts.uuid);
  push(raw, "uuid_raw");
  if (raw) push(byteSwapUuid(raw), "uuid_swapped");
  push(uuidFromSmbiosSerial(facts.serial), "serial_smbios");

  return out;
}
