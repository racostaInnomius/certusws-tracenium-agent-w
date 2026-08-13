// src/plugins/pmp/scan-note.ts
//
// A scan that returns zero patches is ambiguous: the machine may genuinely
// have nothing pending, or the scan may have failed and reported nothing.
// Both render identically ("Inventory Only, 0 patches"), which is how twelve
// servers in one tenant looked fine for weeks while none of them were
// actually scanning.
//
// This turns the privsvc posture into a short human-readable reason, or
// `undefined` when there is genuinely nothing to explain. It is deliberately
// pure and platform-agnostic: the three providers (windows/macos/linux) all
// receive the same `patch.scan` response shape, so they should all be equally
// diagnosable.
//
// The note is a DIAGNOSTIC, not a status. It never changes the reported
// counts or the overall status — it only says why they look the way they do.

/** The subset of a `patch.scan` privsvc response this needs. */
export interface ScanPosture {
  status?: unknown;
  /** privsvc's own explanation (e.g. an stderr tail) when it has one. */
  note?: unknown;
}

/**
 * Statuses that fully explain themselves. Anything else reaching a scan
 * result with no note is worth reporting: it means the provider ended in a
 * state it could not describe.
 */
const SELF_EXPLANATORY = new Set(["updates_available", "healthy"]);

export function deriveScanNote(posture: ScanPosture | null | undefined): string | undefined {
  // privsvc's own note always wins: it carries the real detail (stderr tail,
  // exit code) that we cannot reconstruct here.
  const own = posture?.note;
  if (typeof own === "string" && own.trim()) return own.trim();

  const status = posture?.status;
  if (typeof status !== "string" || !status.trim()) return undefined;
  if (SELF_EXPLANATORY.has(status)) return undefined;

  return `patch scan returned status="${status}" with no items`;
}
