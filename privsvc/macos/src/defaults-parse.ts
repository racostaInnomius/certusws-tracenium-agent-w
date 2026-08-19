// privsvc/macos/src/defaults-parse.ts
//
// Sprint 4 (SCP) — macOS hardening, item 9. Pure helpers around
// `defaults read` output, extracted so the three collectors that used to
// do `trimmed === "1"` by hand share one (tested) parser.
//
// ── Why "1"/"0" alone was a bug ───────────────────────────────────────
//
// `defaults read` prints the stored plist value in its own syntax. A key
// the GUI toggled is an integer (`1`); the SAME key written by an MDM
// configuration profile or `defaults write … -bool` is a boolean and
// prints `true`/`false` (older tooling: `YES`/`NO`). The collectors
// accepted only "1"/"0", so every managed fleet — exactly the fleet that
// cares about compliance — resolved `undefined` → not_applicable, and
// macos.screen_lock.password_required plus all five softwareUpdate.*
// checks were silently dead on MDM-managed Macs.
//
// ── Absent ≠ compliant, but absent ≠ failed either ───────────────────
//
// `defaults read` exits non-zero for two very different reasons:
//   · the key/domain DOES NOT EXIST → stderr "… does not exist"
//   · the read FAILED (sandbox, corrupt plist, no such user) → other text
// The first is real information ("not configured" = macOS default
// applies); the second is not. classifyDefaultsRead tells them apart so
// a collector can say `false` for a genuinely-absent GuestEnabled (the
// macOS default IS off) without turning a failed read into a PASS.

/** `1`/`0`, `true`/`false`, `YES`/`NO` (any case), else undefined. */
export function parseDefaultsBool(output: string | null | undefined): boolean | undefined {
  if (output === null || output === undefined) return undefined;
  const v = String(output).trim().toLowerCase();
  if (v === "1" || v === "true" || v === "yes") return true;
  if (v === "0" || v === "false" || v === "no") return false;
  return undefined;
}

/** Integer value (`defaults read` prints plain digits for ints). */
export function parseDefaultsInt(output: string | null | undefined): number | undefined {
  if (output === null || output === undefined) return undefined;
  const m = /^-?\d+$/.exec(String(output).trim());
  return m ? Number(m[0]) : undefined;
}

export type DefaultsReadKind = "value" | "absent" | "failed";

/**
 * Classify a `defaults read` result. `ok` is execFile success; `output`
 * is the combined stream (absence is reported on stderr).
 */
export function classifyDefaultsRead(r: { ok: boolean; output: string }): DefaultsReadKind {
  if (r.ok) return "value";
  const o = String(r.output || "");
  // Both phrasings exist across macOS versions:
  //   "The domain/default pair of (X, Y) does not exist"
  //   "Domain X does not exist"
  if (/does not exist/i.test(o)) return "absent";
  return "failed";
}

/**
 * Convenience: bool from a read, with absence semantics.
 *   value  → parsed bool (or undefined if unparseable)
 *   absent → `whenAbsent` (caller decides: false when the macOS default
 *            is off, undefined when absence is not informative)
 *   failed → undefined (never a verdict)
 */
export function boolFromDefaultsRead(
  r: { ok: boolean; output: string; stdout?: string },
  whenAbsent: boolean | undefined
): boolean | undefined {
  const kind = classifyDefaultsRead(r);
  if (kind === "value") return parseDefaultsBool(r.stdout ?? r.output);
  if (kind === "absent") return whenAbsent;
  return undefined;
}
