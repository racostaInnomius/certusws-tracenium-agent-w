// privsvc/linux/src/pwquality.ts
//
// Pure parser for the Linux `pwquality` (PAM password-quality) evidence block.
// Dependency-free so it's unit-testable against a pwquality.conf sample.
//
// This is the MODERN complement to the legacy `passwordPolicy` block (which
// reads /etc/login.defs). pwquality.conf (from libpam-pwquality / libpwquality)
// drives pam_pwquality's complexity enforcement: minlen, character classes,
// dictionary checking, repeat limits.
//
// FAIL-HONEST: pwquality.conf ships with every key COMMENTED OUT (the compiled
// default applies). We only report EXPLICITLY-SET (uncommented) keys — a
// commented/unset key means "compiled default in effect", which we can't read
// from the file, so we omit it and let the backend mark that check
// not_applicable rather than guessing the default and false-failing.

// CIS-relevant numeric knobs we surface (other keys are ignored). Values are
// coerced to numbers when they're pure integers.
const NUMERIC_KEYS = new Set([
  "minlen",
  "minclass",
  "dcredit",
  "ucredit",
  "lcredit",
  "ocredit",
  "maxrepeat",
  "maxsequence",
  "maxclassrepeat",
  "dictcheck",
  "usercheck",
  "enforcing",
  "retry",
]);

export type PwqualitySettings = Record<string, number | string>;

/**
 * Parse pwquality.conf content. Returns only EXPLICITLY-SET (uncommented)
 * key=value pairs; commented/absent keys are omitted (→ not_applicable). Later
 * assignments win (matching how pwquality.conf.d drop-ins override the base).
 */
export function parsePwquality(text: string): PwqualitySettings {
  const out: PwqualitySettings = {};
  for (const raw of (text || "").split("\n")) {
    // Whole-line comment or blank → skip. Then strip any inline comment.
    const noComment = raw.replace(/#.*$/, "");
    const line = noComment.trim();
    if (!line) continue;
    const m = /^([A-Za-z_]\w*)\s*=\s*(.+?)\s*$/.exec(line);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const rawVal = m[2].trim();
    if (!NUMERIC_KEYS.has(key)) continue; // ignore keys we don't evaluate
    out[key] = /^-?\d+$/.test(rawVal) ? Number(rawVal) : rawVal;
  }
  return out;
}

/**
 * Shape the evidence block. `configured` = at least one pwquality source exists
 * (the config file was found). When it isn't, applicable:false + no settings so
 * every pwquality rule resolves not_applicable.
 */
export function shapePwqualityEvidence(configured: boolean, settings: PwqualitySettings): Record<string, unknown> {
  if (!configured) return { applicable: false };
  return { applicable: true, ...settings };
}
