// privsvc/macos/src/pwpolicy-parse.ts
//
// Parser for `pwpolicy -getaccountpolicies` (global account policies,
// readable as root — privsvc's context). Two forms carry the minimum
// password length, and a Mac can have both:
//
//   1. The regex form every Mac has by default (field sample,
//      JPR-MacBookPro 2026-08-19):
//        <string>policyAttributePassword matches '.{4,}+'</string>
//      → the {N,} lower bound IS the minimum length (OS default 4).
//   2. The parameter form MDM / `pwpolicy -setaccountpolicies` writes:
//        <key>minimumLength</key><integer>12</integer>
//
// When several policies apply the STRICTEST (max) wins — that's how
// loginwindow enforces them (a password must satisfy every policy).
//
// Absent ≠ compliant: no recognizable policy → undefined, never a
// verdict. But note the OS default regex means real Macs practically
// always yield a number — this check evaluates pass/fail fleet-wide,
// unlike the old askForPassword read.

export function parsePwpolicyMinimumLength(output: string | null | undefined): number | undefined {
  const text = String(output ?? "");
  const candidates: number[] = [];

  // Form 2 — policyParameters integer.
  for (const m of text.matchAll(/<key>minimumLength<\/key>\s*<integer>(\d+)<\/integer>/g)) {
    candidates.push(Number(m[1]));
  }

  // Form 1 — the password regex. Three real shapes seen in the field:
  //   '.{4,}+'      OS default (JPR-MacBookPro)            → 4
  //   '^$|.{4,}+'   OS default allowing a BLANK password    → 0
  //                 (iMac-2, GtecMBPro 2026-08-23): the `^$`
  //                 alternative means the empty string passes, so the
  //                 effective minimum is zero — reporting 4 would hide
  //                 exactly the weakness the check exists for.
  //   '^.{15,}$'    anchored MDM/pwpolicy form              → 15
  // Anything without a recognizable `.{N,}` bound stays undefined:
  // guessing at arbitrary policy regexes would mint verdicts from
  // rules we don't actually understand.
  for (const m of text.matchAll(/policyAttributePassword\s+matches\s+'([^']*)'/g)) {
    const re = m[1];
    if (/(^|\|)\^\$(\||$)/.test(re)) {
      candidates.push(0);
      continue;
    }
    const bound = re.match(/\.\{(\d+),\}/);
    if (bound) candidates.push(Number(bound[1]));
  }

  const valid = candidates.filter((n) => Number.isFinite(n) && n >= 0);
  if (!valid.length) return undefined;
  return Math.max(...valid);
}
