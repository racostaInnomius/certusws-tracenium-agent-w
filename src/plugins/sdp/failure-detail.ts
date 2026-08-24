// src/plugins/sdp/failure-detail.ts
//
// The `reason=` an operator reads when an install or uninstall dies before the
// installer ever ran.
//
// WHAT WAS LOST
//
// When the privsvc call comes back `ok:false`, the IPC envelope carries
// `{ code, message }` — and the plugin kept only `code`, falling back to the
// literal "install_failed" when even that was absent. So the most common
// failure in production reached the dashboard as:
//
//     reason=install_failed        exit_code=NULL        stderr_excerpt=(same)
//
// which says exactly one thing: "it failed, and nothing said why". Three of
// three real failures looked like that. The message the privsvc had already
// written was thrown away one line before it could be sent.
//
// WHY THERE IS STILL NO exit=
//
// `exitCode` lives in the response `result`, which does not exist on an
// `ok:false`. This branch means the privsvc never got as far as running the
// installer — an installer that runs and returns 1603 comes back `ok:true` and
// is judged against the expected exit codes further down. So there is no exit
// code here to report, and inventing one would be worse than the silence: it
// would send an operator hunting an MSI error that never happened.
//
// The detail rides inside `reason=` rather than a new key because the backend
// reducer ignores keys it does not know (forward-compat by design). A `detail=`
// segment would be dropped in silence, which is the failure mode this module
// exists to end.

/** Longest reason we emit. The reducer caps at 240; the encoder at 200. */
const MAX_REASON = 180;

/**
 * Collapse anything that would corrupt the `;`-separated ACK grammar, or just
 * make the line unreadable in a table cell.
 */
function flatten(text: string): string {
  return text.replace(/[;\r\n\t]+/g, " ").replace(/\s{2,}/g, " ").trim();
}

/**
 * Build the `reason=` for a privsvc call that failed before the installer ran.
 *
 * `fallback` is the label to use when the privsvc named no code at all — the
 * one case where we genuinely have nothing, and should say so in the caller's
 * own vocabulary ("install_failed" / "uninstall_failed") rather than inventing
 * a diagnosis.
 */
export function failureReason(
  errCode: unknown,
  errMessage: unknown,
  fallback: string
): string {
  const code = flatten(String(errCode ?? "")) || fallback;
  const message = flatten(String(errMessage ?? ""));

  // A privsvc that echoes its own code as the message adds nothing, and
  // "install_failed: install_failed" reads like a bug in us.
  if (!message || message === code) return code.slice(0, MAX_REASON);

  const combined = `${code}: ${message}`;
  if (combined.length <= MAX_REASON) return combined;

  // Keep the code whole and truncate the message — the code is the part an
  // operator groups and searches by, so losing its tail would be worse than
  // losing the tail of a sentence.
  const room = MAX_REASON - code.length - 2;
  if (room <= 0) return code.slice(0, MAX_REASON);
  return `${code}: ${message.slice(0, room)}`;
}
