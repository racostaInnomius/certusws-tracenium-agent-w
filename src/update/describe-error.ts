// src/update/describe-error.ts
//
// Turn a thrown value into a line that still says WHY, including when Node
// hands us an error whose message is empty.
//
// THE FAILURE THIS EXISTS TO STOP LOSING
//
// Tenant 111 reported nine `update_failed: AggregateError` in three days. It
// read like a new class of failure. It was not: `AggregateError` is what Node
// throws when a hostname resolves to SEVERAL candidate addresses — happy
// eyeballs, `autoSelectFamily`, on by default since Node 20 — and every one of
// the connection attempts fails. Its own `message` is the empty string and the
// real reasons live in `err.errors[]`.
//
// So the idiom we used everywhere,
//
//     const error = err?.message || String(err);
//
// fell through the empty message to `String(err)`, which for an Error with no
// message is just the class name. Same host, same firewall, same TCP timeout as
// the eighteen `connect ETIMEDOUT 20.60.178.4:443` rows from the week before —
// but with two candidate addresses instead of one, so the entire diagnosis was
// replaced by the word "AggregateError". The reader could not tell which host
// was unreachable, or that it was even a connectivity problem.
//
// This is worth a module rather than an inline `if` because the loss happens at
// exactly the moment the evidence is scarcest: on an endpoint we do not control,
// hours before anyone reads a dashboard, in a catch block that must not throw.

/** Total budget for the rendered line. Bounded because this text travels in a
 *  gRPC ACK and lands in `device_jobs.last_error`; a stack of a hundred DNS
 *  failures helps nobody and would push the useful part off the front. */
const MAX_LENGTH = 300;

/** How deep to follow nested aggregates / causes. Two is enough for the real
 *  shapes (an aggregate of connect errors, or an error wrapping a cause) and
 *  stops a self-referencing chain from spinning. */
const MAX_DEPTH = 2;

/** Reads a property that might be a throwing getter or a hostile proxy. Every
 *  caller of this module is already inside a catch: a describeError that throws
 *  would replace a bad error message with no error at all. */
function safe<T>(read: () => T): T | undefined {
  try {
    return read();
  } catch {
    return undefined;
  }
}

function messageOf(err: any): string {
  const m = safe(() => err?.message);
  return typeof m === "string" ? m.trim() : "";
}

function nameOf(err: any): string {
  const n = safe(() => err?.name);
  if (typeof n === "string" && n.trim()) return n.trim();
  const ctor = safe(() => err?.constructor?.name);
  return typeof ctor === "string" && ctor.trim() ? ctor.trim() : "Error";
}

/** The `errors` array of an AggregateError — or of anything shaped like one.
 *  Duck-typed on purpose: undici and other transports construct their own
 *  aggregate-ish errors that are not `instanceof AggregateError`. */
function causesOf(err: any): any[] {
  const arr = safe(() => err?.errors);
  return Array.isArray(arr) ? arr : [];
}

/**
 * A human-readable one-liner for any thrown value.
 *
 * Ordinary errors render as their message, exactly as before — this is a
 * drop-in for `err?.message || String(err)` and deliberately does not change
 * what those look like, so existing log greps keep working.
 *
 * An aggregate renders as its name, how many attempts it covers, and the
 * distinct reasons:
 *
 *     AggregateError(2): connect ETIMEDOUT 20.60.178.4:443; connect ENETUNREACH 2620:1ec::4:443
 *
 * The count is part of the diagnosis, not decoration: it says how many
 * addresses were tried, which is what separates "the host is down" from "we
 * only ever had one route to it".
 */
export function describeError(err: unknown, depth = 0): string {
  if (err === null) return "null";
  if (err === undefined) return "undefined";
  if (typeof err === "string") return err.trim() || "(empty string)";
  if (typeof err !== "object") return String(err);

  const own = messageOf(err);
  const causes = causesOf(err);

  if (causes.length > 0 && depth < MAX_DEPTH) {
    // Dedupe: happy eyeballs against a host with several A records commonly
    // fails the same way on each, and three copies of one message crowd out a
    // different fourth one that would have been the interesting part.
    const seen = new Set<string>();
    const parts: string[] = [];
    for (const cause of causes) {
      const text = describeError(cause, depth + 1);
      if (!text || seen.has(text)) continue;
      seen.add(text);
      parts.push(text);
    }

    const head = `${nameOf(err)}(${causes.length})`;
    // A non-empty own message is rare on an aggregate but not impossible, and
    // when it is there it is the caller's own framing — keep it in front.
    const prefix = own ? `${head}: ${own}` : head;
    if (parts.length === 0) return truncate(prefix, MAX_LENGTH);
    return truncate(`${prefix}: ${joinBounded(parts, MAX_LENGTH - prefix.length - 2)}`, MAX_LENGTH);
  }

  if (own) {
    // `cause` carries the reason for a wrapper whose own message is generic;
    // append it only when it adds something the message does not already say.
    const cause = safe(() => (err as any)?.cause);
    if (cause && depth < MAX_DEPTH) {
      const causeText = describeError(cause, depth + 1);
      if (causeText && !own.includes(causeText)) {
        return truncate(`${own} (cause: ${causeText})`, MAX_LENGTH);
      }
    }
    return truncate(own, MAX_LENGTH);
  }

  // No message and no causes: the class name is genuinely all we have, but say
  // so explicitly rather than emitting a bare word that reads like a message.
  const asString = safe(() => String(err));
  const fallback = asString && asString !== "[object Object]" ? asString : nameOf(err);
  return truncate(fallback, MAX_LENGTH);
}

/** Join what fits, then say how many were dropped — never silently truncate a
 *  list, or the reader cannot tell a complete picture from a clipped one.
 *
 *  ⚠️ The "(+N more)" notice has to fit INSIDE the budget, not be appended to a
 *  join that already spent it. The first version appended it and let the outer
 *  truncate clip the result, which produced `... (+192 m…` — the announcement
 *  of the truncation, itself truncated. That is the precise failure this
 *  function exists to prevent, so it was worth the second pass. */
function joinBounded(parts: string[], budget: number): string {
  if (budget <= 0) return `${parts.length} causes`;

  const suffix = (dropped: number) => (dropped > 0 ? ` (+${dropped} more)` : "");
  const width = (kept: string[]) =>
    kept.reduce((n, p, i) => n + p.length + (i ? 2 : 0), 0) +
    suffix(parts.length - kept.length).length;

  const kept: string[] = [];
  for (const part of parts) {
    kept.push(part);
    if (width(kept) > budget) {
      kept.pop();
      break;
    }
  }

  // Dropping the last kept part can lengthen the suffix (9 → 10 rolls a digit),
  // so re-check rather than assuming one pop is enough.
  while (kept.length > 0 && width(kept) > budget) kept.pop();

  if (kept.length === 0) return `${parts.length} causes`;
  return kept.join("; ") + suffix(parts.length - kept.length);
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}
