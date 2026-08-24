// src/update/update-source-report.ts
//
// Decide whether this boot owes the control plane a report of WHO SERVED the
// installer for the version now running.
//
// WHY THIS EXISTS
//
// `servedBy` was already computed and already reported — but only on the two
// paths that have a job or a control command behind them, because those are the
// paths with an ACK to attach it to. The periodic update check has neither: the
// scheduler calls runUpdateTask and drops the return value on the floor. The
// tier was computed, written to update state, and thrown away.
//
// That is exactly backwards from what matters. The poll is how the fleet moves
// on its own — a release can reach every endpoint without a single job — so the
// one mechanism we could not measure was the one doing the work. In tenant 111,
// 18 job-driven updates all reported `src=dp`, while every poll-driven update
// reported nothing at all.
//
// REPORTING AT THE NEXT CONNECT, NOT AT INSTALL TIME
//
// The obvious place would be right after runUpdateTask returns "started". But at
// that moment the installer is already running and is about to replace this
// process: anything written to the stream races the agent's own death. The job
// path lives with that race because it has no choice. The poll does — the tier
// is on disk, so the report can simply wait for the next boot, when the new
// version connects and can say "I am 1.1.49, and a DP gave me these bytes".
//
// The guard below is what keeps that honest: it reports only when the version
// the state was attempting is the version actually running now. A failed or
// abandoned update leaves `lastServedBy` behind, and attributing it to whatever
// the endpoint happens to be running would manufacture LAN traffic that never
// happened.

/**
 * Facts namespace for this report.
 *
 * Facts is the only agent→server channel that carries free-form payloads, so
 * riding it means no change to controlplane.proto — and a proto change would
 * have to land in the iOS and Android agents in lockstep to add one string that
 * neither of them has any use for.
 */
export const NAMESPACE = "agent_update";

export interface UpdateSourceReport {
  version: string;
  servedBy: string;
}

export interface UpdateSourceStateView {
  lastServedBy?: string | null;
  lastAttemptedVersion?: string;
}

/**
 * The report this boot owes, or null when it owes none.
 *
 * Returns null — rather than a report with a placeholder — whenever the facts
 * do not line up, because a wrong attribution here is worse than a missing one:
 * the whole point of the field is to answer "how much of the fleet came over the
 * LAN", and that answer is only as good as its refusal to guess.
 */
export function decideSourceReport(
  state: UpdateSourceStateView | null | undefined,
  runningVersion: string | null | undefined
): UpdateSourceReport | null {
  const attempted = String(state?.lastAttemptedVersion ?? "").trim();
  const running = String(runningVersion ?? "").trim();
  if (!attempted || !running) return null;

  // The update did not land — the endpoint is on some other version. Whoever
  // served those bytes did not serve what is running, so say nothing.
  //
  // This guard is also what makes the `origin` default below safe: an attempt
  // that died before downloading anything leaves no tier AND leaves the running
  // version behind the attempted one, so it never reaches that line.
  if (attempted !== running) return null;

  // ⚠️ A MISSING TIER MEANS ORIGIN, NOT "NOTHING TO REPORT".
  //
  // `lastServedBy` is written ONLY inside the `if (viaDp)` branch of
  // update-service — a direct download never sets it. The ACK path has always
  // papered over that with `lastServedBy || "origin"`, which is why `src=origin`
  // shows up in production while the state field is empty.
  //
  // Requiring a non-empty tier here made every WAN update invisible: the first
  // two endpoints to update after this shipped both came over the internet and
  // reported nothing at all. Mirroring the convention the ACK already ships is
  // what makes "what fraction came over the LAN" a real fraction — silence has
  // to land in the denominator, not outside it.
  const servedBy = String(state?.lastServedBy ?? "").trim() || "origin";

  return { version: running, servedBy };
}

/**
 * The outbox payload for a report.
 *
 * Only the payload: the sender loop derives the wire `namespace` and
 * `namespaces` from the payload's own keys, which is also what the backend
 * validator cross-checks them against. Building them here would just be a
 * second copy of the same truth, free to drift.
 */
export function sourceReportPayload(report: UpdateSourceReport): Record<string, unknown> {
  return {
    namespaces: {
      [NAMESPACE]: {
        version: report.version,
        servedBy: report.servedBy,
      },
    },
  };
}
