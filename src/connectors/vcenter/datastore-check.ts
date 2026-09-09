/**
 * Datastore capacity pre-check, run before creating a pre-patch snapshot.
 *
 * PURE. Takes measurements, returns a verdict.
 *
 * WHY BOTH A PERCENTAGE AND AN ABSOLUTE FLOOR
 * Measured against a real lab (ADR-0001, Inc 3):
 *
 *   datastore3   22.3 TB capacity   4.1 TB free   18.7% free   ← snapshot succeeded here
 *   NFS backup    8.0 TB            994 GB        12.1%
 *   datastore1     95 GB             94 GB        98.5%
 *
 * A naive "require 20% free" would have BLOCKED the snapshot we actually took
 * successfully — 4.1 TB is ample room for a delta. So a percentage alone is
 * wrong on large datastores. Equally, "require 10 GB free" alone is wrong on
 * small ones: 90% free of a 20 GB datastore is only 18 GB, which looks healthy
 * by ratio and is thin in practice.
 *
 * We therefore require BOTH floors to hold. The percentage catches a datastore
 * in genuine trouble; the absolute catches a small one running out of room.
 *
 * A snapshot's delta grows with every guest write for as long as it lives, and
 * its final size cannot be known in advance — so this is a sanity gate, not a
 * capacity forecast. It exists to refuse the clearly-dangerous case: taking a
 * snapshot on a datastore that is nearly full can wedge the VM itself, which is
 * strictly worse than not patching.
 *
 * ⚠️ WHY `uncommitted` IS REPORTED AND NOT SUBTRACTED
 * It used to be subtracted, and that made the gate reject the very datastore
 * the table above was calibrated on. The first real snapshot ever attempted
 * (2026-09-09, MSIG-RADIUS-CA on datastore3) came back
 * `rejected / low_free_ratio` with 4.06 TB free of 21.83 TB — 18.6%, comfortably
 * over the 10% floor.
 *
 * The calibration tests never caught it because their fixtures omit
 * `uncommitted`, while `datastoresForVm()` always asks vCenter for
 * `summary.uncommitted` — so production rows always carry it and the fixtures
 * never did. The figures in the table above are RAW free space; the code gated
 * on free-minus-uncommitted. Two different rules wearing the same name.
 *
 * And subtracting it in full is the wrong rule anyway: `summary.uncommitted` is
 * the total additional space every thin disk on the datastore COULD eventually
 * consume. It is a capacity-planning horizon, not occupied space, and on any
 * normally thin-provisioned datastore it dwarfs free space — so the gate fired
 * on the common case. Over-commitment is also not made worse by a snapshot that
 * lives for the length of a patch window: the risk it describes exists whether
 * or not we patch, and blocking on it converts a planning problem into an
 * unpatched fleet.
 *
 * So both floors now measure real free space, and over-commitment travels in
 * the detail line where an operator can see it.
 */

export interface DatastoreInfo {
  name: string;
  /** Bytes. */
  capacity: number;
  /** Bytes. */
  freeSpace: number;
  /**
   * Bytes every thin-provisioned disk on this datastore could eventually
   * consume (`summary.uncommitted`). REPORTED, never subtracted — see the note
   * at the top of this file. It is a planning horizon, not occupied space.
   */
  uncommitted?: number;
}

export interface DatastoreThresholds {
  /** Minimum free ratio, 0..1. Default 0.10. */
  minFreeRatio?: number;
  /** Minimum free bytes. Default 10 GiB. */
  minFreeBytes?: number;
}

export const DEFAULT_MIN_FREE_RATIO = 0.1;
export const DEFAULT_MIN_FREE_BYTES = 10 * 1024 ** 3;

export type CapacityVerdict =
  | { ok: true; detail: string }
  | { ok: false; reason: "low_free_ratio" | "low_free_bytes" | "no_capacity_data"; detail: string };

const GiB = (n: number) => (n / 1024 ** 3).toFixed(1) + " GiB";
const pct = (n: number) => (n * 100).toFixed(1) + "%";

/**
 * Free space left if every thin disk on the datastore grew to its full size.
 *
 * INFORMATIONAL ONLY — it does not gate anything. Useful context for an
 * operator ("this datastore is over-committed") and useless as a threshold,
 * because on a normally thin-provisioned datastore it is near zero while the
 * datastore is in no danger at all. Gating on it blocked the one snapshot the
 * lab had proved worked.
 */
export function effectiveFree(ds: DatastoreInfo): number {
  return Math.max(0, ds.freeSpace - uncommittedOf(ds));
}

function uncommittedOf(ds: DatastoreInfo): number {
  return Number.isFinite(ds.uncommitted) ? Math.max(0, ds.uncommitted as number) : 0;
}

/** True when thin-provisioned promises exceed what is actually left. */
export function isOvercommitted(ds: DatastoreInfo): boolean {
  return uncommittedOf(ds) > ds.freeSpace;
}

/** The over-commitment note appended to a detail line, or "" when there is none. */
function overcommitNote(ds: DatastoreInfo): string {
  const u = uncommittedOf(ds);
  if (u <= 0) return "";
  return `, ${GiB(u)} promised to thin disks${u > ds.freeSpace ? " (over-committed)" : ""}`;
}

export function checkDatastore(
  ds: DatastoreInfo,
  thresholds: DatastoreThresholds = {}
): CapacityVerdict {
  const minRatio = thresholds.minFreeRatio ?? DEFAULT_MIN_FREE_RATIO;
  const minBytes = thresholds.minFreeBytes ?? DEFAULT_MIN_FREE_BYTES;

  // No usable numbers is NOT a failure verdict — see checkDatastores() for why
  // the caller proceeds. We just cannot vouch for it.
  if (!Number.isFinite(ds.capacity) || ds.capacity <= 0 || !Number.isFinite(ds.freeSpace)) {
    return {
      ok: false,
      reason: "no_capacity_data",
      detail: `${ds.name}: vCenter reported no usable capacity figures`,
    };
  }

  // Real free space, both floors. Not free-minus-uncommitted — see the top.
  const free = ds.freeSpace;
  const ratio = free / ds.capacity;
  const note = overcommitNote(ds);

  if (ratio < minRatio) {
    return {
      ok: false,
      reason: "low_free_ratio",
      detail: `${ds.name}: ${pct(ratio)} free (${GiB(free)} of ${GiB(ds.capacity)}), below the ${pct(minRatio)} floor${note}`,
    };
  }
  if (free < minBytes) {
    return {
      ok: false,
      reason: "low_free_bytes",
      detail: `${ds.name}: only ${GiB(free)} free, below the ${GiB(minBytes)} floor${note}`,
    };
  }

  return { ok: true, detail: `${ds.name}: ${GiB(free)} free (${pct(ratio)})${note}` };
}

export interface CapacityDecision {
  /** May the snapshot proceed? */
  proceed: boolean;
  /** Set when we could not evaluate — the caller proceeds but logs this. */
  unknown: boolean;
  reason: string | null;
  detail: string;
}

/**
 * Decide for a VM that may span several datastores.
 *
 * The WORST datastore governs: a VM with one disk on a full datastore cannot
 * be safely snapshotted, however roomy its other disks are.
 *
 * FAIL-OPEN when nothing can be measured. If vCenter tells us nothing — no
 * datastores resolved, no usable figures — we proceed. Refusing to patch
 * because a capacity metric was unreadable would turn a monitoring gap into an
 * outage of the patching pipeline, and the snapshot itself will fail loudly if
 * the space genuinely is not there. FAIL-CLOSED only on a measurement that
 * actually says "too full".
 */
export function checkDatastores(
  datastores: DatastoreInfo[],
  thresholds: DatastoreThresholds = {}
): CapacityDecision {
  if (!datastores.length) {
    return {
      proceed: true,
      unknown: true,
      reason: "no_datastore_data",
      detail: "no datastore could be resolved for this VM; proceeding without a capacity check",
    };
  }

  const verdicts = datastores.map((ds) => ({ ds, v: checkDatastore(ds, thresholds) }));
  const blocking = verdicts.filter((x) => !x.v.ok && x.v.reason !== "no_capacity_data");

  if (blocking.length) {
    // Report the tightest one — that is the one an operator must fix. Ranked by
    // REAL free space, the same measure the verdict above gates on.
    const worst = blocking.sort((a, b) => a.ds.freeSpace - b.ds.freeSpace)[0];
    const v = worst.v as Extract<CapacityVerdict, { ok: false }>;
    return { proceed: false, unknown: false, reason: v.reason, detail: v.detail };
  }

  const measured = verdicts.filter((x) => x.v.ok);
  if (!measured.length) {
    return {
      proceed: true,
      unknown: true,
      reason: "no_capacity_data",
      detail: "no datastore reported usable capacity; proceeding without a capacity check",
    };
  }

  return {
    proceed: true,
    unknown: false,
    reason: null,
    detail: measured.map((x) => x.v.detail).join("; "),
  };
}
