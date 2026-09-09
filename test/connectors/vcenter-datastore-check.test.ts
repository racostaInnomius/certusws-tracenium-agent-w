import { describe, it, expect } from "vitest";
import {
  checkDatastore,
  checkDatastores,
  effectiveFree,
  isOvercommitted,
  DEFAULT_MIN_FREE_RATIO,
  DEFAULT_MIN_FREE_BYTES,
  type DatastoreInfo,
} from "../../src/connectors/vcenter/datastore-check";

const GB = (n: number) => n * 1024 ** 3;

/**
 * Real measurements from the lab (ADR-0001 Inc 3). These are the calibration
 * data for the thresholds, so they are asserted directly.
 *
 * ⚠️ EVERY FIXTURE CARRIES `uncommitted`, and that is the point.
 * These fixtures used to omit it while `datastoresForVm()` always asks vCenter
 * for `summary.uncommitted` — so every production row had it and no test did.
 * The gate subtracted it, and on 2026-09-09 the first real snapshot ever
 * attempted was refused on THIS datastore (18.6% free) while this very file
 * asserted it should pass. A fixture missing a field the real caller always
 * sends is not a fixture, it is a blindfold.
 */
const LAB = {
  // Where MSIG-VEEAM-SRV and MSIG-RADIUS-CA live, and where a snapshot DID
  // succeed. `uncommitted` from the same vCenter: thin disks across 17 VMs
  // promise far more than the 4.1 TB actually left.
  datastore3: { name: "datastore3", capacity: GB(22354.3), freeSpace: GB(4188.1), uncommitted: GB(9120.4) },
  nfsBackup: { name: "VeeamBackup_NFS", capacity: GB(8192), freeSpace: GB(993.9), uncommitted: GB(0) },
  datastore1: { name: "datastore1", capacity: GB(95.3), freeSpace: GB(93.8), uncommitted: GB(0) },
  datastore2: { name: "datastore2", capacity: GB(21896.8), freeSpace: GB(14127.8), uncommitted: GB(743.1) },
} satisfies Record<string, DatastoreInfo>;

describe("calibration against the real lab", () => {
  it("⭐ ALLOWS the datastore where a snapshot actually succeeded (18.7% free), over-committed or not", () => {
    // The regression this file exists for. A naive "require 20% free" would have
    // blocked a snapshot we know worked; so did subtracting `uncommitted`, which
    // is 9.1 TB here against 4.1 TB free.
    expect(checkDatastore(LAB.datastore3).ok).toBe(true);
  });

  it("allows the 12.1%-free NFS backup store — still ~1 TB absolute", () => {
    expect(checkDatastore(LAB.nfsBackup).ok).toBe(true);
  });

  it("allows a small but nearly-empty datastore", () => {
    expect(checkDatastore(LAB.datastore1).ok).toBe(true);
  });

  it("⭐ says so in the detail when thin disks promise more than is left", () => {
    // Reported, not gated: the operator sees the over-commitment and the
    // snapshot still proceeds.
    const v = checkDatastore(LAB.datastore3);
    expect(v.detail).toContain("promised to thin disks");
    expect(v.detail).toContain("over-committed");
    expect(isOvercommitted(LAB.datastore3)).toBe(true);
  });

  it("a merely thin datastore is noted without being called over-committed", () => {
    const v = checkDatastore(LAB.datastore2);
    expect(v.ok).toBe(true);
    expect(v.detail).toContain("promised to thin disks");
    expect(v.detail).not.toContain("over-committed");
    expect(isOvercommitted(LAB.datastore2)).toBe(false);
  });

  it("effectiveFree still reports the over-commitment horizon, and gates nothing", () => {
    expect(effectiveFree(LAB.datastore2)).toBe(GB(14127.8) - GB(743.1));
    expect(effectiveFree(LAB.datastore3)).toBe(0); // 9.1 TB promised vs 4.1 TB free
    expect(checkDatastore(LAB.datastore3).ok).toBe(true); // …and it still passes
  });
});

describe("both floors must hold", () => {
  it("blocks a large datastore that is genuinely nearly full", () => {
    const v = checkDatastore({ name: "big", capacity: GB(20000), freeSpace: GB(500) });
    expect(v.ok).toBe(false);
    expect((v as any).reason).toBe("low_free_ratio");
  });

  it("blocks a small datastore that looks healthy by ratio but is thin", () => {
    // 90% free of 10 GiB is 9 GiB: an excellent ratio, and still under the
    // absolute floor. This is the case the percentage check cannot see.
    const v = checkDatastore({ name: "tiny", capacity: GB(10), freeSpace: GB(9) });
    expect(v.ok).toBe(false);
    expect((v as any).reason).toBe("low_free_bytes");
  });

  it("allows a small datastore that clears the absolute floor", () => {
    // 18 GiB free is a fine amount of room, small datastore or not — the floor
    // marks clear danger, it is not a forecast of snapshot growth.
    expect(checkDatastore({ name: "small", capacity: GB(20), freeSpace: GB(18) }).ok).toBe(true);
  });

  it("passes only when BOTH floors hold", () => {
    expect(checkDatastore({ name: "ok", capacity: GB(1000), freeSpace: GB(200) }).ok).toBe(true);
  });

  it("uses the documented defaults", () => {
    expect(DEFAULT_MIN_FREE_RATIO).toBe(0.1);
    expect(DEFAULT_MIN_FREE_BYTES).toBe(10 * 1024 ** 3);
  });

  it("honours custom thresholds", () => {
    // The stricter policy the lab data argues against — still available to an
    // operator who wants it.
    expect(checkDatastore(LAB.datastore3, { minFreeRatio: 0.2 }).ok).toBe(false);
  });

  it("⭐ a floor of 0 disables that check, which is what the UI's 0 has to mean", () => {
    const nearlyFull = { name: "brim", capacity: GB(1000), freeSpace: GB(1) };
    // Ratio off, absolute still guarding: 1 GiB is under the 10 GiB floor.
    expect(checkDatastore(nearlyFull, { minFreeRatio: 0 }).ok).toBe(false);
    expect((checkDatastore(nearlyFull, { minFreeRatio: 0 }) as any).reason).toBe("low_free_bytes");
    // Both off: the operator has explicitly accepted the risk.
    expect(checkDatastore(nearlyFull, { minFreeRatio: 0, minFreeBytes: 0 }).ok).toBe(true);
  });

  it("a looser percentage lets a tight-but-large datastore through", () => {
    // The lever that did not exist: 6% of 22 TB is 1.3 TB, ample for a delta.
    const tight = { name: "big", capacity: GB(22000), freeSpace: GB(1400) };
    expect(checkDatastore(tight).ok).toBe(false);
    expect(checkDatastore(tight, { minFreeRatio: 0.05 }).ok).toBe(true);
  });

  it("includes actionable numbers in the message", () => {
    const v = checkDatastore({ name: "big", capacity: GB(20000), freeSpace: GB(500) });
    expect(v.detail).toContain("big");
    expect(v.detail).toMatch(/GiB/);
    expect(v.detail).toMatch(/%/);
  });
});

describe("checkDatastores — the worst datastore governs", () => {
  it("blocks when ANY of the VM's datastores is too full", () => {
    // One disk on a full datastore cannot be safely snapshotted, however roomy
    // the others are.
    const d = checkDatastores([LAB.datastore3, { name: "full", capacity: GB(1000), freeSpace: GB(5) }]);
    expect(d.proceed).toBe(false);
    expect(d.detail).toContain("full");
  });

  it("reports the tightest datastore, the one to fix", () => {
    const d = checkDatastores([
      { name: "tight", capacity: GB(1000), freeSpace: GB(5) },
      { name: "tighter", capacity: GB(1000), freeSpace: GB(1) },
    ]);
    expect(d.detail).toContain("tighter");
  });

  it("proceeds when every datastore is healthy", () => {
    const d = checkDatastores([LAB.datastore3, LAB.datastore1]);
    expect(d.proceed).toBe(true);
    expect(d.unknown).toBe(false);
  });
});

describe("fail-OPEN when nothing can be measured", () => {
  it("proceeds when no datastore resolved", () => {
    // Refusing to patch because a metric was unreadable would turn a monitoring
    // gap into an outage of the whole patching pipeline.
    const d = checkDatastores([]);
    expect(d.proceed).toBe(true);
    expect(d.unknown).toBe(true);
    expect(d.reason).toBe("no_datastore_data");
  });

  it("proceeds when vCenter reports unusable figures", () => {
    const d = checkDatastores([{ name: "weird", capacity: 0, freeSpace: NaN }]);
    expect(d.proceed).toBe(true);
    expect(d.unknown).toBe(true);
    expect(d.reason).toBe("no_capacity_data");
  });

  it("still BLOCKS on a real measurement even when another store is unreadable", () => {
    // Fail-open covers ignorance, not evidence.
    const d = checkDatastores([
      { name: "unknown", capacity: 0, freeSpace: NaN },
      { name: "full", capacity: GB(1000), freeSpace: GB(2) },
    ]);
    expect(d.proceed).toBe(false);
    expect(d.unknown).toBe(false);
  });
});
