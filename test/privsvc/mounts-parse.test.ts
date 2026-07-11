// test/privsvc/mounts-parse.test.ts
//
// Unit coverage for the Linux filesystem-hardening (`mounts`) evidence builder:
// /proc/mounts parsing + per-target separate/nodev/nosuid/noexec facts, and the
// omit-for-not_applicable behavior when a target isn't a dedicated mount.

import { describe, it, expect } from "vitest";
import { parseMounts, buildMountsEvidence } from "../../privsvc/linux/src/mounts-parse";

const PROC_MOUNTS = [
  "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0",
  "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0",
  "tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime 0 0",
  "tmpfs /tmp tmpfs rw,nosuid,nodev,relatime 0 0", // note: NO noexec
  "/dev/sda1 / ext4 rw,relatime 0 0",
].join("\n");

describe("parseMounts", () => {
  it("maps each mountpoint to its option set (last entry wins)", () => {
    const m = parseMounts(PROC_MOUNTS);
    expect(m.get("/dev/shm")).toEqual(new Set(["rw", "nosuid", "nodev", "noexec", "relatime"]));
    expect(m.get("/")?.has("relatime")).toBe(true);
  });

  it("ignores malformed lines", () => {
    expect(parseMounts("garbage\n\n").size).toBe(0);
  });
});

describe("buildMountsEvidence", () => {
  it("reports separate mounts with their nodev/nosuid/noexec flags", () => {
    const ev = buildMountsEvidence(PROC_MOUNTS);
    expect(ev.dev_shm).toEqual({ separate: true, nodev: true, nosuid: true, noexec: true });
    // /tmp is separate but lacks noexec → the noexec rule will fail (correctly).
    expect(ev.tmp).toEqual({ separate: true, nodev: true, nosuid: true, noexec: false });
  });

  it("marks a non-dedicated target separate:false and OMITS the option flags (→ NA)", () => {
    // /var/tmp is not a distinct mount in the sample → lives under /.
    const ev = buildMountsEvidence(PROC_MOUNTS);
    expect(ev.var_tmp).toEqual({ separate: false });
    expect(ev.var_tmp).not.toHaveProperty("nosuid");
  });

  it("marks every target separate:false when /proc/mounts is empty", () => {
    const ev = buildMountsEvidence("");
    expect(ev.tmp).toEqual({ separate: false });
    expect(ev.dev_shm).toEqual({ separate: false });
  });
});
