// test/privsvc/disk-encryption-parse.test.ts
//
// Linux disk-encryption evidence (Sprint 4 — platform parity). Canned
// lsblk -J trees for the three shapes that matter in the field, plus
// the absent≠compliant contract.

import { describe, it, expect } from "vitest";
import {
  parseLsblkJson,
  buildDiskEncryptionEvidence,
  indexMountpoints,
} from "../../privsvc/linux/src/disk-encryption-parse";

// Ubuntu installer default with "encrypt the new installation":
// nvme0n1p3 → dm_crypt-0 (crypt) → ubuntu--vg-root (lvm) → /
const LUKS_ON_LVM = JSON.stringify({
  blockdevices: [
    { name: "nvme0n1", type: "disk", fstype: null, mountpoint: null, children: [
      { name: "nvme0n1p1", type: "part", fstype: "vfat", mountpoint: "/boot/efi" },
      { name: "nvme0n1p2", type: "part", fstype: "ext4", mountpoint: "/boot" },
      { name: "nvme0n1p3", type: "part", fstype: "crypto_LUKS", mountpoint: null, children: [
        { name: "dm_crypt-0", type: "crypt", fstype: "LVM2_member", mountpoint: null, children: [
          { name: "ubuntu--vg-root", type: "lvm", fstype: "ext4", mountpoint: "/" },
        ] },
      ] },
    ] },
  ],
});

// Plain install, no encryption, separate /home.
const PLAINTEXT_WITH_HOME = JSON.stringify({
  blockdevices: [
    { name: "sda", type: "disk", children: [
      { name: "sda1", type: "part", fstype: "ext4", mountpoint: "/" },
      { name: "sda2", type: "part", fstype: "ext4", mountpoint: "/home" },
    ] },
  ],
});

// Encrypted root, PLAINTEXT separate /home — the case that must not
// be reported as fully compliant.
const MIXED = JSON.stringify({
  blockdevices: [
    { name: "sda", type: "disk", children: [
      { name: "sda1", type: "part", fstype: "crypto_LUKS", children: [
        { name: "root_crypt", type: "crypt", fstype: "ext4", mountpoint: "/" },
      ] },
      { name: "sda2", type: "part", fstype: "ext4", mountpoint: "/home" },
    ] },
  ],
});

// util-linux ≥ 2.37 emits `mountpoints` (plural). btrfs subvolume host.
const PLURAL_MOUNTPOINTS = JSON.stringify({
  blockdevices: [
    { name: "vda", type: "disk", children: [
      { name: "vda2", type: "part", fstype: "crypto_LUKS", children: [
        { name: "luks-abc", type: "crypt", fstype: "btrfs", mountpoint: null,
          mountpoints: ["/", "/home", "/var"] },
      ] },
    ] },
  ],
});

describe("parseLsblkJson", () => {
  it("returns the blockdevices array", () => {
    expect(parseLsblkJson(LUKS_ON_LVM)?.[0]?.name).toBe("nvme0n1");
  });
  it("returns null on garbage or unexpected shape", () => {
    expect(parseLsblkJson("not json")).toBeNull();
    expect(parseLsblkJson('{"foo":1}')).toBeNull();
  });
});

describe("indexMountpoints", () => {
  it("maps a mountpoint to its ancestor chain, leaf first", () => {
    const idx = indexMountpoints(parseLsblkJson(LUKS_ON_LVM)!);
    expect(idx.get("/")?.map((n) => n.name)).toEqual([
      "ubuntu--vg-root", "dm_crypt-0", "nvme0n1p3", "nvme0n1",
    ]);
  });
});

describe("buildDiskEncryptionEvidence", () => {
  it("LUKS-on-LVM root → encrypted (crypt layer anywhere in the chain)", () => {
    const ev = buildDiskEncryptionEvidence(parseLsblkJson(LUKS_ON_LVM));
    expect(ev.available).toBe(true);
    expect(ev.targets).toHaveLength(1); // no separate /home → omitted
    expect(ev.targets![0]).toMatchObject({ mountpoint: "/", encrypted: true, cryptLayer: "dm_crypt-0" });
    expect(ev.allTargetsEncrypted).toBe(true);
    // Catalog-facing flat keys: root present, home ABSENT (not false).
    expect(ev.root).toEqual({ encrypted: true });
    expect(ev.home).toBeUndefined();
  });

  it("plaintext root + plaintext /home → both false", () => {
    const ev = buildDiskEncryptionEvidence(parseLsblkJson(PLAINTEXT_WITH_HOME));
    expect(ev.targets!.map((t) => [t.mountpoint, t.encrypted])).toEqual([["/", false], ["/home", false]]);
    expect(ev.allTargetsEncrypted).toBe(false);
  });

  it("encrypted root but plaintext /home → allTargetsEncrypted false", () => {
    const ev = buildDiskEncryptionEvidence(parseLsblkJson(MIXED));
    expect(ev.root).toEqual({ encrypted: true });
    expect(ev.home).toEqual({ encrypted: false });
    expect(ev.targets!.find((t) => t.mountpoint === "/")!.encrypted).toBe(true);
    expect(ev.targets!.find((t) => t.mountpoint === "/home")!.encrypted).toBe(false);
    expect(ev.allTargetsEncrypted).toBe(false);
  });

  it("handles util-linux plural `mountpoints` (btrfs subvolumes)", () => {
    const ev = buildDiskEncryptionEvidence(parseLsblkJson(PLURAL_MOUNTPOINTS));
    expect(ev.targets!.map((t) => t.mountpoint)).toEqual(["/", "/home"]);
    expect(ev.allTargetsEncrypted).toBe(true);
  });

  it("absent ≠ compliant: null tree → available:false and NO target facts", () => {
    const ev = buildDiskEncryptionEvidence(null, "lsblk: not found");
    expect(ev.available).toBe(false);
    expect(ev.targets).toBeUndefined();
    expect(ev.allTargetsEncrypted).toBeUndefined();
    expect(ev.raw).toBe("lsblk: not found");
  });

  it("a tree with no target mounted at all → available but no verdict", () => {
    const ev = buildDiskEncryptionEvidence([{ name: "sr0", type: "rom" }]);
    expect(ev.available).toBe(true);
    expect(ev.targets).toEqual([]);
    expect(ev.allTargetsEncrypted).toBeUndefined();
  });
});
