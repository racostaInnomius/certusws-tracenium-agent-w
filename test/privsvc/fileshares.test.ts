// test/privsvc/fileshares.test.ts
//
// Unit coverage for the Linux smb (Samba) + shares (NFS exports) evidence
// parsers/shapers. The key behaviors: SMB1 derivation from `server min
// protocol`, NFS export risk counting, and omit-for-not_applicable shaping.

import { describe, it, expect } from "vitest";
import {
  parseTestparmMinProtocol,
  deriveSmb1Enabled,
  parseExports,
  shapeSmbEvidence,
  shapeSharesEvidence,
} from "../../privsvc/linux/src/fileshares";

describe("parseTestparmMinProtocol", () => {
  it("extracts the server min protocol when set", () => {
    const out = ["[global]", "\tserver min protocol = SMB2", "\tworkgroup = WG"].join("\n");
    expect(parseTestparmMinProtocol(out)).toBe("SMB2");
  });

  it("returns undefined when the parameter is at its (unprinted) default", () => {
    expect(parseTestparmMinProtocol("[global]\n\tworkgroup = WG")).toBeUndefined();
  });
});

describe("deriveSmb1Enabled", () => {
  it("is false for the modern default (undefined) and SMB2/SMB3", () => {
    expect(deriveSmb1Enabled(undefined)).toBe(false);
    expect(deriveSmb1Enabled("SMB2")).toBe(false);
    expect(deriveSmb1Enabled("SMB3_11")).toBe(false);
  });

  it("is true when NT1/SMB1 or an older dialect is the floor", () => {
    expect(deriveSmb1Enabled("NT1")).toBe(true);
    expect(deriveSmb1Enabled("nt1")).toBe(true);
    expect(deriveSmb1Enabled("LANMAN2")).toBe(true);
  });
});

describe("parseExports", () => {
  it("counts exports, world-reachable exports, and no_root_squash grants", () => {
    const text = [
      "# NFS exports",
      "/srv/nfs   192.168.1.0/24(rw,sync,no_subtree_check)",
      "/export    *(ro,sync)",
      "/data      host1(rw,no_root_squash) host2(ro)",
      "/legacy", // old-style, no client → world
    ].join("\n");
    expect(parseExports(text)).toEqual({ exportCount: 4, worldExportCount: 2, noRootSquashCount: 1 });
  });

  it("returns zeros for empty / comment-only content", () => {
    expect(parseExports("# just a comment\n\n")).toEqual({
      exportCount: 0,
      worldExportCount: 0,
      noRootSquashCount: 0,
    });
  });
});

describe("shapeSmbEvidence", () => {
  it("omits smb1 detail when Samba is not installed (→ not_applicable)", () => {
    expect(shapeSmbEvidence(false)).toEqual({ applicable: false, installed: false });
  });

  it("nests smb1.enabled to match the shared cross-platform path", () => {
    expect(shapeSmbEvidence(true, false)).toEqual({
      applicable: true,
      installed: true,
      smb1: { enabled: false },
    });
  });
});

describe("shapeSharesEvidence", () => {
  it("is not applicable (counts omitted) when there are no exports", () => {
    expect(shapeSharesEvidence({ exportCount: 0, worldExportCount: 0, noRootSquashCount: 0 })).toEqual({
      applicable: false,
      nfsExportCount: 0,
    });
    expect(shapeSharesEvidence(null)).toEqual({ applicable: false, nfsExportCount: 0 });
  });

  it("exposes the risk counts when exports exist", () => {
    expect(shapeSharesEvidence({ exportCount: 3, worldExportCount: 1, noRootSquashCount: 2 })).toEqual({
      applicable: true,
      nfsExportCount: 3,
      worldExportCount: 1,
      noRootSquashCount: 2,
    });
  });
});
