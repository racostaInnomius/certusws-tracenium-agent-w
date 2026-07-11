// test/privsvc/updates-parse.test.ts
//
// Unit coverage for the Linux patch-compliance (`updates`) parsers. These are
// the risky part of the collector — the exec wiring is thin, the per-tool output
// parsing is where distro-version drift bites — so we pin them against
// representative real command output. First SCP collector tests in the repo.

import { describe, it, expect } from "vitest";
import {
  parseAptCheck,
  parseAptSimulate,
  parseDnfCheckUpdate,
  parseDnfSecurityCount,
  parseZypperTableCount,
  parseNeedsRestarting,
  shapeUpdatesEvidence,
} from "../../privsvc/linux/src/updates-parse";

describe("parseAptCheck", () => {
  it("parses the 'total;security' pair apt-check prints on stderr", () => {
    expect(parseAptCheck("23;5\n")).toEqual({ total: 23, security: 5 });
    expect(parseAptCheck("0;0")).toEqual({ total: 0, security: 0 });
  });

  it("returns null when the output isn't the N;M shape", () => {
    expect(parseAptCheck("")).toBeNull();
    expect(parseAptCheck("E: could not open cache")).toBeNull();
  });
});

describe("parseAptSimulate", () => {
  it("counts Inst lines as total and *-security suites as security", () => {
    const out = [
      "Reading package lists...",
      "Calculating upgrade...",
      "The following packages will be upgraded:",
      "  base-files libssl3 tzdata",
      "3 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.",
      "Inst base-files [12.4ubuntu1] (12.4ubuntu2 Ubuntu:24.04/noble-updates [amd64])",
      "Inst libssl3 [3.0.13-0ubuntu3] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-security [amd64])",
      "Inst tzdata [2024a-2ubuntu1] (2024a-3ubuntu1 Ubuntu:24.04/noble-security [all])",
      "Conf base-files (12.4ubuntu2 Ubuntu:24.04/noble-updates [amd64])",
    ].join("\n");
    expect(parseAptSimulate(out)).toEqual({ total: 3, security: 2 });
  });

  it("returns zeros for an up-to-date system", () => {
    expect(parseAptSimulate("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.")).toEqual({
      total: 0,
      security: 0,
    });
  });
});

describe("parseDnfCheckUpdate", () => {
  it("returns 0 on a clean exit (code 0)", () => {
    expect(parseDnfCheckUpdate("", 0)).toBe(0);
  });

  it("counts package rows on code 100 and stops at the Obsoleting trailer", () => {
    const out = [
      "Last metadata expiration check: 0:12:05 ago on Wed 10 Jul 2026.",
      "",
      "NetworkManager.x86_64            1:1.46.0-4.el9_4      baseos",
      "openssl-libs.x86_64             1:3.2.2-6.el9_4       baseos",
      "sudo.x86_64                     1.9.5p2-10.el9_4      baseos",
      "",
      "Obsoleting Packages",
      "grub2-common.noarch            1:2.06-70.el9_4        appstream",
    ].join("\n");
    expect(parseDnfCheckUpdate(out, 100)).toBe(3);
  });

  it("returns null on an error/other exit code", () => {
    expect(parseDnfCheckUpdate("some error", 1)).toBeNull();
    expect(parseDnfCheckUpdate("", null)).toBeNull();
  });
});

describe("parseDnfSecurityCount", () => {
  it("counts advisory rows carrying the /Sec. severity marker", () => {
    const out = [
      "Last metadata expiration check: 0:12:05 ago on Wed 10 Jul 2026.",
      "RHSA-2024:1234 Important/Sec.  openssl-libs-1:3.2.2-6.el9_4.x86_64",
      "RHSA-2024:5678 Moderate/Sec.   NetworkManager-1:1.46.0-4.el9_4.x86_64",
    ].join("\n");
    expect(parseDnfSecurityCount(out)).toBe(2);
  });

  it("returns 0 when there are no security advisories", () => {
    expect(parseDnfSecurityCount("Last metadata expiration check: 0:01:00 ago.\n")).toBe(0);
  });
});

describe("parseZypperTableCount", () => {
  it("counts data rows and skips the header + separator", () => {
    const out = [
      "S | Repository          | Name        | Current Version | Available Version | Arch",
      "--+---------------------+-------------+-----------------+-------------------+-------",
      "v | Update Repository   | glibc       | 2.31-1          | 2.31-2            | x86_64",
      "v | Update Repository   | openssl     | 1.1.1-1         | 1.1.1-2           | x86_64",
    ].join("\n");
    expect(parseZypperTableCount(out)).toBe(2);
  });

  it("returns 0 for output with no data rows", () => {
    expect(parseZypperTableCount("No updates found.")).toBe(0);
  });
});

describe("parseNeedsRestarting", () => {
  it("maps exit codes: 0 → no reboot, 1 → reboot, other → unknown", () => {
    expect(parseNeedsRestarting(0)).toBe(false);
    expect(parseNeedsRestarting(1)).toBe(true);
    expect(parseNeedsRestarting(null)).toBeNull();
    expect(parseNeedsRestarting(127)).toBeNull();
  });
});

describe("shapeUpdatesEvidence", () => {
  it("keeps every field when all are concrete values", () => {
    expect(
      shapeUpdatesEvidence({
        applicable: true,
        manager: "apt",
        source: "apt-check",
        updatesAvailable: 12,
        securityUpdatesAvailable: 3,
        rebootRequired: true,
        raw: "12;3",
      })
    ).toEqual({
      applicable: true,
      manager: "apt",
      source: "apt-check",
      updatesAvailable: 12,
      securityUpdatesAvailable: 3,
      rebootRequired: true,
      raw: "12;3",
    });
  });

  it("OMITS null/undefined evaluated fields so the backend marks them not_applicable", () => {
    // securityUpdatesAvailable + rebootRequired unknown → must be absent, NOT null.
    const out = shapeUpdatesEvidence({
      applicable: true,
      manager: "zypper",
      updatesAvailable: 5,
      securityUpdatesAvailable: null,
      rebootRequired: null,
    });
    expect(out).toEqual({ applicable: true, manager: "zypper", updatesAvailable: 5 });
    expect(out).not.toHaveProperty("securityUpdatesAvailable");
    expect(out).not.toHaveProperty("rebootRequired");
  });

  it("emits only applicable+manager when the whole block is not applicable", () => {
    expect(shapeUpdatesEvidence({ applicable: false, manager: null })).toEqual({
      applicable: false,
      manager: null,
    });
  });

  it("keeps rebootRequired:false (a real value) but drops empty raw", () => {
    const out = shapeUpdatesEvidence({
      applicable: true,
      manager: "dnf",
      rebootRequired: false,
      raw: "",
    });
    expect(out.rebootRequired).toBe(false);
    expect(out).not.toHaveProperty("raw");
  });
});
