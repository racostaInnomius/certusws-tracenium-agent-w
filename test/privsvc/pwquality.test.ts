// test/privsvc/pwquality.test.ts
//
// Unit coverage for the PAM pwquality parser: only EXPLICITLY-SET (uncommented)
// knobs are surfaced, numeric coercion, inline-comment stripping, and the
// omit-for-not_applicable shaping.

import { describe, it, expect } from "vitest";
import { parsePwquality, shapePwqualityEvidence } from "../../privsvc/linux/src/pwquality";

describe("parsePwquality", () => {
  it("reads only uncommented knobs and coerces integers", () => {
    const conf = [
      "# Configuration for systemwide password quality",
      "# minlen = 8",
      "minlen = 14",
      "dictcheck = 1",
      "maxrepeat = 3   # no more than 3 repeats",
      "# ucredit = 0",
    ].join("\n");
    expect(parsePwquality(conf)).toEqual({ minlen: 14, dictcheck: 1, maxrepeat: 3 });
  });

  it("ignores keys we don't evaluate and returns {} for all-commented files", () => {
    expect(parsePwquality("# minlen = 8\n# dcredit = -1\nbadwords = foo bar")).toEqual({});
  });

  it("keeps negative credit values", () => {
    expect(parsePwquality("dcredit = -1\nocredit = -1")).toEqual({ dcredit: -1, ocredit: -1 });
  });
});

describe("shapePwqualityEvidence", () => {
  it("is not applicable when no config file was found", () => {
    expect(shapePwqualityEvidence(false, {})).toEqual({ applicable: false });
  });

  it("spreads the explicitly-set knobs when configured", () => {
    expect(shapePwqualityEvidence(true, { minlen: 14, dictcheck: 1 })).toEqual({
      applicable: true,
      minlen: 14,
      dictcheck: 1,
    });
  });
});
