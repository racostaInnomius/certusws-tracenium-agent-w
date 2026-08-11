// The gate and the output parsing are the parts that must not regress: every
// path that returns a coordinate is personal data leaving the endpoint. Both
// are pure, which is why they can be tested without a Windows box, a location
// permission, or a Wi-Fi radio.

import { describe, it, expect } from "vitest";
import {
  parseGeoOutput,
  supportsOsLocation,
  collectGeo,
  parseConsoleUser,
  isFixFresh,
  classifyGeoOutput,
} from "../../src/plugins/amp/providers/geo";

const at = () => new Date("2026-08-09T18:00:00.000Z");

describe("parseGeoOutput", () => {
  it("parses a well-formed reading", () => {
    expect(parseGeoOutput('{"lat":19.432608,"lon":-99.133209,"accuracyM":38}', at)).toEqual({
      lat: 19.432608,
      lon: -99.133209,
      accuracyM: 38,
      collectedAtUtc: "2026-08-09T18:00:00.000Z",
    });
  });

  it("treats the helper's own failure markers as 'no position'", () => {
    // The script prints these instead of throwing so a denied consent store
    // does not look the same as a crashed interpreter.
    expect(parseGeoOutput("TIMEOUT", at)).toBeNull();
    expect(parseGeoOutput("ERROR:Access is denied", at)).toBeNull();
  });

  it("returns null for anything that is not JSON", () => {
    expect(parseGeoOutput("", at)).toBeNull();
    expect(parseGeoOutput("   ", at)).toBeNull();
    expect(parseGeoOutput("not json", at)).toBeNull();
    expect(parseGeoOutput(undefined, at)).toBeNull();
    expect(parseGeoOutput(null, at)).toBeNull();
    expect(parseGeoOutput("[1,2,3]", at)).toBeNull();
  });

  it("rejects Null Island — a zeroed struct, not a place", () => {
    expect(parseGeoOutput('{"lat":0,"lon":0,"accuracyM":10}', at)).toBeNull();
  });

  it("keeps a legitimate zero on one axis", () => {
    // The equator and the Greenwich meridian are real places.
    expect(parseGeoOutput('{"lat":0,"lon":32.5}', at)?.lat).toBe(0);
    expect(parseGeoOutput('{"lat":51.48,"lon":0}', at)?.lon).toBe(0);
  });

  it("rejects out-of-range coordinates", () => {
    expect(parseGeoOutput('{"lat":91,"lon":0}', at)).toBeNull();
    expect(parseGeoOutput('{"lat":0,"lon":181}', at)).toBeNull();
    expect(parseGeoOutput('{"lat":"north","lon":"west"}', at)).toBeNull();
  });

  it("reports an unusable accuracy as unknown, not as perfect", () => {
    // A negative or missing accuracy must not render as "±0 m", which would
    // read as a pinpoint fix.
    expect(parseGeoOutput('{"lat":19.4,"lon":-99.1,"accuracyM":-1}', at)?.accuracyM).toBeNull();
    expect(parseGeoOutput('{"lat":19.4,"lon":-99.1}', at)?.accuracyM).toBeNull();
  });

  it("keeps a zero accuracy distinct from an absent one", () => {
    expect(parseGeoOutput('{"lat":19.4,"lon":-99.1,"accuracyM":0}', at)?.accuracyM).toBe(0);
  });
});

describe("supportsOsLocation", () => {
  it("covers the platforms with a real system location service", () => {
    expect(supportsOsLocation("win32")).toBe(true);
    expect(supportsOsLocation("darwin")).toBe(true);
  });

  it("excludes Linux, which has no equivalent", () => {
    // Those devices keep falling back to the operator's CIDR→site mapping,
    // which is exact anyway.
    expect(supportsOsLocation("linux")).toBe(false);
    expect(supportsOsLocation("freebsd")).toBe(false);
  });
});

describe("collectGeo — the gate", () => {
  it("collects nothing when the tenant has not enabled it, and says so", async () => {
    expect(await collectGeo(false, "win32")).toEqual({ geo: null, status: "disabled" });
  });

  it("fails closed on anything that is not exactly true", async () => {
    // A policy that failed to load, or one carrying a truthy string, must not
    // start reading positions.
    for (const value of [undefined, null, "true", 1]) {
      const result = await collectGeo(value as any, "win32");
      expect(result.geo).toBeNull();
      expect(result.status).toBe("disabled");
    }
  });

  it("distinguishes an unsupported platform from a disabled tenant", async () => {
    // Both produce no coordinate; only one of them is worth acting on.
    expect(await collectGeo(true, "linux")).toEqual({ geo: null, status: "unsupported" });
  });
});

describe("classifyGeoOutput — why there is no position", () => {
  it("reports a usable reading as ok", () => {
    expect(classifyGeoOutput('{"lat":19.4,"lon":-99.1}')).toBe("ok");
  });

  it("separates a refusal from a miss", () => {
    // "denied" is a configuration problem an admin can fix; "unavailable" is
    // weather. Collapsing them would send an MSP chasing the wrong one.
    expect(classifyGeoOutput("ERROR:Access is denied")).toBe("denied");
    expect(classifyGeoOutput("TIMEOUT")).toBe("unavailable");
  });

  it("treats nothing-at-all as unavailable", () => {
    // On macOS this is the status app not running, no console user, or a fix
    // that aged out of the freshness window.
    expect(classifyGeoOutput("")).toBe("unavailable");
    expect(classifyGeoOutput("   ")).toBe("unavailable");
    expect(classifyGeoOutput(null)).toBe("unavailable");
  });

  it("treats a malformed or rejected reading as unavailable, not ok", () => {
    expect(classifyGeoOutput("not json")).toBe("unavailable");
    expect(classifyGeoOutput('{"lat":0,"lon":0}')).toBe("unavailable");
    expect(classifyGeoOutput('{"lat":91,"lon":0}')).toBe("unavailable");
  });
});

describe("parseConsoleUser (macOS)", () => {
  it("accepts the logged-in console user", () => {
    expect(parseConsoleUser("javierpacheco\n")).toBe("javierpacheco");
    expect(parseConsoleUser("  first.last  ")).toBe("first.last");
  });

  it("rejects the states where nobody is really logged in", () => {
    // At the login window the console is owned by root or loginwindow, and
    // there is no user session that could have collected a position.
    expect(parseConsoleUser("root")).toBeNull();
    expect(parseConsoleUser("loginwindow")).toBeNull();
    expect(parseConsoleUser("")).toBeNull();
    expect(parseConsoleUser("   ")).toBeNull();
    expect(parseConsoleUser(null)).toBeNull();
  });

  it("rejects a name that could escape the path it is interpolated into", () => {
    expect(parseConsoleUser("../../etc")).toBeNull();
    expect(parseConsoleUser("bad name")).toBeNull();
    expect(parseConsoleUser("a/b")).toBeNull();
    expect(parseConsoleUser("$(whoami)")).toBeNull();
  });
});

describe("isFixFresh (macOS staleness window)", () => {
  const now = Date.parse("2026-08-09T18:00:00.000Z");

  it("accepts a fix from the last refresh cycle", () => {
    expect(isFixFresh("2026-08-09T17:50:00.000Z", now)).toBe(true);
  });

  it("tolerates one missed cycle — asleep, no Wi-Fi, a failed request", () => {
    expect(isFixFresh("2026-08-09T17:10:00.000Z", now)).toBe(true);
  });

  it("expires a fix older than the window", () => {
    // The guard that stops a killed status app from pinning a laptop to an
    // office it left days ago.
    expect(isFixFresh("2026-08-09T16:30:00.000Z", now)).toBe(false);
    expect(isFixFresh("2026-08-01T18:00:00.000Z", now)).toBe(false);
  });

  it("rejects a timestamp from the future — clock skew or a forged file", () => {
    expect(isFixFresh("2026-08-09T19:00:00.000Z", now)).toBe(false);
  });

  it("tolerates a little skew rather than discarding a good fix", () => {
    expect(isFixFresh("2026-08-09T18:00:30.000Z", now)).toBe(true);
  });

  it("rejects anything that is not a parseable timestamp", () => {
    expect(isFixFresh(undefined, now)).toBe(false);
    expect(isFixFresh("", now)).toBe(false);
    expect(isFixFresh("yesterday", now)).toBe(false);
    expect(isFixFresh(12345, now)).toBe(false);
  });
});

describe("parseGeoOutput — the fix's own timestamp", () => {
  it("keeps the timestamp the source stamped on the reading", () => {
    // On macOS the status app takes the reading minutes before the daemon
    // reads the file; restamping it as "now" would report a stale position as
    // current.
    const geo = parseGeoOutput(
      '{"lat":19.4,"lon":-99.1,"collectedAtUtc":"2026-08-09T17:45:00.000Z"}',
      at
    );
    expect(geo?.collectedAtUtc).toBe("2026-08-09T17:45:00.000Z");
  });

  it("falls back to now when the source did not stamp one (Windows)", () => {
    expect(parseGeoOutput('{"lat":19.4,"lon":-99.1}', at)?.collectedAtUtc).toBe(
      "2026-08-09T18:00:00.000Z"
    );
  });

  it("falls back to now on an unparseable stamp", () => {
    expect(
      parseGeoOutput('{"lat":19.4,"lon":-99.1,"collectedAtUtc":"nope"}', at)?.collectedAtUtc
    ).toBe("2026-08-09T18:00:00.000Z");
  });
});
