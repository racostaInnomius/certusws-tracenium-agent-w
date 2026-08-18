// test/domain/os-release.test.ts
//
// Both Linux servers in the fleet reported distro="unknown", release="unknown"
// while their kernel came through correctly — systeminformation obtains the
// first two by shelling out and the third from Node. Reading os-release
// ourselves removes the subprocess from the path entirely.

import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseOsRelease, readOsRelease, isUnknown } from "../../src/domain/os-release";

/** Verbatim /etc/os-release from Ubuntu 24.04 — the shape we must handle. */
const UBUNTU_2404 = `PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
`;

function withTempFile(content: string, fn: (p: string) => void) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "osrel-"));
  const file = path.join(dir, "os-release");
  fs.writeFileSync(file, content, "utf8");
  try {
    fn(file);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe("parseOsRelease", () => {
  it("parses a real Ubuntu file", () => {
    const f = parseOsRelease(UBUNTU_2404);
    expect(f.NAME).toBe("Ubuntu");
    expect(f.VERSION_ID).toBe("24.04");
    expect(f.ID).toBe("ubuntu");
  });

  it("strips only a matched pair of quotes", () => {
    // A value containing a quote must survive: mangling it would produce a
    // subtly wrong distro name rather than an obviously missing one.
    const f = parseOsRelease(['A="quoted"', "B=bare", `C='single'`, 'D="un-matched'].join("\n"));
    expect(f.A).toBe("quoted");
    expect(f.B).toBe("bare");
    expect(f.C).toBe("single");
    expect(f.D).toBe('"un-matched');
  });

  it("keeps '=' inside values", () => {
    // HOME_URL and friends routinely carry query strings.
    expect(parseOsRelease('X="a=b=c"').X).toBe("a=b=c");
  });

  it("ignores comments, blanks and malformed lines", () => {
    const f = parseOsRelease(["# a comment", "", "   ", "NOEQUALS", "=novalue", "NAME=Debian"].join("\n"));
    expect(f).toEqual({ NAME: "Debian" });
  });

  it("drops keys with empty values rather than reporting them as present", () => {
    // An empty NAME must fall through to ID, not win as a blank answer.
    expect(parseOsRelease('NAME=""\nID=alpine')).toEqual({ ID: "alpine" });
  });
});

describe("readOsRelease", () => {
  it("returns the distro and version from a real file", () => {
    withTempFile(UBUNTU_2404, (p) => {
      expect(readOsRelease([p])).toEqual({ distro: "Ubuntu", release: "24.04" });
    });
  });

  it("falls back to ID and VERSION when NAME/VERSION_ID are absent", () => {
    withTempFile('ID=arch\nVERSION="rolling"', (p) => {
      expect(readOsRelease([p])).toEqual({ distro: "arch", release: "rolling" });
    });
  });

  it("tries the vendor copy when /etc is missing", () => {
    // Minimal and read-only-root images ship only /usr/lib/os-release.
    withTempFile(UBUNTU_2404, (p) => {
      expect(readOsRelease(["/nonexistent/etc/os-release", p]).distro).toBe("Ubuntu");
    });
  });

  it("skips a file that parses but says nothing", () => {
    withTempFile("# nothing useful here\n", (p) => {
      withTempFile(UBUNTU_2404, (q) => {
        expect(readOsRelease([p, q]).distro).toBe("Ubuntu");
      });
    });
  });

  it("returns empty instead of throwing when nothing is readable", () => {
    // This runs inside inventory collection: one unreadable file must not
    // cost the entire snapshot.
    expect(readOsRelease(["/nonexistent/a", "/nonexistent/b"])).toEqual({});
  });
});

describe("isUnknown", () => {
  it("recognises what collectors send for 'I could not tell'", () => {
    // The literal string that started this: truthy, so it survives `??`.
    for (const v of ["unknown", "UNKNOWN", " unknown ", "", "   ", "-"]) {
      expect(isUnknown(v), `${JSON.stringify(v)} should count as unknown`).toBe(true);
    }
    for (const v of [undefined, null, 42]) {
      expect(isUnknown(v)).toBe(true);
    }
  });

  it("treats real values as known", () => {
    for (const v of ["Ubuntu", "24.04", "6.8.0-101-generic"]) {
      expect(isUnknown(v)).toBe(false);
    }
  });
});
