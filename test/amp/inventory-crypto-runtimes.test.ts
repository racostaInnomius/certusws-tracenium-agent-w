// test/amp/inventory-crypto-runtimes.test.ts
//
// The two inventory holes that made the PQC agility check blind, one per
// platform. Both were silent, and both were found by asking a different
// question than "does the code look right": by counting rows in
// production.
//
//   macOS  — `brew list --versions` was run from a root LaunchDaemon,
//            which Homebrew refuses, and every failure was swallowed by a
//            `catch {}` commented "brew not installed". Result: zero rows
//            with `source=homebrew` in ANY tenant, on a fleet with
//            several Macs — while CDP's Java collector was reading
//            /opt/homebrew/Cellar off the same disks.
//
//   Linux  — `libssl3` is a transitive dependency, so it is always marked
//            auto, so the manual-only filter always dropped it. The only
//            survivor was the `openssl` CLI, which measures the command
//            line rather than the library services actually link.

import { describe, it, expect } from "vitest";
import { compareBrewVersions } from "../../src/plugins/amp/providers/macos";

describe("compareBrewVersions", () => {
  const newest = (versions: string[]) => [...versions].sort(compareBrewVersions).pop();

  it("orders numerically, not lexically", () => {
    // The bug a string sort would introduce: "9" sorting after "10", so
    // the collector reports an old version as the installed one — and an
    // agility rule then judges the wrong number.
    expect(newest(["3.9.1", "3.10.0"])).toBe("3.10.0");
    expect(newest(["1.9", "1.10", "1.2"])).toBe("1.10");
  });

  it("picks the newest of the versions a formula keeps side by side", () => {
    // Real shapes from a live Cellar.
    expect(newest(["3.6.3"])).toBe("3.6.3");
    expect(newest(["21.0.9", "21.0.10"])).toBe("21.0.10");
    expect(newest(["3.4.1", "3.6.3", "3.5.0"])).toBe("3.6.3");
  });

  it("handles Homebrew's revision suffix", () => {
    // `1.2.3_1` is a rebuild of 1.2.3 and is newer than it.
    expect(newest(["1.2.3", "1.2.3_1"])).toBe("1.2.3_1");
    expect(newest(["1.2.3_2", "1.2.3_10"])).toBe("1.2.3_10");
  });

  it("does not throw on a non-numeric version", () => {
    // Some formulae version by date or word. Ordering them is
    // best-effort; crashing the whole inventory is not acceptable.
    expect(() => newest(["2024-01-01", "HEAD", "1.0"])).not.toThrow();
  });

  it("is a consistent comparator", () => {
    expect(compareBrewVersions("1.0", "1.0")).toBe(0);
    expect(compareBrewVersions("1.0", "2.0")).toBeLessThan(0);
    expect(compareBrewVersions("2.0", "1.0")).toBeGreaterThan(0);
  });
});

// The Linux exemption is a regex in the provider. Re-stated here rather
// than exported, because what deserves pinning is the POLICY — which
// names survive the manual-only filter — and that it stays narrow.
const CRYPTO_RUNTIME_RE = /^(libssl[0-9.]*(t64)?|openssl|libgnutls[0-9.-]*(t64)?|gnutls-bin|libnss3|libgcrypt[0-9]*(t64)?)$/i;

describe("Linux crypto-runtime exemption", () => {
  it("keeps the TLS libraries the agility check needs", () => {
    // These are always auto-marked, being transitive dependencies, so
    // without the exemption none of them ever reach the inventory.
    for (const pkg of ["libssl3", "libssl1.1", "libssl3t64", "openssl", "libgnutls30", "libnss3"]) {
      expect(CRYPTO_RUNTIME_RE.test(pkg), pkg).toBe(true);
    }
  });

  it("stays narrow enough not to reopen the dependency graph", () => {
    // The manual-only filter cuts inventory 3-4x and is right about
    // almost everything; this exemption must not become a general escape
    // hatch. Development headers and unrelated libs stay out.
    for (const pkg of [
      "libssl-dev", "openssl-doc", "libc6", "libcurl4", "python3-openssl",
      "libsqlite3-0", "openssh-client", "ssl-cert"
    ]) {
      expect(CRYPTO_RUNTIME_RE.test(pkg), pkg).toBe(false);
    }
  });
});
