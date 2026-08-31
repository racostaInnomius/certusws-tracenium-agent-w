// test/update/describe-error.test.ts
//
// The regression under test is a SILENT one: every assertion here passed just
// as happily with the old `err?.message || String(err)` for ordinary errors,
// which is exactly why nobody noticed that the aggregate case reported nothing.
// The empty-message tests are the ones that matter.

import { describe, it, expect } from "vitest";
import { describeError } from "../../src/update/describe-error";

describe("describeError · the failure that motivated this", () => {
  // The literal shape Node produced on DanielA-PC in tenant 111: two candidate
  // addresses for the Azure Blob host, both refused, nine times over three days
  // reported as the single word "AggregateError".
  it("names the reasons an aggregate hides", () => {
    const err = new AggregateError([
      new Error("connect ETIMEDOUT 20.60.178.4:443"),
      new Error("connect ENETUNREACH 2620:1ec::4:443"),
    ]);

    const out = describeError(err);

    expect(out).toContain("connect ETIMEDOUT 20.60.178.4:443");
    expect(out).toContain("connect ENETUNREACH 2620:1ec::4:443");
    // The count is diagnosis, not decoration: it separates "the host is down"
    // from "we only ever had one route to it".
    expect(out).toContain("AggregateError(2)");
  });

  // Proves the OLD code was wrong, so this file fails if anyone reverts to it.
  it("beats the idiom it replaces on exactly this input", () => {
    const err = new AggregateError([new Error("connect ETIMEDOUT 20.60.178.4:443")]);
    const oldIdiom = (err as any)?.message || String(err);

    expect(oldIdiom).toBe("AggregateError");
    expect(describeError(err)).toContain("ETIMEDOUT");
  });
});

describe("describeError · ordinary errors are untouched", () => {
  // A drop-in replacement has to leave the common case byte-identical, or every
  // existing log grep and every operator's muscle memory breaks.
  it("returns the message and nothing else", () => {
    expect(describeError(new Error("update_hash_mismatch"))).toBe("update_hash_mismatch");
    expect(describeError(new Error("download_http_404"))).toBe("download_http_404");
  });

  it("trims, because a trailing newline in an ACK is noise", () => {
    expect(describeError(new Error("  boom\n"))).toBe("boom");
  });

  it("handles the values that are not errors at all", () => {
    expect(describeError("plain string")).toBe("plain string");
    expect(describeError(null)).toBe("null");
    expect(describeError(undefined)).toBe("undefined");
    expect(describeError(42)).toBe("42");
  });
});

describe("describeError · aggregate edge cases", () => {
  it("collapses duplicate reasons instead of repeating one three times", () => {
    const err = new AggregateError([
      new Error("connect ECONNREFUSED 10.130.130.5:47821"),
      new Error("connect ECONNREFUSED 10.130.130.5:47821"),
      new Error("connect ECONNREFUSED 10.130.130.5:47821"),
    ]);

    const out = describeError(err);

    expect(out.match(/ECONNREFUSED/g)).toHaveLength(1);
    // ...but the count still says three attempts happened.
    expect(out).toContain("AggregateError(3)");
  });

  it("keeps a caller's own framing in front of the causes", () => {
    const err = new AggregateError([new Error("ETIMEDOUT")], "all dp sources exhausted");
    const out = describeError(err);

    expect(out).toContain("all dp sources exhausted");
    expect(out).toContain("ETIMEDOUT");
  });

  it("says something useful when the aggregate carries no causes", () => {
    expect(describeError(new AggregateError([]))).toContain("AggregateError");
  });

  // undici and friends build aggregate-shaped errors that are not instances of
  // AggregateError; matching on the shape is what makes those readable too.
  it("reads an aggregate-shaped object that is not an AggregateError", () => {
    const err: any = new Error("");
    err.name = "SocketError";
    err.errors = [new Error("EHOSTUNREACH")];

    expect(describeError(err)).toContain("EHOSTUNREACH");
    expect(describeError(err)).toContain("SocketError(1)");
  });

  it("follows a cause when the wrapper's own message does not say it", () => {
    const err = new Error("request failed", { cause: new Error("ECONNRESET") });
    expect(describeError(err)).toContain("ECONNRESET");
  });

  it("does not repeat a cause the message already contains", () => {
    const err = new Error("request failed: ECONNRESET", { cause: new Error("ECONNRESET") });
    expect(describeError(err)).toBe("request failed: ECONNRESET");
  });
});

describe("describeError · it must never make things worse", () => {
  // ⚠️ Every caller is inside a catch block. A describeError that throws would
  // replace a bad error message with no error at all, and on the update path it
  // would take the ACK with it — the job would hang instead of failing.
  it("survives an object whose getters throw", () => {
    const hostile = {
      get message() { throw new Error("nope"); },
      get name() { throw new Error("nope"); },
      get errors() { throw new Error("nope"); },
    };
    expect(() => describeError(hostile)).not.toThrow();
  });

  it("survives a self-referencing aggregate instead of recursing forever", () => {
    const err: any = new AggregateError([]);
    err.errors = [err];
    expect(() => describeError(err)).not.toThrow();
  });

  it("bounds the output — this text travels in a gRPC ACK", () => {
    const many = Array.from({ length: 200 }, (_, i) =>
      new Error(`connect ETIMEDOUT 10.0.0.${i}:47821`)
    );
    const out = describeError(new AggregateError(many));

    expect(out.length).toBeLessThanOrEqual(300);
    // ⚠️ Truncation must ANNOUNCE itself. A clipped list that reads as complete
    // is worse than the aggregate we started with: it looks like the whole
    // story and is not.
    expect(out).toMatch(/\+\d+ more/);
  });
});
