// test/core/namespace-hash.test.ts
//
// Regression coverage for the scheduler's SCP change-detection gate.
//
// Bug (found 2026-08-13): privsvc stamps patches.lastScanUtc on EVERY
// collection (Windows and macOS), and the field survived into the hash
// projection — so two posture-identical collections always hashed
// differently, hasChanges was always true, and a full SCP snapshot
// (including the complete Windows Update history) shipped every tick.
// Linux never forwarded the field, which masked the bug on that
// platform. buildScpStateForHash now strips it.

import { describe, it, expect } from "vitest";
import {
  hashNamespace,
  buildScpStateForHash,
  buildPmpStateForHash,
  stableStringify
} from "../../src/core/namespace-hash";
import type { ScpNamespace } from "../../src/domain/scp-types";

function scpFixture(overrides: Record<string, unknown> = {}): ScpNamespace {
  return {
    schemaVersion: "2.0",
    collector: { version: "1.4.0" },
    firewall: { enabled: true },
    patches: {
      lastScanUtc: "2026-08-13T10:00:00Z",
      items: [{ id: "KB500", title: "Update" }],
      count: 1
    },
    ...overrides
  } as unknown as ScpNamespace;
}

describe("buildScpStateForHash — volatile-field stripping", () => {
  it("hashes two posture-identical collections identically despite different lastScanUtc", () => {
    const first = scpFixture({
      patches: { lastScanUtc: "2026-08-13T10:00:00Z", items: [], count: 0 }
    });
    const second = scpFixture({
      patches: { lastScanUtc: "2026-08-13T18:00:00Z", items: [], count: 0 }
    });
    expect(hashNamespace(buildScpStateForHash(first)))
      .toBe(hashNamespace(buildScpStateForHash(second)));
  });

  it("still detects a real posture change", () => {
    const before = scpFixture({ firewall: { enabled: true } });
    const after = scpFixture({ firewall: { enabled: false } });
    expect(hashNamespace(buildScpStateForHash(before)))
      .not.toBe(hashNamespace(buildScpStateForHash(after)));
  });

  it("still detects a patches change beyond the timestamp", () => {
    const before = scpFixture({
      patches: { lastScanUtc: "2026-08-13T10:00:00Z", items: [], count: 0 }
    });
    const after = scpFixture({
      patches: { lastScanUtc: "2026-08-13T10:00:00Z", items: [{ id: "KB1" }], count: 1 }
    });
    expect(hashNamespace(buildScpStateForHash(before)))
      .not.toBe(hashNamespace(buildScpStateForHash(after)));
  });

  it("strips the internal hasChanges flag", () => {
    const withFlag = { ...scpFixture(), hasChanges: true } as ScpNamespace;
    const withoutFlag = scpFixture();
    expect(hashNamespace(buildScpStateForHash(withFlag)))
      .toBe(hashNamespace(buildScpStateForHash(withoutFlag)));
  });

  it("tolerates a namespace without a patches block (Linux collector error path)", () => {
    const ns = scpFixture({ patches: undefined });
    expect(() => buildScpStateForHash(ns)).not.toThrow();
  });
});

describe("buildPmpStateForHash", () => {
  it("strips only hasChanges", () => {
    const ns = { hasChanges: true, updates: [{ id: "u1" }] } as any;
    expect(buildPmpStateForHash(ns)).toEqual({ updates: [{ id: "u1" }] });
  });
});

describe("stableStringify", () => {
  it("is key-order independent", () => {
    expect(stableStringify({ b: 1, a: { d: 2, c: 3 } }))
      .toBe(stableStringify({ a: { c: 3, d: 2 }, b: 1 }));
  });
});
