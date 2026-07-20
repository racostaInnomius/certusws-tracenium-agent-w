// test/plugins/sdp-dp.test.ts
//
// Distribution Phase B — the DP prefetch job handler (scripted privsvc) and
// the pure blob-server helpers (path parsing, range handling, LRU eviction).

import fs from "fs";
import os from "os";
import path from "path";
import { describe, expect, it, vi } from "vitest";
import { runDpPrefetch } from "../../src/plugins/sdp/dp";
import { blobShaFromPath, parseRange, evictLru } from "../../privsvc/macos/src/dp";

function makeCtx(resp: any) {
  return {
    priv: { call: vi.fn(async (_req: any) => resp) },
    enrollment: { tenantId: "t-1", deviceId: "dp-1" },
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  } as any;
}

const SHA = "a".repeat(64);
const SOURCES = [{ tier: "cdn", url: "https://cdn.example.net/x" }];

describe("runDpPrefetch", () => {
  it("acks success when the cache is warm and the server is up", async () => {
    const ctx = makeCtx({ ok: true, result: { ready: true, cached: false, servedFrom: "cdn" } });
    const ack = await runDpPrefetch(ctx, "j1", { deploymentId: 7, sha256: SHA, sources: SOURCES });
    expect(ack.ackStatus).toBe(0);
    expect(ack.ackMessage).toContain("software_dp_prefetch:success");
    expect(ack.ackMessage).toContain("deploymentId=7");
    const call = ctx.priv.call.mock.calls[0][0];
    expect(call.method).toBe("sdp.dp.prefetch");
    expect(call.params.sha256).toBe(SHA);
  });

  it("rejects an invalid payload without touching privsvc", async () => {
    const ctx = makeCtx({ ok: true, result: { ready: true } });
    const bad = await runDpPrefetch(ctx, "j2", { deploymentId: 7, sha256: "nope", sources: SOURCES });
    expect(bad.ackStatus).toBe(2);
    expect(ctx.priv.call).not.toHaveBeenCalled();
  });

  it("maps a transient download failure to a retryable ack", async () => {
    const ctx = makeCtx({ ok: false, error: { code: "download_failed" } });
    const ack = await runDpPrefetch(ctx, "j3", { deploymentId: 7, sha256: SHA, sources: SOURCES });
    expect(ack.ackStatus).toBe(1);
    expect(ack.ackMessage).toContain("reason=download_failed");
  });

  it("maps a cache-warm-but-server-down result to a permanent failure", async () => {
    const ctx = makeCtx({ ok: true, result: { ready: false, serverReason: "identity_unavailable:ENOENT" } });
    const ack = await runDpPrefetch(ctx, "j4", { deploymentId: 7, sha256: SHA, sources: SOURCES });
    expect(ack.ackStatus).toBe(2);
    expect(ack.ackMessage).toContain("identity_unavailable");
  });
});

describe("blobShaFromPath", () => {
  it("accepts exactly /sdp/blob/<64-hex> and nothing else", () => {
    expect(blobShaFromPath(`/sdp/blob/${SHA}`)).toBe(SHA);
    expect(blobShaFromPath(`/sdp/blob/${SHA.toUpperCase()}`)).toBe(SHA);
    expect(blobShaFromPath(`/sdp/blob/${SHA}?x=1`)).toBe(SHA);
    expect(blobShaFromPath("/sdp/blob/short")).toBeNull();
    expect(blobShaFromPath(`/sdp/blob/../../etc/passwd`)).toBeNull();
    expect(blobShaFromPath(`/other/${SHA}`)).toBeNull();
  });
});

describe("parseRange", () => {
  it("parses open, closed and suffix ranges bounded by size", () => {
    expect(parseRange("bytes=0-99", 1000)).toEqual({ start: 0, end: 99 });
    expect(parseRange("bytes=500-", 1000)).toEqual({ start: 500, end: 999 });
    expect(parseRange("bytes=-100", 1000)).toEqual({ start: 900, end: 999 });
    expect(parseRange("bytes=0-5000", 1000)).toEqual({ start: 0, end: 999 });
  });
  it("rejects malformed / out-of-bounds ranges", () => {
    expect(parseRange(undefined, 1000)).toBeNull();
    expect(parseRange("bytes=1000-", 1000)).toBeNull();
    expect(parseRange("bytes=9-5", 1000)).toBeNull();
    expect(parseRange("chunks=0-5", 1000)).toBeNull();
  });
});

describe("evictLru", () => {
  it("removes oldest files until the cap fits, newest survive", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dp-cache-"));
    try {
      const mk = (name: string, size: number, ageSec: number) => {
        const full = path.join(dir, name);
        fs.writeFileSync(full, Buffer.alloc(size));
        const t = new Date(Date.now() - ageSec * 1000);
        fs.utimesSync(full, t, t);
      };
      mk("old", 500, 300);
      mk("mid", 500, 200);
      mk("new", 500, 10);
      const evicted = evictLru(dir, 1100); // fits 2 of 3
      expect(evicted).toBe(1);
      expect(fs.existsSync(path.join(dir, "old"))).toBe(false);
      expect(fs.existsSync(path.join(dir, "new"))).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
