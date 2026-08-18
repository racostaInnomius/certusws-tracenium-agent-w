// test/update/update-via-dp.test.ts
//
// The agent update used to download with `downloadToFile` — a plain HTTP GET
// against one URL from this process. It could not present the enrollment
// client certificate a distribution point requires, had no ordered fallback,
// and knew nothing about the download budget. So every endpoint pulled its own
// copy of a 141MB MSI from Azure, even with a DP sitting on the same switch
// holding the exact same bytes.
//
// Routing it through privsvc's `sdp.download` inherits the tiering that was
// proven in the field: ordered sources, the sha256 gate, per-source budget
// slicing and a 5s connect timeout so an unreachable DP costs seconds.
//
// What these tests protect is the FALLBACK behaviour, because that is what
// decides whether a bad DP breaks updates or merely fails to speed them up.

import { describe, expect, it, vi } from "vitest";
import {
  downloadUpdateViaSources,
  SELF_UPDATE_PACKAGE_ID,
} from "../../src/update/update-service";
import { DOWNLOAD_BUDGET_SECONDS } from "../../src/plugins/sdp";

const SOURCES = [
  { tier: "dp", url: "https://10.1.2.3:47821/sdp/blob/abc" },
  { tier: "origin", url: "https://blob.core.windows.net/agent.msi?sig=x" },
];

function ctxWith(call: any) {
  return {
    priv: { call },
    enrollment: { tenantId: "111", deviceId: "dev-1" },
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  } as any;
}

const OPTS = {
  version: "1.1.39",
  format: "msi",
  expectedHash: "A".repeat(64),
  sources: SOURCES,
};

describe("downloadUpdateViaSources", () => {
  it("hands privsvc the ordered tiers and the shared budget", async () => {
    const call = vi.fn(async () => ({
      ok: true,
      result: { stagingPath: "C:\\staging\\pkg.msi", sizeBytes: 99, servedBy: "dp" },
    }));

    const out = await downloadUpdateViaSources(ctxWith(call), OPTS);

    const req = call.mock.calls[0][0] as any;
    expect(req.method).toBe("sdp.download");
    expect(req.params.sources).toEqual(SOURCES);
    // The budget must be the same constant the SDP plugin uses — it is bounded
    // by the IPC client's sdp.download ceiling, and a second number here would
    // drift out of that invariant unnoticed.
    expect(req.params.timeoutSeconds).toBe(DOWNLOAD_BUDGET_SECONDS);
    expect(req.params.packageId).toBe(SELF_UPDATE_PACKAGE_ID);
    // Hash is the integrity gate and privsvc compares lowercase.
    expect(req.params.sha256).toBe("a".repeat(64));
    expect(out?.servedBy).toBe("dp");
    expect(out?.filePath).toBe("C:\\staging\\pkg.msi");
  });

  it("still names the origin in the legacy `url` field", async () => {
    // A privsvc that ignores `sources` falls back to `url`. Putting the origin
    // there means an older privsvc downloads the right bytes from the internet
    // rather than failing outright.
    const call = vi.fn(async () => ({
      ok: true,
      result: { stagingPath: "/tmp/p.msi", sizeBytes: 1 },
    }));
    await downloadUpdateViaSources(ctxWith(call), OPTS);
    expect((call.mock.calls[0][0] as any).params.url).toBe(SOURCES[1].url);
  });

  it("returns null when there are no sources, so the caller downloads directly", async () => {
    const call = vi.fn();
    expect(await downloadUpdateViaSources(ctxWith(call), { ...OPTS, sources: [] })).toBeNull();
    expect(call).not.toHaveBeenCalled();
  });

  it("returns null on a privsvc too old to know the method", async () => {
    // Degrading to the direct download keeps updates working on endpoints
    // whose privsvc has not been upgraded yet. Failing here would strand
    // exactly the machines that most need an update.
    const call = vi.fn(async () => ({ ok: false, error: { code: "not_supported" } }));
    expect(await downloadUpdateViaSources(ctxWith(call), OPTS)).toBeNull();
  });

  it("throws when privsvc exhausted every source", async () => {
    // Different from the case above: `origin` was in the list and also failed,
    // so there is nothing left to fall back to and the caller must not silently
    // proceed as if no DP had been configured.
    const call = vi.fn(async () => ({
      ok: false,
      error: { code: "download_failed", message: "budget exhausted" },
    }));
    await expect(downloadUpdateViaSources(ctxWith(call), OPTS)).rejects.toThrow(
      /update_download_failed/
    );
  });

  it("returns null if privsvc answers without a staging path", async () => {
    const call = vi.fn(async () => ({ ok: true, result: {} }));
    expect(await downloadUpdateViaSources(ctxWith(call), OPTS)).toBeNull();
  });
});
