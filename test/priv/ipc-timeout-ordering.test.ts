import { describe, it, expect } from "vitest";
import { getTimeoutForMethod as winTimeout } from "../../src/priv/privsvc-client-windows";
import { getTimeoutForMethod as macTimeout } from "../../src/priv/privsvc-client-macos";
import { getTimeoutForMethod as linuxTimeout } from "../../src/priv/privsvc-client-linux";

/**
 * THE INVARIANT: the CALLER must outwait the HANDLER.
 *
 * When an IPC client gives up before privsvc can answer, a handler that hits
 * its own ceiling can never deliver its diagnostic: the reply lands on a
 * promise nobody is holding. The failure then surfaces as a bare timeout with
 * no detail, which is indistinguishable from a hang.
 *
 * This has bitten this codebase three separate times:
 *   - SDP self-update: client 8s vs privsvc 600-1740s
 *   - Windows security.compliance: client 30s vs a ~10-script handler
 *   - macOS patch_install (2026-08-11): privsvc, client and job ALL 3600s,
 *     so all three expired together and the job stored an empty result_json.
 *
 * These are the privsvc-side ceilings the clients must stay above. Raising a
 * handler budget without raising its client is what breaks it, so this test
 * exists to make that failure loud.
 *
 * ⚠️ NECESSARY BUT NOT SUFFICIENT. A 5th occurrence (cdp.certs.read,
 * 2026-08-13) satisfied every assertion in this file and still failed in
 * production, because the Windows pipe serves ONE request at a time and the
 * old client started each timer at write instead of at dispatch — so a
 * budget could be spent entirely on somebody else's handler. The ordering
 * asserted here only holds per-request; the queue in
 * privsvc-client-windows.ts is what makes it true end to end. See
 * ipc-lane-queue.test.ts.
 */
const PRIVSVC_CEILING_MS: Record<string, { windows?: number; macos?: number; linux?: number }> = {
  // The 4th documented victim of the invariant — and, embarrassingly,
  // the one this file's docblock already cited without covering.
  // Windows: every section runs sequentially at 15s (DEFAULT_PS_
  // TIMEOUT_MS) + 45s patches + 15s Get-HotFix fallback ≈ 240s worst
  // case. macOS: system_profiler 25s + sequential smb/ssh 8s each +
  // per-share probes ≈ 45s. Linux: serial dnf path 3 × 20s
  // (UPDATES_TIMEOUT_MS) = 60s.
  "security.compliance": { windows: 240_000, macos: 45_000, linux: 60_000 },
  // Windows WUA install; macOS/Linux softwareupdate/apt-dnf.
  "patch.install": { windows: 90 * 60_000, macos: 60 * 60_000, linux: 60 * 60_000 },
  // macOS `softwareupdate --list` 120s; Windows scan 60s.
  "patch.scan": { windows: 60_000, macos: 120_000 },
  "sdp.download": { windows: 600_000, macos: 600_000, linux: 600_000 },
  "sdp.install": { windows: 1_740_000, macos: 1_740_000, linux: 1_740_000 },
  "sdp.uninstall": { windows: 1_740_000, macos: 1_740_000, linux: 1_740_000 },
  "sdp.dp.prefetch": { windows: 840_000, macos: 840_000, linux: 840_000 },
  // 5th victim (2026-08-13). Windows-only: the macOS/Linux CDP collectors
  // read the trust stores directly and never go through privsvc.
  // CdpCertificates.HandlerBudgetMs — which did not exist until this bug;
  // an unbounded handler is one the invariant cannot even be stated for.
  "cdp.certs.read": { windows: 45_000 },
};

const CLIENTS = {
  windows: winTimeout,
  macos: macTimeout,
  linux: linuxTimeout,
} as const;

describe("IPC client budgets outwait the privsvc handler", () => {
  for (const [method, ceilings] of Object.entries(PRIVSVC_CEILING_MS)) {
    for (const [platform, ceiling] of Object.entries(ceilings)) {
      it(`${platform}: ${method} client budget > privsvc ${ceiling! / 1000}s`, () => {
        const client = CLIENTS[platform as keyof typeof CLIENTS](method);
        expect(client).toBeGreaterThan(ceiling!);
      });
    }
  }

  it("patch.install leaves real margin over the slowest handler (Windows 90min)", () => {
    // A tie is as broken as being under: both sides expire together and the
    // diagnostic is lost.
    for (const t of Object.values(CLIENTS)) {
      expect(t("patch.install")).toBeGreaterThanOrEqual(95 * 60_000);
    }
  });

  it("patch.scan no longer falls into the 8s default", () => {
    for (const t of Object.values(CLIENTS)) {
      expect(t("patch.scan")).toBeGreaterThanOrEqual(180_000);
    }
  });

  it("an unknown method still gets the conservative default", () => {
    for (const t of Object.values(CLIENTS)) {
      expect(t("something.new")).toBe(8000);
    }
  });
});
