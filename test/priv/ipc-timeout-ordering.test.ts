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
 * A 6th occurrence (grpc.send.remoteSessionIce, 2026-08-15) was a DIFFERENT
 * shape again: the handler is a microsecond stream write, so no ceiling was
 * ever violated. What killed it was the QUEUE — ICE candidates arrive in a
 * burst of 4-5 and the later ones spent their whole 8s default budget waiting
 * their turn on the serial lane. RCP sessions died with `ice_failed` and the
 * browser never saw a remote candidate. Budgets below are therefore about
 * queueing latency, not handler duration.
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
  // macOS `softwareupdate --list` 120s; Windows WSUS scan 150s.
  "patch.scan": { windows: 150_000, macos: 120_000 },
  "sdp.download": { windows: 600_000, macos: 600_000, linux: 600_000 },
  "sdp.install": { windows: 1_740_000, macos: 1_740_000, linux: 1_740_000 },
  "sdp.uninstall": { windows: 1_740_000, macos: 1_740_000, linux: 1_740_000 },
  "sdp.dp.prefetch": { windows: 840_000, macos: 840_000, linux: 840_000 },
  // 5th victim (2026-08-13). Windows-only: the macOS/Linux CDP collectors
  // read the trust stores directly and never go through privsvc.
  // CdpCertificates.HandlerBudgetMs — which did not exist until this bug;
  // an unbounded handler is one the invariant cannot even be stated for.
  "cdp.certs.read": { windows: 45_000 },
  // Stores por usuario (HKEY_USERS). Windows-only por construccion.
  "cdp.certs.readUser": { windows: 45_000 },
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
      expect(t("patch.scan")).toBeGreaterThanOrEqual(240_000);
    }
  });

  it("an unknown method still gets the conservative default", () => {
    for (const t of Object.values(CLIENTS)) {
      expect(t("something.new")).toBe(8000);
    }
  });
});

// The 6th occurrence has no handler ceiling to outwait — these budgets exist
// to survive QUEUEING on the serial IPC lane, so they get their own block
// rather than an entry in PRIVSVC_CEILING_MS.
describe("RCP signaling survives the serial IPC lane", () => {
  const RCP_SENDS = [
    "grpc.send.remoteSessionAnswer",
    "grpc.send.remoteSessionIce",
    "grpc.send.remoteSessionClose",
    "grpc.send.remoteSessionError",
    "grpc.send.remoteSessionTranscript",
    "grpc.send.remoteFileTransferAudit",
    "grpc.send.remoteScreenAudit",
  ];

  for (const method of RCP_SENDS) {
    it(`${method} is off the 8s default on every platform`, () => {
      for (const t of Object.values(CLIENTS)) {
        // 8s is what expired mid-burst in production. Anything at the
        // default here means a platform was missed when the case list grew.
        expect(t(method)).toBeGreaterThan(8000);
      }
    });
  }

  it("all three platforms agree on the signaling budget", () => {
    // Signaling is platform-independent: the same burst, the same lane
    // semantics. A per-platform divergence would only ever be an oversight,
    // and would make RCP fail on exactly one OS — the hardest thing to spot.
    for (const method of RCP_SENDS) {
      const budgets = Object.values(CLIENTS).map((t) => t(method));
      expect(new Set(budgets).size).toBe(1);
    }
  });

  it("ICE is not given so long a budget that it outlives its usefulness", () => {
    // A candidate that lands after the browser's connectivity checks have
    // moved on is worse than a failure: it holds the lane for nothing.
    for (const t of Object.values(CLIENTS)) {
      expect(t("grpc.send.remoteSessionIce")).toBeLessThanOrEqual(60_000);
    }
  });
});
