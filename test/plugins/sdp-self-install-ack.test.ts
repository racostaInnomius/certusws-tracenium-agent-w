// test/plugins/sdp-self-install-ack.test.ts
//
// Distributing the agent through SDP is the one case where the installer kills
// the reporter: msiexec stops AgentCore, so the ACK for `sdp.install` never
// leaves the machine. Every self-deployment so far closed with `attempts: 2`
// and roughly 32 minutes between dispatch and completion — the orchestrator's
// retry finding the package already installed.
//
// The fix ACKs before handing off. What matters is the ORDER (the ACK must be
// on the wire before the installer can kill us) and the HONESTY of what it
// claims: the exit code is the one thing the agent cannot know at that point,
// so the message must not carry one. Reporting an exit code we never read is
// the same class of lie that made failed updates report as completed.

import { describe, expect, it, vi } from "vitest";
import os from "os";
import { isSelfPackage, SELF_INSTALL_ACK_REASON } from "../../src/plugins/sdp";

describe("isSelfPackage", () => {
  it("recognises the agent's own package", () => {
    expect(isSelfPackage({ name: "Tracenium Agent", vendor: "CERTUS ITM LLC" })).toBe(true);
    // The catalog name has carried suffixes before ("... Testing").
    expect(isSelfPackage({ name: "Tracenium Agent Testing", vendor: "CERTUS ITM LLC" })).toBe(true);
    expect(isSelfPackage({ name: "tracenium agent", vendor: "" })).toBe(true);
  });

  it("leaves third-party packages alone", () => {
    expect(isSelfPackage({ name: "7-Zip", vendor: "Igor Pavlov" })).toBe(false);
    expect(isSelfPackage({ name: "Google Chrome", vendor: "Google LLC" })).toBe(false);
    // Same name, different vendor: not us, so no early ACK.
    expect(isSelfPackage({ name: "Tracenium Agent", vendor: "Acme Corp" })).toBe(false);
    expect(isSelfPackage({})).toBe(false);
    expect(isSelfPackage(null)).toBe(false);
  });
});

// ── Ordering ──────────────────────────────────────────────────────
//
// Asserted by recording a single ordered timeline of calls. A test that only
// checked "the ACK was sent" would pass even if it went out AFTER the install
// returned — which is exactly the case that does not survive on a real
// endpoint, because the process is gone by then.

// Host-agnostic, like the other orchestrator tests: derive the package's
// platform/format from the host so the plugin's platform-fit check passes on
// macOS, Linux and Windows alike. Hardcoding "windows" would make the whole
// suite pass only on Windows CI.
function hostPlatform(): "windows" | "macos" | "linux" {
  const p = os.platform();
  return p === "win32" ? "windows" : p === "darwin" ? "macos" : "linux";
}
function formatFor(platform: string): string {
  return platform === "windows" ? "msi" : platform === "macos" ? "pkg" : "deb";
}

function harness(opts: { snapshot: any; installOk?: boolean }) {
  const timeline: string[] = [];
  const earlyAcks: string[] = [];

  const priv = {
    call: vi.fn(async (req: any) => {
      timeline.push(req.method);
      switch (req.method) {
        case "sdp.detect":
          return { ok: true, result: { matched: false } };
        case "sdp.download":
          return {
            ok: true,
            result: { stagingPath: "C:\\staging\\pkg.msi", sizeBytes: 10, servedBy: "dp" },
          };
        case "sdp.verifySignature":
          return { ok: true, result: { trusted: true, reason: "trusted" } };
        case "sdp.install":
          return opts.installOk === false
            ? { ok: false, error: { code: "install_failed", message: "exit 1603" } }
            : { ok: true, result: { exitCode: 0, durationMs: 1200 } };
        default:
          return { ok: true, result: {} };
      }
    }),
  };

  const ctx: any = {
    priv,
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    enrollment: { tenantId: "111", deviceId: "dev-1" },
    agent: { platform: hostPlatform() },
  };

  const sendEarlyAck = vi.fn(async (message: string) => {
    timeline.push("EARLY_ACK");
    earlyAcks.push(message);
  });

  const payload = {
    deploymentId: 9,
    mode: "install",
    packageSnapshot: {
      id: 1,
      platform: hostPlatform(),
      arch: "x64",
      format: formatFor(hostPlatform()),
      sha256: "a".repeat(64),
      downloadPath: "https://example/pkg.msi",
      expectedExitCodes: [0, 3010],
      ...opts.snapshot,
    },
  };

  return { ctx, payload, sendEarlyAck, timeline, earlyAcks };
}

describe("self-install early ACK", () => {
  it("ACKs BEFORE handing off to the installer", async () => {
    const { runSoftwareInstall } = await import("../../src/plugins/sdp");
    const h = harness({
      snapshot: { name: "Tracenium Agent", vendor: "CERTUS ITM LLC", version: "1.1.38" },
    });

    await runSoftwareInstall(h.ctx, "job-1", h.payload, h.sendEarlyAck);

    const ackAt = h.timeline.indexOf("EARLY_ACK");
    const installAt = h.timeline.indexOf("sdp.install");
    expect(ackAt, "no early ACK was sent").toBeGreaterThan(-1);
    expect(installAt, "the installer never ran").toBeGreaterThan(-1);
    expect(ackAt, "the ACK must precede the installer that kills this process")
      .toBeLessThan(installAt);
    // And only once it is worth ACKing: after the bytes were verified.
    expect(h.timeline.indexOf("sdp.download")).toBeLessThan(ackAt);
  });

  it("claims no exit code, and marks the row as launched-not-confirmed", async () => {
    const { runSoftwareInstall } = await import("../../src/plugins/sdp");
    const h = harness({
      snapshot: { name: "Tracenium Agent", vendor: "CERTUS ITM LLC", version: "1.1.38" },
    });

    await runSoftwareInstall(h.ctx, "job-1", h.payload, h.sendEarlyAck);

    const [msg] = h.earlyAcks;
    expect(msg).toContain("software_install:success");
    expect(msg).toContain(`reason=${SELF_INSTALL_ACK_REASON}`);
    // The whole point: we are about to be terminated, so we cannot have read
    // an exit code. Inventing one is what we are trying not to repeat.
    expect(msg).not.toMatch(/\bexit=/);
    // The tier IS known by now and is worth carrying.
    expect(msg).toContain("src=dp");
  });

  it("does not fire for third-party packages", async () => {
    const { runSoftwareInstall } = await import("../../src/plugins/sdp");
    const h = harness({ snapshot: { name: "7-Zip", vendor: "Igor Pavlov", version: "23.01" } });

    await runSoftwareInstall(h.ctx, "job-2", h.payload, h.sendEarlyAck);

    expect(h.sendEarlyAck).not.toHaveBeenCalled();
    expect(h.timeline).toContain("sdp.install");
  });

  it("still installs when the early ACK cannot be sent", async () => {
    // Advisory plumbing must never block the actual work: failing the install
    // because a status message did not go out would be worse than the delay
    // the ACK exists to avoid.
    const { runSoftwareInstall } = await import("../../src/plugins/sdp");
    const h = harness({
      snapshot: { name: "Tracenium Agent", vendor: "CERTUS ITM LLC", version: "1.1.38" },
    });
    h.sendEarlyAck.mockRejectedValue(new Error("stream gone"));

    const ack = await runSoftwareInstall(h.ctx, "job-3", h.payload, h.sendEarlyAck);

    expect(h.timeline).toContain("sdp.install");
    expect(ack.outcome).toBe("success");
  });

  it("still reports a failing installer when we survive it", async () => {
    // Early ACK said success; the installer then failed without replacing us.
    // The backend keeps the first terminal outcome for the result row, but the
    // job-level failure is the only signal the operator gets — send it.
    const { runSoftwareInstall } = await import("../../src/plugins/sdp");
    const h = harness({
      snapshot: { name: "Tracenium Agent", vendor: "CERTUS ITM LLC", version: "1.1.38" },
      installOk: false,
    });

    const ack = await runSoftwareInstall(h.ctx, "job-4", h.payload, h.sendEarlyAck);

    expect(h.sendEarlyAck).toHaveBeenCalled();
    expect(ack.ackStatus).not.toBe(0);
    expect(ack.outcome).not.toBe("success");
  });
});
