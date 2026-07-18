// test/plugins/sdp-orchestrator.test.ts
//
// End-to-end tests for the SDP orchestrator (runSoftwareInstall). Everything
// below the orchestrator is IPC to privsvc — we drive it with a scripted fake
// `ctx.priv` so the whole install/uninstall pipeline runs without a real
// privileged service, real OS installers, or network.
//
// Host-agnostic: the snapshot's platform is derived from os.platform() so the
// orchestrator's platform-fit check passes on macOS/Linux/Windows CI alike, and
// the detection rule uses `file_exists` (applicable on every OS) so pre/post
// detection actually dispatches to the fake privsvc.

import os from "os";
import { describe, expect, it, vi } from "vitest";
import { runSoftwareInstall } from "../../src/plugins/sdp/index";

// ── Host platform helpers ─────────────────────────────────────────
function hostPlatform(): "windows" | "macos" | "linux" {
  const p = os.platform();
  return p === "win32" ? "windows" : p === "darwin" ? "macos" : "linux";
}
function otherPlatform(): "windows" | "macos" | "linux" {
  return hostPlatform() === "windows" ? "macos" : "windows";
}
function formatFor(platform: string): string {
  return platform === "windows" ? "msi" : platform === "macos" ? "pkg" : "deb";
}

// ── Scripted privsvc ──────────────────────────────────────────────
//
// Each method maps to a response, or an ARRAY of responses consumed in order
// (sdp.detect is called twice — pre-detect then post-detect). A method with no
// script and no default throws, surfacing an unexpected call.
type PrivResponse = { ok: boolean; result?: any; error?: { code: string } };
type Scripts = Partial<Record<string, PrivResponse | PrivResponse[]>>;

function makeCtx(scripts: Scripts = {}) {
  const calls: Array<{ method: string; params: any }> = [];
  const queues: Record<string, PrivResponse[]> = {};
  for (const [method, val] of Object.entries(scripts)) {
    queues[method] = Array.isArray(val) ? [...val] : [val as PrivResponse];
  }
  const priv = {
    call: vi.fn(async (req: any): Promise<PrivResponse> => {
      calls.push({ method: req.method, params: req.params });
      const q = queues[req.method];
      if (q && q.length > 0) return q.shift() as PrivResponse;
      if (q) return q[q.length - 1] ?? { ok: false, error: { code: "no_script" } };
      throw new Error(`unscripted privsvc method: ${req.method}`);
    }),
  };
  const ctx: any = {
    priv,
    enrollment: { tenantId: "t-1", deviceId: "dev-1" },
    policyRuntime: { pluginEnabled: () => true },
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { ctx, priv, calls };
}

function methodsCalled(calls: Array<{ method: string }>): string[] {
  return calls.map((c) => c.method);
}

// ── ACK parser ────────────────────────────────────────────────────
function parseAck(msg: string): { outcome: string; fields: Record<string, string> } {
  const parts = msg.split(";");
  const outcome = parts[0].split(":")[1];
  const fields: Record<string, string> = {};
  for (const p of parts.slice(1)) {
    const i = p.indexOf("=");
    if (i >= 0) fields[p.slice(0, i)] = p.slice(i + 1);
  }
  return { outcome, fields };
}

// ── Snapshot factory ──────────────────────────────────────────────
function snap(over: Record<string, unknown> = {}) {
  const platform = (over.platform as string) ?? hostPlatform();
  return {
    id: 10,
    name: "TestApp",
    version: "1.0.0",
    platform,
    arch: "any",
    format: formatFor(platform),
    downloadPath: "https://cdn.example.com/app",
    sha256: "a".repeat(64),
    silentInstallArgs: null,
    silentUninstallArgs: null,
    // file_exists is applicable on every OS → pre/post detect reach the fake priv.
    detectionRule: { type: "file_exists", path: "/opt/testapp/bin" },
    expectedExitCodes: [0, 3010],
    signingRequired: false,
    ...over,
  };
}

const OK_DOWNLOAD: PrivResponse = {
  ok: true,
  result: { stagingPath: "/staging/pkg-10", sha256: "a".repeat(64), sizeBytes: 123, durationMs: 5 },
};
const OK_INSTALL: PrivResponse = { ok: true, result: { exitCode: 0, stderrExcerpt: "", durationMs: 42 } };
const DETECT = (matched: boolean): PrivResponse => ({ ok: true, result: { matched, snapshot: { probe: matched } } });

// ── Tests ─────────────────────────────────────────────────────────

describe("runSoftwareInstall — envelope + gates", () => {
  it("rejects an invalid payload (no snapshot)", async () => {
    const { ctx, calls } = makeCtx();
    const ack = await runSoftwareInstall(ctx, "job-1", { deploymentId: 5 });
    expect(ack.ackStatus).toBe(2);
    expect(ack.outcome).toBe("failed");
    expect(parseAck(ack.ackMessage).fields.reason).toBe("invalid_payload");
    expect(calls).toHaveLength(0);
  });

  it("rejects a platform mismatch before any privsvc call", async () => {
    const { ctx, calls } = makeCtx();
    const ack = await runSoftwareInstall(ctx, "job-2", {
      deploymentId: 5,
      packageSnapshot: snap({ platform: otherPlatform() }),
    });
    expect(ack.ackStatus).toBe(2);
    expect(ack.outcome).toBe("rejected");
    expect(parseAck(ack.ackMessage).fields.reason).toMatch(/^platform_mismatch_/);
    expect(calls).toHaveLength(0);
  });

  it("rejects when the sdp plugin is disabled by policy", async () => {
    const { ctx, calls } = makeCtx();
    ctx.policyRuntime.pluginEnabled = () => false;
    const ack = await runSoftwareInstall(ctx, "job-3", { deploymentId: 5, packageSnapshot: snap() });
    expect(ack.ackStatus).toBe(2);
    expect(ack.outcome).toBe("rejected");
    expect(parseAck(ack.ackMessage).fields.reason).toBe("sdp_plugin_disabled_by_policy");
    expect(calls).toHaveLength(0);
  });
});

describe("runSoftwareInstall — install pipeline", () => {
  it("short-circuits already_installed when pre-detect matches (no download)", async () => {
    const { ctx, calls } = makeCtx({ "sdp.detect": DETECT(true) });
    const ack = await runSoftwareInstall(ctx, "job-4", { deploymentId: 7, packageSnapshot: snap() });
    expect(ack.ackStatus).toBe(0);
    expect(ack.outcome).toBe("already_installed");
    expect(parseAck(ack.ackMessage).fields.reason).toBe("pre_detect_matched");
    // Only detect ran — no download, no install.
    expect(methodsCalled(calls)).toEqual(["sdp.detect"]);
  });

  it("maps sha256 mismatch to a permanent rejection", async () => {
    const { ctx, calls } = makeCtx({
      "sdp.detect": DETECT(false),
      "sdp.download": { ok: false, error: { code: "sha256_mismatch" } },
    });
    const ack = await runSoftwareInstall(ctx, "job-5", { deploymentId: 7, packageSnapshot: snap() });
    expect(ack.ackStatus).toBe(2);
    expect(ack.outcome).toBe("rejected");
    expect(parseAck(ack.ackMessage).fields.reason).toBe("sha256_mismatch");
    expect(methodsCalled(calls)).not.toContain("sdp.install");
  });

  it("maps a network download failure to a transient retry", async () => {
    const { ctx } = makeCtx({
      "sdp.detect": DETECT(false),
      "sdp.download": { ok: false, error: { code: "download_failed" } },
    });
    const ack = await runSoftwareInstall(ctx, "job-6", { deploymentId: 7, packageSnapshot: snap() });
    expect(ack.ackStatus).toBe(1);
    expect(ack.outcome).toBe("failed");
    expect(parseAck(ack.ackMessage).fields.reason).toBe("download_failed");
  });

  it("blocks the install when signingRequired but verify is untrusted", async () => {
    const { ctx, calls } = makeCtx({
      "sdp.detect": DETECT(false),
      "sdp.download": OK_DOWNLOAD,
      "sdp.verifySignature": { ok: true, result: { trusted: false, reason: "untrusted_root" } },
    });
    const ack = await runSoftwareInstall(ctx, "job-7", {
      deploymentId: 7,
      packageSnapshot: snap({ signingRequired: true }),
    });
    expect(ack.ackStatus).toBe(2);
    expect(ack.outcome).toBe("signature_invalid");
    expect(parseAck(ack.ackMessage).fields.reason).toBe("untrusted_root");
    // Verify ran, install did not.
    expect(methodsCalled(calls)).toContain("sdp.verifySignature");
    expect(methodsCalled(calls)).not.toContain("sdp.install");
  });

  it("fails on an unexpected installer exit code", async () => {
    const { ctx } = makeCtx({
      "sdp.detect": DETECT(false),
      "sdp.download": OK_DOWNLOAD,
      "sdp.install": { ok: true, result: { exitCode: 1603, stderrExcerpt: "fatal", durationMs: 9 } },
    });
    const ack = await runSoftwareInstall(ctx, "job-8", { deploymentId: 7, packageSnapshot: snap() });
    expect(ack.ackStatus).toBe(2);
    expect(ack.outcome).toBe("failed");
    const p = parseAck(ack.ackMessage);
    expect(p.fields.exit).toBe("1603");
    expect(p.fields.reason).toMatch(/^unexpected_exit_1603/);
  });

  it("fails when post-detect says the software isn't present after install", async () => {
    const { ctx } = makeCtx({
      "sdp.detect": [DETECT(false), DETECT(false)], // pre: absent → proceed; post: still absent → fail
      "sdp.download": OK_DOWNLOAD,
      "sdp.install": OK_INSTALL,
    });
    const ack = await runSoftwareInstall(ctx, "job-9", { deploymentId: 7, packageSnapshot: snap() });
    expect(ack.ackStatus).toBe(2);
    expect(ack.outcome).toBe("failed");
    expect(parseAck(ack.ackMessage).fields.reason).toBe("post_detect_mismatch");
  });

  it("succeeds on the happy path and carries detection forensics", async () => {
    const { ctx, calls } = makeCtx({
      "sdp.detect": [DETECT(false), DETECT(true)], // pre: absent → install; post: present → ok
      "sdp.download": OK_DOWNLOAD,
      "sdp.install": OK_INSTALL,
    });
    const ack = await runSoftwareInstall(ctx, "job-10", { deploymentId: 7, packageSnapshot: snap() });
    expect(ack.ackStatus).toBe(0);
    expect(ack.outcome).toBe("success");
    const p = parseAck(ack.ackMessage);
    expect(p.fields.exit).toBe("0");
    // Forensics blobs (base64url) present for both snapshots.
    expect(p.fields.detectBefore).toBeDefined();
    expect(p.fields.detectAfter).toBeDefined();
    expect(methodsCalled(calls)).toEqual(["sdp.detect", "sdp.download", "sdp.install", "sdp.detect"]);
  });

  it("reports reboot_required on exit 3010", async () => {
    const { ctx } = makeCtx({
      "sdp.detect": [DETECT(false), DETECT(true)],
      "sdp.download": OK_DOWNLOAD,
      "sdp.install": { ok: true, result: { exitCode: 3010, stderrExcerpt: "", durationMs: 12 } },
    });
    const ack = await runSoftwareInstall(ctx, "job-11", { deploymentId: 7, packageSnapshot: snap() });
    expect(ack.ackStatus).toBe(0);
    expect(ack.outcome).toBe("reboot_required");
    expect(parseAck(ack.ackMessage).fields.exit).toBe("3010");
  });
});

describe("runSoftwareInstall — uninstall pipeline", () => {
  // A removable-identity rule the host OS accepts as applicable so pre/post
  // detection dispatch. registry_uninstall is Windows-only; on mac/linux hosts
  // detection is skipped (which the orchestrator treats as "cannot tell").
  function removableSnap(over: Record<string, unknown> = {}) {
    const platform = hostPlatform();
    const rule =
      platform === "windows"
        ? { type: "registry_uninstall", displayNameLike: "TestApp%", productCode: "{GUID-1}" }
        : platform === "macos"
        ? { type: "bundle_version", bundleId: "com.test.app" }
        : { type: "dpkg_installed", packageName: "testapp" };
    return snap({ detectionRule: rule, ...over });
  }

  it("short-circuits already_installed when uninstall target is already absent", async () => {
    const { ctx, calls } = makeCtx({ "sdp.detect": DETECT(false) });
    const ack = await runSoftwareInstall(ctx, "job-u1", {
      deploymentId: 8,
      mode: "uninstall",
      packageSnapshot: removableSnap(),
    });
    expect(ack.ackStatus).toBe(0);
    expect(ack.outcome).toBe("already_installed");
    expect(parseAck(ack.ackMessage).fields.reason).toBe("pre_detect_absent");
    // Nothing beyond detection — no uninstall, no download.
    expect(methodsCalled(calls)).toEqual(["sdp.detect"]);
  });

  it("runs sdp.uninstall (never download/install) when the target is present", async () => {
    const { ctx, calls } = makeCtx({
      "sdp.detect": [DETECT(true), DETECT(false)], // present → uninstall; gone afterwards → success
      "sdp.uninstall": OK_INSTALL,
    });
    const ack = await runSoftwareInstall(ctx, "job-u2", {
      deploymentId: 8,
      mode: "uninstall",
      packageSnapshot: removableSnap(),
    });
    expect(ack.ackStatus).toBe(0);
    expect(ack.outcome).toBe("success");
    expect(methodsCalled(calls)).toEqual(["sdp.detect", "sdp.uninstall", "sdp.detect"]);
    expect(methodsCalled(calls)).not.toContain("sdp.download");
    // Identity was derived from the rule and handed to privsvc.
    const uninstallCall = calls.find((c) => c.method === "sdp.uninstall");
    expect(uninstallCall?.params?.identity).toBeTruthy();
  });

  it("fails when post-detect shows the software is still present after uninstall", async () => {
    const { ctx } = makeCtx({
      "sdp.detect": [DETECT(true), DETECT(true)], // present → uninstall; still present → fail
      "sdp.uninstall": OK_INSTALL,
    });
    const ack = await runSoftwareInstall(ctx, "job-u3", {
      deploymentId: 8,
      mode: "uninstall",
      packageSnapshot: removableSnap(),
    });
    expect(ack.ackStatus).toBe(2);
    expect(ack.outcome).toBe("failed");
    expect(parseAck(ack.ackMessage).fields.reason).toBe("post_detect_still_present");
  });

  it("rejects an uninstall whose rule carries no removable identity", async () => {
    // file_exists is applicable on every OS (so pre-detect matches) but has no
    // uninstall identity → permanent rejection, no privsvc uninstall attempted.
    const { ctx, calls } = makeCtx({ "sdp.detect": DETECT(true) });
    const ack = await runSoftwareInstall(ctx, "job-u4", {
      deploymentId: 8,
      mode: "uninstall",
      packageSnapshot: snap({ detectionRule: { type: "file_exists", path: "/opt/testapp/bin" } }),
    });
    expect(ack.ackStatus).toBe(2);
    expect(ack.outcome).toBe("rejected");
    expect(parseAck(ack.ackMessage).fields.reason).toBe("uninstall_no_identity");
    expect(methodsCalled(calls)).not.toContain("sdp.uninstall");
  });
});
