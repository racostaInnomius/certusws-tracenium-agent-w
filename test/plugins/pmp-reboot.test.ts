// test/plugins/pmp-reboot.test.ts
//
// When a patch run restarts the machine, and — the half that matters more —
// when it must not.

import { describe, it, expect } from "vitest";
import {
  planPatchReboot,
  rebootCommandFor,
  rebootCancelCommandFor,
  rebootAckSuffix,
  DEFAULT_REBOOT_GRACE_MS,
} from "../../src/plugins/pmp/reboot";

const base = { rebootIfRequired: true, rebootRequired: true, installedCount: 3, failedCount: 0 };

describe("planPatchReboot", () => {
  it("⭐ restarts when the operator asked and the patch needs it", () => {
    expect(planPatchReboot(base)).toEqual({
      reboot: true,
      reason: "reboot_required",
      graceMs: DEFAULT_REBOOT_GRACE_MS,
    });
  });

  it("⭐ never restarts a machine that was not enrolled in it", () => {
    // The default. A surprise restart of a production server is worse than an
    // unapplied patch.
    expect(planPatchReboot({ ...base, rebootIfRequired: false })).toMatchObject({
      reboot: false,
      reason: "not_requested",
    });
  });

  it("does not restart when nothing needs one", () => {
    expect(planPatchReboot({ ...base, rebootRequired: false })).toMatchObject({
      reboot: false,
      reason: "not_required",
    });
  });

  it("⭐ restarts on a PARTIAL run — what installed is not applied until it does", () => {
    expect(planPatchReboot({ ...base, installedCount: 2, failedCount: 1 })).toMatchObject({
      reboot: true,
      reason: "reboot_required",
    });
  });

  it("⭐ does NOT restart on somebody else's pending reboot when this run installed nothing", () => {
    // The machine reports a pending reboot from an earlier change. The
    // operator's own action did nothing, so restarting their server on that
    // basis is the surprise this feature must not produce.
    expect(planPatchReboot({ ...base, installedCount: 0, failedCount: 0 })).toMatchObject({
      reboot: false,
      reason: "nothing_installed",
    });
    expect(planPatchReboot({ ...base, installedCount: 0, failedCount: 4 })).toMatchObject({
      reboot: false,
      reason: "nothing_installed",
    });
  });

  it("honours a custom grace and never a negative one", () => {
    expect(planPatchReboot({ ...base, graceMs: 5000 }).graceMs).toBe(5000);
    expect(planPatchReboot({ ...base, graceMs: -1 }).graceMs).toBe(0);
  });
});

describe("rebootCommandFor", () => {
  it("Windows takes seconds directly, and marks the restart as planned", () => {
    const c = rebootCommandFor("win32", 60);
    expect(c.cmd).toBe("shutdown");
    expect(c.args.slice(0, 3)).toEqual(["/r", "/t", "60"]);
    expect(c.args).toContain("/d");
  });

  it("⭐ Unix cannot express seconds, so it rounds UP — never restarting early", () => {
    // `shutdown -r +0` on a 60 s grace would go down immediately and lose the ACK.
    expect(rebootCommandFor("linux", 60).args).toEqual(["-r", "+1", "Tracenium: completing patch installation"]);
    expect(rebootCommandFor("linux", 61).args[1]).toBe("+2");
    expect(rebootCommandFor("darwin", 30).args).toEqual(["-r", "+1"]);
    expect(rebootCommandFor("darwin", 1).args[1]).toBe("+1");
  });

  it("a zero grace is still zero, not a negative delay", () => {
    expect(rebootCommandFor("win32", 0).args[2]).toBe("0");
    expect(rebootCommandFor("linux", -5).args[1]).toBe("+0");
  });

  it("carries a comment a signed-in user can read", () => {
    expect(rebootCommandFor("win32", 60)).toMatchObject({ args: expect.arrayContaining(["/c"]) });
    expect(rebootCommandFor("win32", 60).args.join(" ")).toContain("Tracenium");
  });
});

describe("rebootCancelCommandFor", () => {
  it("knows how to call it off on each platform", () => {
    expect(rebootCancelCommandFor("win32")).toEqual({ cmd: "shutdown", args: ["/a"] });
    expect(rebootCancelCommandFor("linux")).toEqual({ cmd: "shutdown", args: ["-c"] });
  });
});

describe("rebootAckSuffix", () => {
  it("⭐ tells the control plane a restart is coming, and in how long", () => {
    // The ACK goes out BEFORE the restart, so this is the only warning the
    // control plane gets that the device is about to disappear on purpose.
    expect(rebootAckSuffix(planPatchReboot(base))).toBe("; rebootScheduled=true; rebootInSec=60");
  });

  it("says nothing when nothing is scheduled", () => {
    expect(rebootAckSuffix(planPatchReboot({ ...base, rebootIfRequired: false }))).toBe("");
  });
});

// ── the executor ───────────────────────────────────────────────────────────
import { armPatchReboot, cancelPatchReboot } from "../../src/plugins/pmp/reboot-exec";

describe("armPatchReboot", () => {
  const spy = () => {
    const calls: Array<{ cmd: string; args: string[] }> = [];
    return { calls, run: async (cmd: string, args: string[]) => (calls.push({ cmd, args }), { ok: true }) };
  };

  it("⭐ hands the grace to the OS, so the restart survives the agent dying", () => {
    const s = spy();
    return armPatchReboot(planPatchReboot(base), { platform: "win32", run: s.run }).then((armed) => {
      expect(armed).toBe(true);
      expect(s.calls).toHaveLength(1);
      // 60 s on the OS timer — not slept in-process.
      expect(s.calls[0].args.slice(0, 3)).toEqual(["/r", "/t", "60"]);
    });
  });

  it("does nothing at all when the decision says no", async () => {
    const s = spy();
    expect(await armPatchReboot(planPatchReboot({ ...base, rebootIfRequired: false }), { run: s.run })).toBe(false);
    expect(s.calls).toHaveLength(0);
  });

  it("⭐ a restart that cannot be armed does NOT fail the patch", async () => {
    // The patch installed correctly. Reporting it as failed because shutdown.exe
    // refused would turn a successful patch into a false alarm; the endpoint
    // stays visible as rebootRequired instead.
    const armed = await armPatchReboot(planPatchReboot(base), {
      platform: "win32",
      run: async () => ({ ok: false, error: "Access is denied" }),
    });
    expect(armed).toBe(false);
  });

  it("survives the command throwing outright", async () => {
    const armed = await armPatchReboot(planPatchReboot(base), {
      platform: "win32",
      run: async () => { throw new Error("ENOENT"); },
    });
    expect(armed).toBe(false);
  });

  it("cancel calls the platform's abort", async () => {
    const s = spy();
    expect(await cancelPatchReboot({ platform: "win32", run: s.run })).toBe(true);
    expect(s.calls[0]).toEqual({ cmd: "shutdown", args: ["/a"] });
  });
});
