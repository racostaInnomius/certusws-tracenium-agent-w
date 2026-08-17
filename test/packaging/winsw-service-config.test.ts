// test/packaging/winsw-service-config.test.ts
//
// Guards the Windows service packaging against two changes that each took the
// fleet down in August 2026. Neither is caught by compiling or by any runtime
// test — they are configuration, and they only fail on a live endpoint, hours
// or days later, in a way that looks like "the agent is flaky".
//
// 1. The log appender. Switching to `roll-by-size-time` to get real log
//    deletion also brought WinSW 2.12's RollingSizeTimeLogAppender, which
//    closes the FileStream while the stdout-copy thread is still writing:
//
//      System.ObjectDisposedException: Cannot access a closed file.
//         at WinSW.RollingSizeTimeLogAppender.CopyStreamWithRotation(...)
//         at System.Threading.Thread.StartCallback()
//
//    Unhandled on a background thread, so .NET kills TraceniumAgentCore.exe —
//    WinSW itself — and the node.exe child dies with it via the Job Object.
//    Endpoints crashed during the midnight roll and stayed down.
//
// 2. The installer conditions. `NOT Installed OR REINSTALL` skipped the SCM
//    failure actions and the watchdog task on installs Windows did not treat
//    as fresh-or-reinstall, leaving hosts with no restart policy at all.
//
// Both are cheap to reintroduce and expensive to discover, so they are pinned
// here rather than in a comment.

import { describe, expect, it } from "vitest";
import fs from "fs";
import path from "path";

const repoRoot = path.join(__dirname, "..", "..");

function read(rel: string): string {
  return fs.readFileSync(path.join(repoRoot, rel), "utf8");
}

describe("WinSW service definition", () => {
  const xml = read("packaging/windows/core-service/TraceniumAgentCore.xml");

  it("does not use roll-by-size-time (its appender kills the service)", () => {
    expect(xml).not.toMatch(/mode\s*=\s*"roll-by-size-time"/);
  });

  it("does not schedule a timed roll (autoRollAtTime is what fired the crash)", () => {
    expect(xml).not.toMatch(/<autoRollAtTime>/);
  });

  it("still bounds log growth by size and deletes old files", () => {
    // The reason we left roll-by-time in the first place: it ignores
    // keepFiles, so logs grew without limit. Whatever mode we use must keep
    // both guarantees.
    expect(xml).toMatch(/mode\s*=\s*"roll-by-size"/);
    expect(xml).toMatch(/<sizeThreshold>\s*\d+\s*<\/sizeThreshold>/);
    expect(xml).toMatch(/<keepFiles>\s*\d+\s*<\/keepFiles>/);
  });
});

describe("MSI service recovery", () => {
  const wxs = read("windows/installer/wix/AgentCoreFiles.wxs");

  it("configures SCM failure actions with restarts", () => {
    expect(wxs).toMatch(/sc\.exe\s+failure\s+"TraceniumAgentCore"/);
    expect(wxs).toMatch(/actions=\s*restart\//);
  });

  it("applies recovery and watchdog unconditionally", () => {
    // A condition here means some install shapes silently get no restart
    // policy — and nothing re-applies it later. Both actions are idempotent,
    // so there is no reason to gate them.
    for (const action of ["ConfigureAgentCoreRecovery", "RegisterTraceniumWatchdog"]) {
      const line = wxs
        .split("\n")
        .find((l) => l.includes(`<Custom Action="${action}"`));
      expect(line, `no <Custom Action="${action}"> in InstallExecuteSequence`).toBeTruthy();
      expect(line, `${action} must not be conditioned`).not.toMatch(/Condition=/);
    }
  });
});

describe("PrivSvc self-repair", () => {
  it("re-applies AgentCore recovery on every start", () => {
    // The installer has carried the custom action since 1.1.20 and a 1.1.35
    // host was still found with none configured. Runtime repair is what
    // actually reaches already-deployed endpoints.
    const worker = read("privsvc/windows/Tracenium.PrivSvc.Windows/Worker.cs");
    expect(worker).toMatch(/ServiceRecovery\.EnsureConfigured/);
  });

  it("uses the same restart policy as the MSI", () => {
    const cs = read("privsvc/windows/Tracenium.PrivSvc.Windows/ServiceRecovery.cs");
    const wxs = read("windows/installer/wix/AgentCoreFiles.wxs");
    const actions = cs.match(/Actions\s*=\s*"([^"]+)"/)?.[1];
    expect(actions, "ServiceRecovery.Actions not found").toBeTruthy();
    expect(wxs, "MSI and PrivSvc disagree on the restart policy").toContain(actions!);
  });
});

describe("heartbeat honesty", () => {
  it("suppresses the PrivSvc heartbeat when AgentCore has gone silent", () => {
    // Without this gate the bridge keeps refreshing last_heartbeat on its own
    // timer, so a device whose AgentCore died still reads "online" in the
    // portal — indefinitely, and with every dispatched job stuck in `sent`.
    const bridge = read("privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/GrpcBridge.cs");
    expect(bridge).toMatch(/if\s*\(\s*!AgentLiveness\.IsAlive\s*\)/);
  });

  it("stamps liveness from the IPC router, not from a process check", () => {
    // A wedged AgentCore still shows up in the process list; only traffic on
    // the pipe proves its event loop is turning.
    const router = read("privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/Router.cs");
    expect(router).toMatch(/AgentLiveness\.Touch\(\)/);
  });
});
