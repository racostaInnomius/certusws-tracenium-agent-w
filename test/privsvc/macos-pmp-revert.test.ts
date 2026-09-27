// test/privsvc/macos-pmp-revert.test.ts
//
// pmp.revert en la PrivSvc de macOS: deshace un fix devolviendo el
// `state` que read_check_state leyó antes. Se prueba la planificación
// pura (qué comandos se ejecutarían) y el handler con execFile mockeado,
// incluida la verificación del estado posterior: spctl en macOS 15+
// puede salir 0 sin desactivar Gatekeeper, y no hay que fingir éxito.

import { describe, it, expect, vi, beforeEach } from "vitest";

const execFileMock = vi.fn();
vi.mock("child_process", () => ({
  execFile: (...args: unknown[]) => execFileMock(...args)
}));
// El logger real escribe en /Library/Logs; en tests sólo estorba.
vi.mock("../../privsvc/macos/src/logger", () => ({
  logger: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() }
}));

import {
  planMacRevert,
  handlePmpRevert,
  handlePmpReadCheckState
} from "../../privsvc/macos/src/pmp-remediation";

const ALF = "/usr/libexec/ApplicationFirewall/socketfilterfw";

type Reply = { stdout?: string; stderr?: string; code?: number; timeout?: boolean };

// Respuestas por "bin arg1 arg2…"; el mock registra cada llamada.
let replies: Record<string, Reply | Reply[]> = {};
let calls: string[] = [];

function key(bin: string, args: string[]) {
  return [bin, ...args].join(" ");
}

beforeEach(() => {
  replies = {};
  calls = [];
  execFileMock.mockReset();
  execFileMock.mockImplementation((bin: string, args: string[], _opts: unknown, cb: Function) => {
    const k = key(bin, args);
    calls.push(k);
    const entry = replies[k];
    const r: Reply = Array.isArray(entry) ? (entry.shift() ?? {}) : (entry ?? {});
    const stdout = r.stdout ?? "";
    const stderr = r.stderr ?? "";
    if (r.timeout) {
      cb(Object.assign(new Error("killed"), { killed: true, signal: "SIGTERM", stdout, stderr }));
    } else if (r.code && r.code !== 0) {
      cb(Object.assign(new Error("exit " + r.code), { code: r.code, stdout, stderr }));
    } else {
      cb(null, { stdout, stderr });
    }
  });
});

function req(params: any) {
  return { v: 1, id: "r1", method: "pmp.revert", params } as any;
}

function revertReq(checkId: string, stateBefore: unknown, extra: Record<string, unknown> = {}) {
  return req({ checkId, params: { stateBefore }, ...extra });
}

const FW_OFF = { enabled: false, stateValue: 0, raw: "Firewall is disabled. (State = 0)" };
const FW_ON = { enabled: true, stateValue: 1, raw: "Firewall is enabled. (State = 1)" };
const GK_OFF = { enabled: false, raw: "assessments disabled" };
const GK_ON = { enabled: true, raw: "assessments enabled" };
const RL_ON = { enabled: true, raw: "Remote Login: On" };
const RL_OFF = { enabled: false, raw: "Remote Login: Off" };

// ── planMacRevert (puro) ─────────────────────────────────────────

describe("planMacRevert — only restores when the before-state differs", () => {
  it("firewall off before → setglobalstate off", () => {
    const plan = planMacRevert("macos.firewall.enabled", FW_OFF);
    expect(plan).toEqual({
      commands: [{ bin: ALF, args: ["--setglobalstate", "off"], change: "alf:globalstate=off" }],
      expect: { enabled: false, stateValue: 0 }
    });
  });

  it("firewall already on (1 or 2) before → no-op", () => {
    expect(planMacRevert("macos.firewall.enabled", FW_ON)).toEqual({ commands: [], expect: {} });
    expect(planMacRevert("macos.firewall.enabled", { enabled: true, stateValue: 2, raw: "x" }))
      .toEqual({ commands: [], expect: {} });
  });

  it("gatekeeper disabled before → spctl --master-disable", () => {
    const plan = planMacRevert("macos.gatekeeper.enabled", GK_OFF);
    expect("commands" in plan && plan.commands).toEqual([
      { bin: "/usr/sbin/spctl", args: ["--master-disable"], change: "spctl:--master-disable" }
    ]);
    expect("expect" in plan && plan.expect).toEqual({ enabled: false });
  });

  it("gatekeeper enabled before → no-op", () => {
    expect(planMacRevert("macos.gatekeeper.enabled", GK_ON)).toEqual({ commands: [], expect: {} });
  });

  it("remote login on before → systemsetup -f -setremotelogin on (mirrors forward -f)", () => {
    const plan = planMacRevert("macos.remote_login.disabled", RL_ON);
    expect("commands" in plan && plan.commands).toEqual([
      { bin: "/usr/sbin/systemsetup", args: ["-f", "-setremotelogin", "on"], change: "systemsetup:remotelogin=on" }
    ]);
    expect("expect" in plan && plan.expect).toEqual({ enabled: true });
  });

  it("remote login off before → no-op", () => {
    expect(planMacRevert("macos.remote_login.disabled", RL_OFF)).toEqual({ commands: [], expect: {} });
  });

  it("raw is optional (diagnostic only)", () => {
    expect(planMacRevert("macos.gatekeeper.enabled", { enabled: true })).toEqual({ commands: [], expect: {} });
  });
});

describe("planMacRevert — unsupported checkIds", () => {
  it.each(["macos.sip.enabled", "macos.filevault.enabled", "macos.nope", "win.firewall.enabled"])(
    "%s → unsupported_check (even with a valid-looking stateBefore)",
    (checkId) => {
      const plan = planMacRevert(checkId, { enabled: false, raw: "" });
      expect("error" in plan && plan.error.code).toBe("unsupported_check");
    }
  );

  it("read-only checks say so explicitly", () => {
    const plan = planMacRevert("macos.sip.enabled", {});
    expect("error" in plan && plan.error.message).toMatch(/read-only/);
  });
});

describe("planMacRevert — invalid stateBefore → bad_request", () => {
  const cases: Array<[string, string, unknown]> = [
    ["missing", "macos.firewall.enabled", undefined],
    ["null", "macos.firewall.enabled", null],
    ["array", "macos.gatekeeper.enabled", [false]],
    ["string", "macos.remote_login.disabled", "on"],
    ["fw enabled not boolean", "macos.firewall.enabled", { enabled: "false", stateValue: 0 }],
    ["fw stateValue missing", "macos.firewall.enabled", { enabled: false }],
    ["fw stateValue out of range", "macos.firewall.enabled", { enabled: true, stateValue: 3 }],
    ["fw stateValue not integer", "macos.firewall.enabled", { enabled: true, stateValue: 1.5 }],
    ["fw enabled/stateValue inconsistent", "macos.firewall.enabled", { enabled: true, stateValue: 0 }],
    ["fw unknown state (null)", "macos.firewall.enabled", { enabled: false, stateValue: null }],
    ["fw unknown key", "macos.firewall.enabled", { ...FW_OFF, stealth: true }],
    ["raw not string", "macos.firewall.enabled", { ...FW_OFF, raw: 5 }],
    ["gk enabled missing", "macos.gatekeeper.enabled", { raw: "assessments disabled" }],
    ["gk enabled null", "macos.gatekeeper.enabled", { enabled: null }],
    ["gk unknown key", "macos.gatekeeper.enabled", { enabled: false, stateValue: 0 }],
    ["rl enabled string", "macos.remote_login.disabled", { enabled: "On" }],
    ["rl unknown state (null)", "macos.remote_login.disabled", { enabled: null, raw: "?" }],
    ["rl unknown key", "macos.remote_login.disabled", { enabled: true, port: 22 }]
  ];

  it.each(cases)("%s", (_label, checkId, stateBefore) => {
    const plan = planMacRevert(checkId, stateBefore);
    expect("error" in plan && plan.error.code).toBe("bad_request");
  });
});

// ── handlePmpRevert (con execFile mockeado) ──────────────────────

describe("handlePmpRevert — end to end with mocked commands", () => {
  it("rejects missing checkId with bad_request and runs nothing", async () => {
    const res = await handlePmpRevert(req({ params: { stateBefore: FW_OFF } }));
    expect(res.ok).toBe(false);
    expect(res.error?.code).toBe("bad_request");
    expect(calls).toEqual([]);
  });

  it("rejects missing stateBefore with bad_request and runs nothing", async () => {
    const res = await handlePmpRevert(req({ checkId: "macos.firewall.enabled" }));
    expect(res.error?.code).toBe("bad_request");
    expect(calls).toEqual([]);
  });

  it("sip → unsupported_check", async () => {
    const res = await handlePmpRevert(revertReq("macos.sip.enabled", { enabled: false, raw: "" }));
    expect(res.error?.code).toBe("unsupported_check");
    expect(calls).toEqual([]);
  });

  it("rejects a non-positive timeoutSeconds", async () => {
    const res = await handlePmpRevert(revertReq("macos.firewall.enabled", FW_OFF, { timeoutSeconds: 0 }));
    expect(res.error?.code).toBe("bad_request");
    expect(calls).toEqual([]);
  });

  it("no-op when already in the before-state: success, exit 0, no commands", async () => {
    const res = await handlePmpRevert(revertReq("macos.gatekeeper.enabled", GK_ON));
    expect(res.ok).toBe(true);
    expect(res.result).toMatchObject({ exitCode: 0, stderrExcerpt: null, requiresReboot: false, changesApplied: [] });
    expect(calls).toEqual([]);
  });

  it("firewall: turns ALF off, verifies, and read_check_state then equals stateBefore", async () => {
    replies[key(ALF, ["--setglobalstate", "off"])] = { stdout: "Firewall is disabled. (State = 0)\n" };
    replies[key(ALF, ["--getglobalstate"])] = { stdout: "Firewall is disabled. (State = 0)\n" };

    const res = await handlePmpRevert(revertReq("macos.firewall.enabled", FW_OFF));
    expect(res.ok).toBe(true);
    expect(res.result).toMatchObject({
      exitCode: 0,
      stderrExcerpt: null,
      requiresReboot: false,
      changesApplied: ["alf:globalstate=off"]
    });
    expect(typeof res.result.durationMs).toBe("number");
    expect(calls).toEqual([key(ALF, ["--setglobalstate", "off"]), key(ALF, ["--getglobalstate"])]);

    // Lo que verifica el agente Node: cada clave de stateBefore igual.
    const read = await handlePmpReadCheckState(req({ checkId: "macos.firewall.enabled" }));
    for (const [k, v] of Object.entries(FW_OFF)) expect(read.result.state[k]).toEqual(v);
  });

  it("remote login: turns it back on with -f, verifies", async () => {
    replies[key("/usr/sbin/systemsetup", ["-f", "-setremotelogin", "on"])] = { stdout: "" };
    replies[key("/usr/sbin/systemsetup", ["-getremotelogin"])] = { stdout: "Remote Login: On\n" };

    const res = await handlePmpRevert(revertReq("macos.remote_login.disabled", RL_ON));
    expect(res.result).toMatchObject({ exitCode: 0, changesApplied: ["systemsetup:remotelogin=on"] });
    expect(calls[0]).toBe("/usr/sbin/systemsetup -f -setremotelogin on");
  });

  it("gatekeeper: command exits 0 but status unchanged (macOS 15+) → non-zero exit + clear stderr", async () => {
    replies[key("/usr/sbin/spctl", ["--master-disable"])] = {
      stdout: "Globally disabling the assessment system needs to be confirmed in System Settings.\n"
    };
    replies[key("/usr/sbin/spctl", ["--status"])] = { stdout: "assessments enabled\n" };

    const res = await handlePmpRevert(revertReq("macos.gatekeeper.enabled", GK_OFF));
    expect(res.ok).toBe(true);
    expect(res.result.exitCode).not.toBe(0);
    expect(res.result.changesApplied).toEqual([]);
    expect(res.result.stderrExcerpt).toMatch(/state was not restored/);
    expect(res.result.stderrExcerpt).toMatch(/enabled: expected false, got true/);
    expect(res.result.stderrExcerpt).toMatch(/confirmed in System Settings/);
    expect(res.result.stderrExcerpt).toMatch(/Anywhere/);
  });

  it("gatekeeper: succeeds when status flips to disabled", async () => {
    replies[key("/usr/sbin/spctl", ["--master-disable"])] = { stdout: "" };
    replies[key("/usr/sbin/spctl", ["--status"])] = { stdout: "assessments disabled\n" };

    const res = await handlePmpRevert(revertReq("macos.gatekeeper.enabled", GK_OFF));
    expect(res.result).toMatchObject({ exitCode: 0, changesApplied: ["spctl:--master-disable"] });
  });

  it("command failure → success envelope with its exit code and stderr (no verification read)", async () => {
    replies[key("/usr/sbin/systemsetup", ["-f", "-setremotelogin", "on"])] = {
      code: 1,
      stderr: "Turning Remote Login on or off requires Full Disk Access privileges.\n"
    };

    const res = await handlePmpRevert(revertReq("macos.remote_login.disabled", RL_ON));
    expect(res.ok).toBe(true);
    expect(res.result.exitCode).toBe(1);
    expect(res.result.changesApplied).toEqual([]);
    expect(res.result.stderrExcerpt).toMatch(/Full Disk Access/);
    expect(calls).toHaveLength(1);
  });

  it("timed-out command → revert_timeout", async () => {
    replies[key(ALF, ["--setglobalstate", "off"])] = { timeout: true };

    const res = await handlePmpRevert(revertReq("macos.firewall.enabled", FW_OFF, { timeoutSeconds: 5 }));
    expect(res.ok).toBe(false);
    expect(res.error?.code).toBe("revert_timeout");
  });

  it("passes timeoutSeconds down as the exec timeout", async () => {
    replies[key(ALF, ["--setglobalstate", "off"])] = { stdout: "" };
    replies[key(ALF, ["--getglobalstate"])] = { stdout: "Firewall is disabled. (State = 0)" };

    await handlePmpRevert(revertReq("macos.firewall.enabled", FW_OFF, { timeoutSeconds: 7 }));
    const opts = execFileMock.mock.calls[0][2] as { timeout: number };
    expect(opts.timeout).toBeGreaterThan(0);
    expect(opts.timeout).toBeLessThanOrEqual(7000);
  });

  it("spawn failure on the verification read → non-zero exit, not a fake success", async () => {
    replies[key(ALF, ["--setglobalstate", "off"])] = { stdout: "" };
    replies[key(ALF, ["--getglobalstate"])] = { code: 1, stderr: "spawn EACCES" };

    const res = await handlePmpRevert(revertReq("macos.firewall.enabled", FW_OFF));
    expect(res.ok).toBe(true);
    expect(res.result.exitCode).not.toBe(0);
    expect(res.result.stderrExcerpt).toMatch(/stateValue: expected 0, got null/);
  });
});
