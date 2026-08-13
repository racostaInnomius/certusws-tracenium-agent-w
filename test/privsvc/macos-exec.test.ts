// test/privsvc/macos-exec.test.ts
//
// Regression coverage for the macOS privsvc exec plumbing.
//
// Bug (found 2026-08-13): run() concatenated stderr onto stdout and
// runJson() parsed the combined string. system_profiler routinely
// emits warnings on stderr, so `system_profiler -json` results failed
// JSON.parse and became null — for collectPatches that rendered as
// items:[] / count:0, silently indistinguishable from a genuinely
// empty install history. runJson must parse stdout ONLY; the combined
// `output` stays as-is because the regex-matching text collectors
// (systemsetup, socketfilterfw) legitimately read both streams.

import { describe, it, expect, vi, beforeEach } from "vitest";

const execFileMock = vi.fn();
vi.mock("child_process", () => ({
  execFile: (...args: unknown[]) => execFileMock(...args)
}));

import { __test__ } from "../../privsvc/macos/src/security-posture";
const { run, runJson } = __test__;

function resolveWith(stdout: string, stderr: string) {
  execFileMock.mockImplementation((_cmd, _args, _opts, cb) => {
    (cb as (err: unknown, out: unknown) => void)(null, { stdout, stderr });
  });
}

function rejectWith(message: string, stdout = "", stderr = "") {
  execFileMock.mockImplementation((_cmd, _args, _opts, cb) => {
    (cb as (err: unknown, out: unknown) => void)(
      Object.assign(new Error(message), { stdout, stderr }),
      { stdout, stderr }
    );
  });
}

beforeEach(() => {
  execFileMock.mockReset();
});

describe("runJson — stderr must not corrupt the payload", () => {
  it("parses valid JSON when stderr carries a warning", async () => {
    resolveWith('{"SPInstallHistoryDataType":[{"_name":"Safari"}]}', "some system_profiler warning\n");
    const parsed = await runJson<{ SPInstallHistoryDataType: Array<{ _name: string }> }>(
      "/usr/sbin/system_profiler",
      ["SPInstallHistoryDataType", "-json"]
    );
    expect(parsed).not.toBeNull();
    expect(parsed?.SPInstallHistoryDataType?.[0]?._name).toBe("Safari");
  });

  it("returns null when stdout is empty even if stderr has content", async () => {
    resolveWith("", "error: not permitted\n");
    const parsed = await runJson("/usr/sbin/system_profiler", ["-json"]);
    expect(parsed).toBeNull();
  });

  it("returns null on malformed stdout", async () => {
    resolveWith("not json at all", "");
    const parsed = await runJson("/usr/sbin/system_profiler", ["-json"]);
    expect(parsed).toBeNull();
  });
});

describe("run — combined output preserved for text collectors", () => {
  it("keeps stdout+stderr in output but stdout alone in stdout", async () => {
    resolveWith("FileVault is On.\n", "warning line\n");
    const result = await run("/usr/bin/fdesetup", ["status"]);
    expect(result.ok).toBe(true);
    expect(result.output).toContain("FileVault is On.");
    expect(result.output).toContain("warning line");
    expect(result.stdout).toBe("FileVault is On.");
  });

  it("reports ok:false with whatever the failed command produced", async () => {
    rejectWith("Command failed", "partial stdout", "boom on stderr");
    const result = await run("/usr/sbin/systemsetup", ["-getremotelogin"]);
    expect(result.ok).toBe(false);
    expect(result.output).toBe("partial stdout");
    expect(result.stdout).toBe("partial stdout");
  });
});
