// test/update/macos-installer-stall-timer.test.ts
//
// El `installer` que lanza el propio intento: si PackageKit no lo atiende,
// espera para siempre. A la media hora se mata y el estado queda en fallo con
// el motivo.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const updateUpdateState = vi.fn();
vi.mock("../../src/update/update-state", () => ({
  updateUpdateState: (...a: any[]) => updateUpdateState(...a)
}));

type FakeChild = EventEmitter & {
  pid: number;
  exitCode: number | null;
  signalCode: string | null;
  stdout: EventEmitter;
  stderr: EventEmitter;
  kill: ReturnType<typeof vi.fn>;
  unref: () => void;
};
let child: FakeChild;
vi.mock("child_process", async (importOriginal) => ({
  ...(await importOriginal<typeof import("child_process")>()),
  spawn: vi.fn(() => child)
}));

import { runMacosPkgUpdate } from "../../src/update/updater-runner";
import { INSTALLER_STALL_SEC } from "../../src/update/macos-installer-guard";

let pkg: string;

beforeEach(() => {
  vi.useFakeTimers();
  updateUpdateState.mockReset();
  child = Object.assign(new EventEmitter(), {
    pid: 4242,
    exitCode: null,
    signalCode: null,
    stdout: new EventEmitter(),
    stderr: new EventEmitter(),
    kill: vi.fn(),
    unref: () => {}
  }) as FakeChild;
  pkg = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "pkg-")), "Tracenium-Agent-1.1.88-x64.pkg");
  fs.writeFileSync(pkg, "x");
});

afterEach(() => {
  vi.useRealTimers();
  fs.rmSync(path.dirname(pkg), { recursive: true, force: true });
});

describe("runMacosPkgUpdate: tiempo máximo del installer", () => {
  it("⭐ a la media hora sin salir, lo mata y deja el intento en fallo con el motivo", () => {
    runMacosPkgUpdate(pkg);

    vi.advanceTimersByTime(INSTALLER_STALL_SEC * 1000 - 1);
    expect(child.kill).not.toHaveBeenCalled();

    vi.advanceTimersByTime(1);
    expect(child.kill).toHaveBeenCalledWith("SIGTERM");
    expect(updateUpdateState).toHaveBeenCalledWith(
      expect.objectContaining({
        updateInProgress: false,
        status: "failed",
        lastError: expect.stringMatching(/^installer_stalled: .*PackageKit/)
      })
    );
  });

  it("si sale antes, el temporizador no hace nada", () => {
    runMacosPkgUpdate(pkg);
    child.exitCode = 1;
    child.emit("exit", 1, null);

    vi.advanceTimersByTime(INSTALLER_STALL_SEC * 1000);
    expect(child.kill).not.toHaveBeenCalled();
    expect(updateUpdateState.mock.calls.some((c) => /installer_stalled/.test(String(c[0]?.lastError)))).toBe(false);
  });
});
