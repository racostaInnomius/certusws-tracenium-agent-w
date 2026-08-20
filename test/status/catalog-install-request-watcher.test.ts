// test/status/catalog-install-request-watcher.test.ts
//
// Coverage for the tray -> core channel that lets the Software Catalog
// tab's "Install" button reach the control plane: the tray writes
// catalog-install-request.json into its own per-user directory, and
// this module (polled from grpc-stream.ts) reads + consumes it.
//
// Mocks geo.ts's parseConsoleUser/resolveHomeDirectory (the only two
// exports this module uses from it) rather than child_process directly
// — that keeps this suite focused on the file-handling contract
// (consume-once, staleness, malformed input) instead of re-testing
// console-user resolution, which geo.test.ts already owns. Same idea
// for Windows: mocks device-facts-builder's getInteractiveUserFromOs
// rather than the PowerShell call underneath it.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

let tmpHome: string;

vi.mock("../../src/plugins/amp/providers/geo", () => ({
  parseConsoleUser: (stdout: unknown) => (stdout === "no-user" ? null : "testuser"),
  resolveHomeDirectory: async () => tmpHome,
}));

vi.mock("child_process", () => ({
  execFile: (
    _cmd: string,
    _args: string[],
    _opts: unknown,
    cb: (err: Error | null, res: { stdout: string; stderr: string }) => void
  ) => cb(null, { stdout: "testuser", stderr: "" }),
}));

const getInteractiveUserFromOs = vi.fn();
vi.mock("../../src/domain/device-facts-builder", () => ({
  getInteractiveUserFromOs: (...a: unknown[]) => getInteractiveUserFromOs(...a),
}));

let consumePendingCatalogInstallRequest: typeof import("../../src/status/catalog-install-request-watcher").consumePendingCatalogInstallRequest;

function requestFilePath() {
  return path.join(tmpHome, "Library/Application Support/Tracenium", "catalog-install-request.json");
}

function writeRequestFile(payload: Record<string, unknown>) {
  const filePath = requestFilePath();
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(payload), "utf8");
}

const originalPlatform = process.platform;

beforeEach(async () => {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "catalog-install-watcher-test-"));
  Object.defineProperty(process, "platform", { value: "darwin" });
  getInteractiveUserFromOs.mockReset();
  vi.resetModules();
  ({ consumePendingCatalogInstallRequest } = await import(
    "../../src/status/catalog-install-request-watcher"
  ));
});

afterEach(() => {
  fs.rmSync(tmpHome, { recursive: true, force: true });
  Object.defineProperty(process, "platform", { value: originalPlatform });
});

describe("consumePendingCatalogInstallRequest", () => {
  it("returns null when no request file exists", async () => {
    await expect(consumePendingCatalogInstallRequest()).resolves.toBeNull();
  });

  it("reads a fresh request and returns its packageId", async () => {
    writeRequestFile({ packageId: "42", requestedAtUtc: new Date().toISOString() });

    const result = await consumePendingCatalogInstallRequest();

    expect(result).toEqual({ packageId: "42" });
  });

  it("deletes the file after reading (consume-once)", async () => {
    writeRequestFile({ packageId: "42", requestedAtUtc: new Date().toISOString() });

    await consumePendingCatalogInstallRequest();

    expect(fs.existsSync(requestFilePath())).toBe(false);
  });

  it("a second tick after consuming sees nothing", async () => {
    writeRequestFile({ packageId: "42", requestedAtUtc: new Date().toISOString() });

    await consumePendingCatalogInstallRequest();
    const second = await consumePendingCatalogInstallRequest();

    expect(second).toBeNull();
  });

  it("ignores a request older than the staleness window", async () => {
    const staleTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    writeRequestFile({ packageId: "42", requestedAtUtc: staleTimestamp });

    const result = await consumePendingCatalogInstallRequest();

    expect(result).toBeNull();
  });

  it("still consumes (deletes) a stale request so it can't be re-read", async () => {
    const staleTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    writeRequestFile({ packageId: "42", requestedAtUtc: staleTimestamp });

    await consumePendingCatalogInstallRequest();

    expect(fs.existsSync(requestFilePath())).toBe(false);
  });

  it("ignores malformed JSON without throwing", async () => {
    const filePath = requestFilePath();
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, "{not valid json", "utf8");

    await expect(consumePendingCatalogInstallRequest()).resolves.toBeNull();
  });

  it("ignores a request with a missing/blank packageId", async () => {
    writeRequestFile({ packageId: "", requestedAtUtc: new Date().toISOString() });

    await expect(consumePendingCatalogInstallRequest()).resolves.toBeNull();
  });

  it("returns null on Linux without touching the filesystem (only darwin/win32 are supported)", async () => {
    Object.defineProperty(process, "platform", { value: "linux" });
    writeRequestFile({ packageId: "42", requestedAtUtc: new Date().toISOString() });

    const result = await consumePendingCatalogInstallRequest();

    expect(result).toBeNull();
    expect(fs.existsSync(requestFilePath())).toBe(true);
  });
});

describe("consumePendingCatalogInstallRequest — Windows", () => {
  beforeEach(() => {
    Object.defineProperty(process, "platform", { value: "win32" });
  });

  // Repeated vi.spyOn(fs, ...) calls across tests in this block would
  // otherwise reuse the same spy (and its accumulated call count) —
  // restore after every test so each one starts from a clean fs.
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns null and does not touch the filesystem when no interactive user is found", async () => {
    getInteractiveUserFromOs.mockResolvedValue(null);
    const readSpy = vi.spyOn(fs, "readFileSync");

    const result = await consumePendingCatalogInstallRequest();

    expect(result).toBeNull();
    expect(readSpy).not.toHaveBeenCalled();
  });

  it("reads from a path built from the resolved user's AppData\\Local\\Tracenium", async () => {
    getInteractiveUserFromOs.mockResolvedValue({ user: "jdoe" });
    const readSpy = vi
      .spyOn(fs, "readFileSync")
      .mockReturnValue(JSON.stringify({ packageId: "42", requestedAtUtc: new Date().toISOString() }));
    vi.spyOn(fs, "unlinkSync").mockImplementation(() => {});

    const result = await consumePendingCatalogInstallRequest();

    expect(result).toEqual({ packageId: "42" });
    const calledPath = String(readSpy.mock.calls[0][0]);
    expect(calledPath).toContain("jdoe");
    expect(calledPath).toContain("AppData");
    expect(calledPath).toContain("Local");
    expect(calledPath).toContain("Tracenium");
    expect(calledPath).toContain("catalog-install-request.json");
  });

  it("consumes (deletes) the file it read from", async () => {
    getInteractiveUserFromOs.mockResolvedValue({ user: "jdoe" });
    vi.spyOn(fs, "readFileSync").mockReturnValue(
      JSON.stringify({ packageId: "42", requestedAtUtc: new Date().toISOString() })
    );
    const unlinkSpy = vi.spyOn(fs, "unlinkSync").mockImplementation(() => {});

    await consumePendingCatalogInstallRequest();

    expect(unlinkSpy).toHaveBeenCalledTimes(1);
  });

  it("caches the resolved user for repeated ticks instead of re-resolving every time", async () => {
    getInteractiveUserFromOs.mockResolvedValue({ user: "jdoe" });
    vi.spyOn(fs, "readFileSync").mockImplementation(() => {
      throw new Error("ENOENT");
    });

    await consumePendingCatalogInstallRequest();
    await consumePendingCatalogInstallRequest();
    await consumePendingCatalogInstallRequest();

    expect(getInteractiveUserFromOs).toHaveBeenCalledTimes(1);
  });

  it("re-resolves once the cache TTL has passed", async () => {
    vi.useFakeTimers();
    try {
      getInteractiveUserFromOs.mockResolvedValue({ user: "jdoe" });
      vi.spyOn(fs, "readFileSync").mockImplementation(() => {
        throw new Error("ENOENT");
      });

      await consumePendingCatalogInstallRequest();
      vi.advanceTimersByTime(61_000);
      await consumePendingCatalogInstallRequest();

      expect(getInteractiveUserFromOs).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
});
