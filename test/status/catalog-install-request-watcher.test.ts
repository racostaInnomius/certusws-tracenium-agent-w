// test/status/catalog-install-request-watcher.test.ts
//
// Coverage for the tray -> core channel that lets the Software Catalog
// tab's "Install" button reach the control plane: the tray writes
// catalog-install-request.json into its own Application Support
// directory, and this module (polled from grpc-stream.ts) reads +
// consumes it.
//
// Mocks geo.ts's parseConsoleUser/resolveHomeDirectory (the only two
// exports this module uses from it) rather than child_process directly
// — that keeps this suite focused on the file-handling contract
// (consume-once, staleness, malformed input) instead of re-testing
// console-user resolution, which geo.test.ts already owns.

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

  it("returns null on non-macOS platforms without touching the filesystem", async () => {
    Object.defineProperty(process, "platform", { value: "win32" });
    writeRequestFile({ packageId: "42", requestedAtUtc: new Date().toISOString() });

    const result = await consumePendingCatalogInstallRequest();

    expect(result).toBeNull();
    // File untouched — the win32 path returns before ever resolving a
    // console user, so a stray macOS-shaped file left on a Windows box
    // (shouldn't happen, but) is not silently consumed.
    expect(fs.existsSync(requestFilePath())).toBe(true);
  });
});
