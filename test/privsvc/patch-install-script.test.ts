// test/privsvc/patch-install-script.test.ts
//
// Runs the Windows patch-install script against fake WUA objects.
//
// PRODUCTION FAILURE THIS REPRODUCES (DESKTOP-M8GJ0V5, tenant 111,
// 2026-09-04, job 704da2b6): KB5066747 came back `failed` with HRESULT
// 0x80246007 — WU_E_DM_NOTDOWNLOADED, "the update has not been downloaded".
// True, and useless: the script had run the download phase, recorded that
// the download failed, then rebuilt `$results` from scratch for the install
// phase and handed the undownloaded update to the installer anyway. The
// download's own HRESULT — the actual reason — was gone.
//
// The install phase now runs only on what came down; anything else keeps
// its download verdict. Nothing on the agent side changes shape: the
// `results[]` entries are the same fields, just truthful.
//
// Needs pwsh (PowerShell 7). CI has it; a local machine without it skips
// loudly, same as powershell-scripts-parse.test.ts.

import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { extractBlocks, hasPwsh, HOLE } from "./embedded-powershell";

const HARNESS = path.resolve(__dirname, "fixtures/wua-fake-harness.ps1");

interface Report {
  scenario: string;
  calls: string[];
  status: string;
  installedCount: number;
  failedCount: number;
  rebootRequired: boolean;
  results: string[];
}

let scriptPath = "";

beforeAll(() => {
  const install = extractBlocks().find((b) => b.file === "PatchManagement.cs" && b.interpolated);
  if (!install) throw new Error("interpolated PatchManagement script not found");

  // The two interpolation holes, in order: `$mode = {modeJson}` and the KB
  // list. Fill them the way HandleInstall does for an install of three KBs.
  let body = install.body;
  body = body.replace(HOLE, "'install'");
  body = body.replace(HOLE, "'KB5066747','KB5120708','KB5121003'");
  expect(body.includes(HOLE), "unexpected extra interpolation hole").toBe(false);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "privsvc-patch-install-"));
  scriptPath = path.join(dir, "patch-install.ps1");
  fs.writeFileSync(scriptPath, body, "utf8");
});

function run(scenario: string): Report {
  const out = execFileSync(
    "pwsh",
    ["-NoProfile", "-File", HARNESS, "-Scenario", scenario, "-ScriptPath", scriptPath],
    { encoding: "utf8" }
  );
  return JSON.parse(out) as Report;
}

const pwsh = hasPwsh();
if (!pwsh) {
  console.warn("[skip] pwsh not installed — patch-install script behaviour NOT verified on this machine");
}

describe.skipIf(!pwsh)("Windows patch.install script", () => {
  it("⭐ keeps the download HRESULT for what never came down, and installs only the rest", () => {
    const r = run("mixed");

    // The installer received exactly the two downloaded updates.
    expect(r.calls).toEqual(["Download", "Install:KB5120708,KB5121003"]);

    // KB5066747 carries the DOWNLOAD verdict — not 0x80246007 from an
    // installer that was never going to accept it.
    expect(r.results).toEqual([
      "KB5066747 failed 0x80244022 download_failed:failed",
      "KB5120708 installed 0x0 succeeded",
      "KB5121003 failed 0x80070643 failed"
    ]);
    expect(r).toMatchObject({ status: "partial", installedCount: 1, failedCount: 2, rebootRequired: true });
  });

  it("does not call the installer at all when WUA says a reboot is pending", () => {
    const r = run("reboot-pending");

    expect(r.calls).toEqual(["Download"]);
    expect(r.results.every((line) => line.endsWith("skipped  reboot_pending_before_install"))).toBe(true);
    expect(r).toMatchObject({ status: "failed", installedCount: 0, failedCount: 3, rebootRequired: true });
  });

  it("reports success when everything downloads and installs", () => {
    const r = run("all-ok");

    expect(r.calls).toEqual(["Download", "Install:KB5066747,KB5120708,KB5121003"]);
    expect(r).toMatchObject({ status: "success", installedCount: 3, failedCount: 0 });
    // ResultCode by name, not the bare number the operator used to get.
    expect(r.results[2]).toBe("KB5121003 installed 0x0 succeeded_with_errors");
  });
});
