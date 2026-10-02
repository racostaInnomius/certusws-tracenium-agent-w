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
  fatalStage?: string | null;
  hresult?: string | null;
  scenario: string;
  calls: string[];
  status: string;
  installedCount: number;
  failedCount: number;
  rebootRequired: boolean;
  results: string[];
}

let scriptPath = "";
/** El MISMO script, con la lista de KBs vacía: `$targetKbs = @()`. */
let scriptSinLista = "";

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

  let vacio = install.body;
  vacio = vacio.replace(HOLE, "'install'");
  vacio = vacio.replace(HOLE, "");
  scriptSinLista = path.join(dir, "patch-install-sin-lista.ps1");
  fs.writeFileSync(scriptSinLista, vacio, "utf8");
});

function run(scenario: string, script = scriptPath): Report {
  const out = execFileSync(
    "pwsh",
    ["-NoProfile", "-File", HARNESS, "-Scenario", scenario, "-ScriptPath", script],
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

    // 1-oct-2026: ni siquiera descarga — antes bajaba hasta 60 min para nada.
    expect(r.calls).toEqual([]);
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

  it("🔴 con la lista VACÍA no selecciona NADA — antes seleccionaba TODO", () => {
    // El 8-sep-2026 un job con `kbArticleIds: []` instaló 3 actualizaciones que
    // nadie había elegido: el script leía «sin lista» como «todo». Ahora el
    // handler rechaza la lista vacía antes de llegar aquí, y el script, además,
    // ya no puede instalar lo que nadie pidió aunque lo llame otro camino.
    const r = run("all-ok", scriptSinLista);
    expect(r.calls).toEqual([]); // ni descarga ni instalación
    expect(r.installedCount).toBe(0);
  });

  // ── Auditoría 1-oct-2026: las excepciones de WUA no se tragan ─────────────
  // En PS 5.1 una excepción COM termina la sentencia, no el script: seguía con
  // $searchResult a null y decía «no_updates», o «not_started 0x0».
  it("🔴 Search() que lanza (servicio desactivado) → failed con la fase y el HRESULT, no no_updates", () => {
    const r = run("search-throws");
    expect(r.calls).toEqual([]);
    expect(r).toMatchObject({ status: "failed", fatalStage: "search", hresult: "0x80070422", failedCount: 3 });
    expect(r.results[0]).toBe("KB5066747 failed 0x80070422 search_failed");
  });

  it("🔴 Download() que lanza (disco lleno) → failed en 'download' con 0x80070070, sin instalar", () => {
    const r = run("download-throws");
    expect(r.calls).toEqual(["Download"]);
    expect(r).toMatchObject({ status: "failed", fatalStage: "download", hresult: "0x80070070", installedCount: 0 });
  });

  it("🔴 Install() que lanza (otra instalación en curso) → failed en 'install' con 0x80240016", () => {
    const r = run("install-throws");
    expect(r).toMatchObject({ status: "failed", fatalStage: "install", hresult: "0x80240016" });
    expect(r.results.every((l) => l.includes("0x80240016 install_failed"))).toBe(true);
  });

  it("instalador ocupado → ni lo llama: failed en 'install' con 0x80240016", () => {
    const r = run("installer-busy");
    expect(r.calls).toEqual(["Download"]);
    expect(r).toMatchObject({ status: "failed", fatalStage: "install", hresult: "0x80240016" });
  });
});

