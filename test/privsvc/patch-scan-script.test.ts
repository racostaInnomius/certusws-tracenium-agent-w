// test/privsvc/patch-scan-script.test.ts
//
// 🔴 Auditoría PMP 1-oct-2026. El escaneo de Windows hacía
// `$result = $searcher.Search(…)` sin atrapar nada. En PowerShell 5.1 una
// excepción COM sólo termina la SENTENCIA: el script seguía con $result a null,
// 0 items, y con un catálogo sincronizado hace poco eso es exactamente
// 'healthy'. Un WSUS caído o el servicio de Windows Update desactivado salía
// en el portal como un equipo al día.
//
// Se corre el script REAL (extraído del .cs) con pwsh contra COM simulado.
// ⚠️ pwsh 7 en el Mac; producción es PS 5.1 — try/catch atrapa la excepción de
// un método igual en los dos.

import { beforeAll, describe, expect, it } from "vitest";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { extractBlocks, hasPwsh } from "./embedded-powershell";

const HARNESS = path.resolve(__dirname, "fixtures/wua-scan-harness.ps1");
let scriptPath = "";

beforeAll(() => {
  const scan = extractBlocks().find((b) => b.file === "PatchManagement.cs" && !b.interpolated);
  if (!scan) throw new Error("scan script not found in PatchManagement.cs");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "privsvc-patch-scan-"));
  scriptPath = path.join(dir, "patch-scan.ps1");
  fs.writeFileSync(scriptPath, scan.body, "utf8");
});

function run(scenario: string): { status: string; note: string | null; updateCount: number } {
  const out = execFileSync("pwsh", ["-NoProfile", "-File", HARNESS, "-Scenario", scenario, "-ScriptPath", scriptPath], {
    encoding: "utf8",
  });
  return JSON.parse(out);
}

const pwsh = hasPwsh();

describe.skipIf(!pwsh)("Windows patch.scan script", () => {
  it("catálogo reciente y nada pendiente → healthy, sin nota", () => {
    expect(run("clean")).toMatchObject({ status: "healthy", note: null, updateCount: 0 });
  });

  it("🔴 Search() que lanza → 'unknown' con el HRESULT en la nota, NUNCA healthy", () => {
    const r = run("search-throws");
    expect(r.status).toBe("unknown");
    expect(r.note).toMatch(/^Windows Update search failed \(0x8024401c\)/);
  });
});
