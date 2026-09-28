// test/privsvc/patch-ps-encoding.test.ts
//
// 🔴 Títulos de parches rotos en Windows en español: «2026-09 Actualizaci¢n de
// seguridad (KB5129195)» — 3 de 13 en T1 el 28-sep. PowerShell escribía la
// salida redirigida en la página OEM (CP850: «ó» = 0xA2) y .NET la leía como
// ANSI 1252 (0xA2 = «¢»).
//
// ⚠️ Esto lee el C# de verdad: el comportamiento sólo se reproduce en un Windows
// con locale no inglés. pwsh en el Mac ya escribe UTF-8 por defecto, así que un
// test que lo ejecute aquí daría un falso verde.

import { describe, expect, it } from "vitest";
import fs from "fs";
import path from "path";

const CS = fs.readFileSync(
  path.join(__dirname, "..", "..", "privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/PatchManagement.cs"),
  "utf8"
);

function runPsBody(): string {
  const start = CS.indexOf("private static PsResult RunPs(");
  expect(start).toBeGreaterThan(-1);
  return CS.slice(start, CS.indexOf("proc.BeginOutputReadLine", start));
}

function prelude(): string {
  const m = /const string Utf8OutputPrelude =\s*"((?:[^"\\]|\\.)*)";/.exec(CS);
  expect(m, "Utf8OutputPrelude").not.toBeNull();
  return m![1].replace(/\\n/g, "\n");
}

describe("patch.scan / patch.install — UTF-8 en los dos extremos del tubo", () => {
  it("⭐ .NET lee stdout y stderr como UTF-8 SIN BOM", () => {
    const body = runPsBody();
    expect(body).toMatch(/StandardOutputEncoding\s*=\s*new UTF8Encoding\(false\)/);
    expect(body).toMatch(/StandardErrorEncoding\s*=\s*new UTF8Encoding\(false\)/);
  });

  it("⭐ y PowerShell escribe UTF-8: el preámbulo va delante de TODO script", () => {
    const body = runPsBody();
    expect(body).toMatch(/GetBytes\(Utf8OutputPrelude \+ command\)/);
    const p = prelude();
    expect(p).toMatch(/\[Console\]::OutputEncoding\s*=\s*New-Object System\.Text\.UTF8Encoding \$false/);
  });

  it("el preámbulo no puede tumbar el script: va en try, es ASCII y no produce salida", () => {
    const p = prelude();
    expect(p.trim().startsWith("try {")).toBe(true);
    expect(p).toMatch(/catch \{\}\s*$/);
    expect(/^[\x20-\x7e\n]*$/.test(p)).toBe(true); // PS 5.1 lee sin BOM como ANSI
    expect(p.split("\n").some((l) => l.trimStart().startsWith("|"))).toBe(false);
    expect(p).not.toMatch(/Write-|echo |Out-/);
  });

  it("ningún script de PatchManagement abre con param(): el preámbulo lo rompería", () => {
    expect(CS).not.toMatch(/RunPs\(\s*\$?@"\s*param\s*\(/i);
  });
});
