// test/privsvc/patch-ps-encoding.test.ts
//
// 🔴 Texto con acentos roto en Windows en español: «2026-09 Actualizaci¢n de
// seguridad (KB5129195)» — 3 de 13 títulos de parches en T1 el 28-sep; lo mismo
// en valores de compliance y nombres de apps de la Store. PowerShell escribía la
// salida redirigida en la página OEM (CP850: «ó» = 0xA2) y .NET la leía como
// ANSI 1252 (0xA2 = «¢»).
//
// ⚠️ Esto lee el C# de verdad: el comportamiento sólo se reproduce en un Windows
// con locale no inglés. pwsh en el Mac ya escribe UTF-8 por defecto, así que un
// test que lo ejecute aquí daría un falso verde.

import { describe, expect, it } from "vitest";
import fs from "fs";
import path from "path";

const IPC = path.join(__dirname, "..", "..", "privsvc/windows/Tracenium.PrivSvc.Windows/Ipc");
const read = (f: string) => fs.readFileSync(path.join(IPC, f), "utf8");
const HELPER = read("PowerShellUtf8.cs");

function constValue(name: string): string {
  const m = new RegExp(`const string ${name} =\\s*"((?:[^"\\\\]|\\\\.)*)"`).exec(HELPER);
  expect(m, name).not.toBeNull();
  return m![1];
}

describe("PowerShellUtf8 — el helper", () => {
  const set = constValue("SetOutputEncoding");

  it("⭐ PowerShell escribe UTF-8 SIN BOM, y el cambio no puede tumbar el script", () => {
    expect(set).toMatch(/^try \{ \[Console\]::OutputEncoding = New-Object System\.Text\.UTF8Encoding \$false \} catch \{\}$/);
    expect(/^[\x20-\x7e]*$/.test(set)).toBe(true); // PS 5.1 lee sin BOM como ANSI
  });

  it("⭐ .NET lee stdout y stderr como UTF-8 SIN BOM", () => {
    expect(HELPER).toMatch(/StandardOutputEncoding = new UTF8Encoding\(false\)/);
    expect(HELPER).toMatch(/StandardErrorEncoding = new UTF8Encoding\(false\)/);
  });

  it("los dos preámbulos: en su línea (script) y en línea con `;` (-Command)", () => {
    expect(HELPER).toMatch(/Prelude = SetOutputEncoding \+ "\\n";/);
    expect(HELPER).toMatch(/InlinePrelude = SetOutputEncoding \+ "; ";/);
  });
});

// Los tres sitios que lanzan powershell y leen su salida. Uno nuevo que se
// olvide de pasar por aquí vuelve a traer «Actualizaci¢n».
describe.each([
  ["PatchManagement.cs", "private static PsResult RunPs(", "Prelude"],
  ["SecurityCompliance.cs", "private static PsResult RunPsWithTimeout(", "Prelude"],
  ["SoftwareInventory.cs", 'var ps = "powershell";', "InlinePrelude"],
])("%s", (file, anchor, prelude) => {
  const cs = read(file);
  const start = cs.indexOf(anchor);
  const body = cs.slice(start, start + 4000);

  it("⭐ antepone el preámbulo y lee la salida como UTF-8", () => {
    expect(start).toBeGreaterThan(-1);
    expect(body).toContain(`PowerShellUtf8.${prelude} +`);
    expect(body).toMatch(/\}\.ReadAsUtf8\(\)/);
  });

  it("ningún script abre con param(): el preámbulo lo rompería", () => {
    expect(cs).not.toMatch(/RunPs(?:WithTimeout)?\(\s*\$?@?"\s*(param\s*\(|\[CmdletBinding)/i);
  });
});
