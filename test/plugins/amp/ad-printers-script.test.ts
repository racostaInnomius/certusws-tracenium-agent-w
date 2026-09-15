// test/plugins/amp/ad-printers-script.test.ts
//
// ADR-0023 — las reglas de Scripts/ad-printers.ps1, sobre el fichero, y su
// recorrido real con `pwsh` si está instalado:
//   · nada de cargadores codificados (AMSI bloqueó uno en el spike de ADR-0022);
//   · SÓLO LECTURA: lo único que escribe es la salida que pide privsvc;
//   · los parámetros son los que construye AdPrintersShape.PowerShellArguments;
//   · ⚠️ ninguna variable repetida con otra caja: en el spike, `$r` del bucle
//     ERA `$R` (el informe) y lo sobrescribió entero;
//   · un fallo sale en `error`, nunca como lista vacía sin motivo.

import { describe, it, expect } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { spawnSync } from "child_process";

const ROOT = path.resolve(__dirname, "../../..");
const SCRIPT = path.join(ROOT, "privsvc/windows/Tracenium.PrivSvc.Windows/Scripts/ad-printers.ps1");
const src = fs.readFileSync(SCRIPT, "utf8");
const code = src.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
const hasPwsh = spawnSync("pwsh", ["-NoProfile", "-Command", "exit 0"], { encoding: "utf8" }).status === 0;

/** Mete código de prueba DESPUÉS del bloque param(): delante, PowerShell no ejecuta el script. */
function withFakes(fakes: string, scriptText: string): string {
  const anchor = "$ErrorActionPreference = 'Stop'";
  const i = scriptText.indexOf(anchor);
  if (i < 0) throw new Error("anchor not found");
  return scriptText.slice(0, i) + fakes + "\n" + scriptText.slice(i);
}

function runScript(scriptText: string): any {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "adp-"));
  const file = path.join(dir, "s.ps1");
  const out = path.join(dir, "out.json");
  fs.writeFileSync(file, scriptText);
  // cwd en el temporal: un script roto que escriba con una ruta relativa no puede
  // dejar ficheros en el repo (pasó una vez con uno llamado `100000`).
  spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-File", file, "-OutputPath", out, "-BudgetMs", "20000"], { encoding: "utf8", cwd: dir });
  const json = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, "utf8")) : null;
  fs.rmSync(dir, { recursive: true, force: true });
  return json;
}

describe("ad-printers.ps1 — reglas estáticas", () => {
  it("⭐ ningún cargador codificado ni evaluación de texto", () => {
    for (const banned of [/Invoke-Expression/i, /\biex\b/i, /EncodedCommand/i, /FromBase64String/i, /\bAdd-Type\b/i, /\[scriptblock\]::Create/i, /Start-Process/i, /Invoke-WebRequest|Net\.WebClient/i]) {
      expect(code, String(banned)).not.toMatch(banned);
    }
  });

  it("⭐ sólo lectura: nada escribe en AD, y el único fichero es la salida", () => {
    for (const banned of [/\.CommitChanges\(/i, /\.SetInfo\(/i, /\.Put\(/i, /\.DeleteTree\(/i, /\b(Set|New|Remove)-AD\w+/i, /\bSet-ItemProperty\b/i, /\bRemove-Item\b/i]) {
      expect(code, String(banned)).not.toMatch(banned);
    }
    expect(code.match(/WriteAllText\(/g)).toHaveLength(1);
    expect(code).toContain("WriteAllText($OutputPath");
  });

  it("los parámetros casan con los que construye AdPrintersShape", () => {
    const shape = fs.readFileSync(path.join(ROOT, "privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AdPrintersShape.cs"), "utf8");
    expect(shape).toContain('-OutputPath \\"{outputPath}\\" -BudgetMs {budgetMs}');
    expect(code).toMatch(/\[string\]\$OutputPath/);
    expect(code).toMatch(/\[int\]\$BudgetMs/);
  });

  it("⚠️ ninguna variable con dos cajas (PowerShell no distingue mayúsculas)", () => {
    const byLower = new Map<string, Set<string>>();
    for (const m of code.matchAll(/\$([A-Za-z_][A-Za-z0-9_]*)/g)) {
      const k = m[1].toLowerCase();
      if (!byLower.has(k)) byLower.set(k, new Set());
      byLower.get(k)!.add(m[1]);
    }
    for (const [k, spellings] of byLower) expect([...spellings], k).toHaveLength(1);
  });

  it("funciones con prefijo Adp (un alias integrado gana a una función)", () => {
    const names = [...code.matchAll(/^\s*function\s+([A-Za-z0-9_-]+)/gm)].map((m) => m[1]);
    expect(names.length).toBeGreaterThan(0);
    for (const n of names) expect(n, n).toMatch(/^Adp[A-Z]/);
  });
});

describe.skipIf(!hasPwsh)("ad-printers.ps1 — con pwsh", () => {
  it("⚠️ sin Windows ni AD, el fallo sale en `error` y el JSON existe igualmente", () => {
    const r = runScript(src);
    expect(r).not.toBeNull();
    expect(r.collector).toBe("ad-printers/1");
    expect(typeof r.error).toBe("string");
    expect(r.error.length).toBeGreaterThan(0);
  });

  it("⭐ con un AD simulado devuelve la forma que el backend espera (spike de T111)", () => {
    const fakes = `
function Get-CimInstance { [pscustomobject]@{ PartOfDomain = $true; Domain = 'mountainside-investment.com' } }
function New-AdpFakeHit($h) { $bag = @{}; foreach ($k in $h.Keys) { $bag[$k] = @($h[$k]) }; [pscustomobject]@{ Properties = $bag } }
`;
    const sim = src
      .replace("New-Object System.DirectoryServices.DirectoryEntry(\"LDAP://$($computer.Domain)/RootDSE\")",
        () => "[pscustomobject]@{ defaultNamingContext = [pscustomobject]@{ Value = 'DC=mountainside-investment,DC=com' }; dnsHostName = [pscustomobject]@{ Value = 'MSIG-DOMAIN01.mountainside-investment.com' } }")
      .replace("$searcher = New-Object System.DirectoryServices.DirectorySearcher",
        () => "$searcher = [pscustomobject]@{ SearchRoot = $null; Filter = $null; PageSize = 0; ServerTimeLimit = $null; ClientTimeout = $null; PropertiesToLoad = (New-Object System.Collections.Generic.List[string]) }")
      .replace("$searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(\"LDAP://$($computer.Domain)/$namingContext\")", () => "")
      .replace("$searcher.PropertiesToLoad.AddRange([string[]]$attributes) | Out-Null", () => "$searcher.PropertiesToLoad.AddRange([string[]]$attributes)")
      .replace("foreach ($hit in $searcher.FindAll())",
        () => "foreach ($hit in @((New-AdpFakeHit @{ printername = 'PrintRoomH2O'; shortservername = 'MSIG-WSUS'; printsharename = 'PrintRooH20'; drivername = 'HP Color LaserJet Pro M478f-9f PCL-6 (V4)'; location = 'Printing room'; portname = @('IP_10.100.17.74'); printcolor = $true; whenchanged = [DateTime]'2026-08-12T19:24:02Z' }), (New-AdpFakeHit @{ printername = 'HP452Marketing'; shortservername = 'MSIG-WSUS'; portname = @('10.100.25.20', 'IP_10.100.19.138') })))");
    expect(sim).not.toBe(src);
    const r = runScript(withFakes(fakes, sim));
    expect(r.error).toBeNull();
    expect(r).toMatchObject({ partOfDomain: true, domain: "mountainside-investment.com", dcUsed: "MSIG-DOMAIN01.mountainside-investment.com" });
    expect(r.queues).toHaveLength(2);
    expect(r.queues[0]).toMatchObject({ printerName: "PrintRoomH2O", shareName: "PrintRooH20", portNames: ["IP_10.100.17.74"], color: true });
    expect(Date.parse(r.queues[0].whenChanged)).toBe(Date.parse("2026-08-12T19:24:02Z"));
    // Un solo puerto sigue siendo LISTA, y dos también.
    expect(r.queues[1].portNames).toEqual(["10.100.25.20", "IP_10.100.19.138"]);
  });

  it("un equipo fuera de dominio lo dice (partOfDomain=false), sin lista inventada", () => {
    const r = runScript(withFakes("function Get-CimInstance { [pscustomobject]@{ PartOfDomain = $false; Domain = 'WORKGROUP' } }", src));
    expect(r).toMatchObject({ partOfDomain: false, domain: null, queues: [] });
  });
});
