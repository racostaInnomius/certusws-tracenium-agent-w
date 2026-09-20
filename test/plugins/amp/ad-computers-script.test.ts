// test/plugins/amp/ad-computers-script.test.ts
//
// Cobertura — las reglas de Scripts/ad-computers.ps1, sobre el fichero, y su
// recorrido real con `pwsh` si está instalado. Mismas reglas que el lector de
// impresoras (ad-printers-script.test.ts), más las dos conversiones que sólo se
// pueden comprobar ejecutándolo:
//   · objectGUID llega como byte[16] y tiene que salir como GUID de texto;
//   · lastLogonTimestamp y pwdLastSet son FILETIME de 64 bits, y el 0 significa
//     «nunca», no una fecha de 1601.

import { describe, it, expect } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { spawnSync } from "child_process";

const ROOT = path.resolve(__dirname, "../../..");
const SCRIPT = path.join(ROOT, "privsvc/windows/Tracenium.PrivSvc.Windows/Scripts/ad-computers.ps1");
const src = fs.readFileSync(SCRIPT, "utf8");
const code = src.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
const hasPwsh = spawnSync("pwsh", ["-NoProfile", "-Command", "exit 0"], { encoding: "utf8" }).status === 0;

function withFakes(fakes: string, scriptText: string): string {
  const anchor = "$ErrorActionPreference = 'Stop'";
  const i = scriptText.indexOf(anchor);
  if (i < 0) throw new Error("anchor not found");
  return scriptText.slice(0, i) + fakes + "\n" + scriptText.slice(i);
}

function runScript(scriptText: string): any {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "adc-"));
  const file = path.join(dir, "s.ps1");
  const out = path.join(dir, "out.json");
  fs.writeFileSync(file, scriptText);
  spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-File", file, "-OutputPath", out, "-BudgetMs", "20000"], { encoding: "utf8", cwd: dir });
  const json = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, "utf8")) : null;
  fs.rmSync(dir, { recursive: true, force: true });
  return json;
}

describe("ad-computers.ps1 — reglas estáticas", () => {
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

  it("los parámetros casan con los que construye AdComputersShape", () => {
    const shape = fs.readFileSync(path.join(ROOT, "privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AdComputersShape.cs"), "utf8");
    expect(shape).toContain('-OutputPath \\"{outputPath}\\" -BudgetMs {budgetMs} -MaxComputers {MaxComputers}');
    expect(code).toMatch(/\[string\]\$OutputPath/);
    expect(code).toMatch(/\[int\]\$BudgetMs/);
    expect(code).toMatch(/\[int\]\$MaxComputers/);
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

  it("funciones con prefijo Adc (un alias integrado gana a una función)", () => {
    const names = [...code.matchAll(/^\s*function\s+([A-Za-z0-9_-]+)/gm)].map((m) => m[1]);
    expect(names.length).toBeGreaterThan(0);
    for (const n of names) expect(n, n).toMatch(/^Adc[A-Z]/);
  });
});

const FAKES = `
function Get-CimInstance { [pscustomobject]@{ PartOfDomain = $true; Domain = 'mountainside-investment.com' } }
function New-AdcFakeHit($h) {
  $bag = @{}
  foreach ($k in $h.Keys) {
    $v = $h[$k]
    # El GUID es un byte[16] y tiene que seguir siéndolo dentro del bolsa de
    # propiedades: @() lo desharía en 16 elementos.
    if ($v -is [byte[]]) { $bag[$k] = ,$v } else { $bag[$k] = @($v) }
  }
  [pscustomobject]@{ Properties = $bag }
}
`;

/** Sustituye AD por una lista de objetos falsos. */
function simulate(hits: string): string {
  const sim = src
    .replace("New-Object System.DirectoryServices.DirectoryEntry(\"LDAP://$($computer.Domain)/RootDSE\")",
      () => "[pscustomobject]@{ defaultNamingContext = [pscustomobject]@{ Value = 'DC=mountainside-investment,DC=com' }; dnsHostName = [pscustomobject]@{ Value = 'MSIG-DOMAIN01.mountainside-investment.com' } }")
    .replace("$searcher = New-Object System.DirectoryServices.DirectorySearcher",
      () => "$searcher = [pscustomobject]@{ SearchRoot = $null; Filter = $null; PageSize = 0; ServerTimeLimit = $null; ClientTimeout = $null; PropertiesToLoad = (New-Object System.Collections.Generic.List[string]) }")
    .replace("$searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(\"LDAP://$($computer.Domain)/$namingContext\")", () => "")
    .replace("$searcher.PropertiesToLoad.AddRange([string[]]$attributes) | Out-Null", () => "$searcher.PropertiesToLoad.AddRange([string[]]$attributes)")
    .replace("foreach ($hit in $searcher.FindAll())", () => `foreach ($hit in @(${hits}))`);
  if (sim === src) throw new Error("la simulación no sustituyó nada");
  return withFakes(FAKES, sim);
}

const GUID_BYTES = "[byte[]](0xD4,0xC3,0xB2,0xA1,0x11,0x11,0x22,0x22,0x33,0x33,0x44,0x44,0x55,0x55,0x66,0x66)";

describe.skipIf(!hasPwsh)("ad-computers.ps1 — con pwsh", () => {
  it("⚠️ sin Windows ni AD, el fallo sale en `error` y el JSON existe igualmente", () => {
    const r = runScript(src);
    expect(r).not.toBeNull();
    expect(r.collector).toBe("ad-computers/1");
    expect(typeof r.error).toBe("string");
    expect(r.error.length).toBeGreaterThan(0);
    expect(r.computers).toEqual([]);
  });

  it("⭐ el GUID sale como texto y las dos fechas como ISO; el 0 de AD es «nunca»", () => {
    const hits = `
      (New-AdcFakeHit @{ objectguid = ${GUID_BYTES}; name = 'MSIG-FINAN6'; dnshostname = 'MSIG-Finan6.mountainside-investment.com';
        operatingsystem = 'Windows 11 Pro'; operatingsystemversion = '10.0 (26100)';
        lastlogontimestamp = [DateTime]::Parse('2026-09-01T10:00:00Z').ToFileTimeUtc();
        pwdlastset = [DateTime]::Parse('2026-09-10T08:30:00Z').ToFileTimeUtc();
        whencreated = [DateTime]'2024-02-01T09:00:00Z'; useraccountcontrol = 4096 }),
      (New-AdcFakeHit @{ objectguid = ${GUID_BYTES.replace("0xD4", "0xAA")}; name = 'MSIG-NUEVO'; lastlogontimestamp = 0; pwdlastset = 0; useraccountcontrol = 4098 })`;
    const r = runScript(simulate(hits));
    expect(r.error).toBeNull();
    expect(r).toMatchObject({ partOfDomain: true, domain: "mountainside-investment.com", dcUsed: "MSIG-DOMAIN01.mountainside-investment.com", truncated: false });
    expect(r.computers).toHaveLength(2);
    expect(r.computers[0]).toMatchObject({
      objectGuid: "a1b2c3d4-1111-2222-3333-444455556666",
      name: "MSIG-FINAN6",
      dnsHostName: "MSIG-Finan6.mountainside-investment.com",
      operatingSystem: "Windows 11 Pro",
      userAccountControl: 4096,
    });
    expect(Date.parse(r.computers[0].lastLogonUtc)).toBe(Date.parse("2026-09-01T10:00:00Z"));
    expect(Date.parse(r.computers[0].passwordLastSetUtc)).toBe(Date.parse("2026-09-10T08:30:00Z"));
    expect(Date.parse(r.computers[0].whenCreatedUtc)).toBe(Date.parse("2024-02-01T09:00:00Z"));
    // «Nunca» es ausencia, no una fecha de 1601 que haría parecer muertísimo a
    // un equipo recién creado.
    expect(r.computers[1].lastLogonUtc).toBeNull();
    expect(r.computers[1].passwordLastSetUtc).toBeNull();
  });

  it("⚠️ un objeto sin GUID no se manda: no sabríamos de quién habla", () => {
    const r = runScript(simulate(`(New-AdcFakeHit @{ name = 'SIN-GUID' }), (New-AdcFakeHit @{ objectguid = ${GUID_BYTES}; name = 'CON-GUID' })`));
    expect(r.computers).toHaveLength(1);
    expect(r.computers[0].name).toBe("CON-GUID");
  });

  it("un equipo fuera de dominio lo dice (partOfDomain=false), sin lista inventada", () => {
    const r = runScript(withFakes("function Get-CimInstance { [pscustomobject]@{ PartOfDomain = $false; Domain = 'WORKGROUP' } }", src));
    expect(r).toMatchObject({ partOfDomain: false, domain: null, computers: [] });
  });
});
