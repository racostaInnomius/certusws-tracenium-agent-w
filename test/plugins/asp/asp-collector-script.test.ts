// test/plugins/asp/asp-collector-script.test.ts
//
// ADR-0022 §Fase 0 — las reglas del colector .ps1, comprobadas sobre el fichero:
//   · nada de cargadores codificados ni evaluación de texto (AMSI bloqueó el
//     spike con `ScriptContainedMaliciousContent`);
//   · SÓLO LECTURA: ninguna llamada que escriba en AD o en el registro;
//   · helpers con prefijo Asp (los alias integrados ganan a las funciones);
//   · ningún alias en el cuerpo — un `gc`/`sl`/`rv` puede significar otra cosa.
// Y, si hay `pwsh` en la máquina, que PARSEA y que el recorrido de E/S produce
// el JSON que el agente espera aunque el directorio no esté disponible.

import { describe, it, expect } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { spawnSync } from "child_process";

const SCRIPT = path.resolve(__dirname, "../../../privsvc/windows/Tracenium.PrivSvc.Windows/Scripts/asp-ad-collector.ps1");
const src = fs.readFileSync(SCRIPT, "utf8");
/** El código sin comentarios de línea: las reglas se escriben EN los comentarios. */
const code = src
  .split("\n")
  .filter((l) => !l.trim().startsWith("#"))
  .join("\n");

const hasPwsh = spawnSync("pwsh", ["-NoProfile", "-Command", "exit 0"], { encoding: "utf8" }).status === 0;

describe("asp-ad-collector.ps1 — reglas estáticas", () => {
  it("⭐ ningún cargador codificado ni evaluación de texto", () => {
    for (const banned of [/Invoke-Expression/i, /\biex\b/i, /EncodedCommand/i, /FromBase64String/i, /\bAdd-Type\b/i, /\[scriptblock\]::Create/i, /Invoke-Command/i, /Start-Process/i, /DownloadString|Invoke-WebRequest|Net\.WebClient/i]) {
      expect(code, String(banned)).not.toMatch(banned);
    }
  });

  it("⭐ sólo lectura: nada que escriba en AD ni en el registro", () => {
    for (const banned of [/\.CommitChanges\(/i, /\.SetInfo\(/i, /\.Put\(/i, /\.DeleteTree\(/i, /\.Rename\(/i, /\.MoveTo\(/i, /\b(Set|New|Remove|Move|Rename|Add)-AD\w+/i, /\bSet-ItemProperty\b/i, /\bNew-ItemProperty\b/i, /\bRemove-ItemProperty\b/i, /\bNew-Item\b/i, /\bRemove-Item\b/i, /\bSet-Acl\b/i, /\bSetAccessRule/i, /\bAddAccessRule/i]) {
      expect(code, String(banned)).not.toMatch(banned);
    }
    // Lo único que escribe: la salida que pide el PrivSvc.
    expect(code.match(/WriteAllText\(/g)).toHaveLength(1);
    expect(code).toContain("WriteAllText($OutputPath");
  });

  it("todas las funciones llevan prefijo Asp", () => {
    const names = [...code.matchAll(/^\s*function\s+([A-Za-z0-9_-]+)/gm)].map((m) => m[1]);
    expect(names.length).toBeGreaterThan(5);
    for (const n of names) expect(n, n).toMatch(/^Asp[A-Z]/);
  });

  it("no usa alias integrados de PowerShell como comandos", () => {
    // Los que un script de AD tendería a escribir; la lista completa de 5.1 es
    // más larga, pero éstos son los que se cuelan.
    const aliases = ["gc", "sl", "rv", "gci", "ls", "dir", "cat", "echo", "gp", "sp", "ni", "ri", "rm", "del", "cd", "cp", "mv", "sls", "iwr", "irm", "gcm", "sv", "gv"];
    for (const a of aliases) {
      const re = new RegExp(`(^|[|;{(]\\s*)${a}\\s`, "m");
      expect(code, a).not.toMatch(re);
    }
    // `foreach` y `where` son también palabras clave del lenguaje; como ALIAS
    // sólo aparecen detrás de una tubería.
    for (const a of ["foreach", "where", "select", "%", "\\?"]) {
      expect(code, a).not.toMatch(new RegExp(`\\|\\s*${a}(\\s|\\{)`, "m"));
    }
  });

  it("los tipos de consulta del script son exactamente los del catálogo", () => {
    const kinds = [...code.matchAll(/^\s*'([a-z_]+)'\s*\{\s*Asp/gm)].map((m) => m[1]).sort();
    expect(kinds).toEqual(["acl", "group_members", "ldap_object", "ldap_search", "registry", "rootdse", "sysvol_files"]);
  });
});

describe.skipIf(!hasPwsh)("asp-ad-collector.ps1 — con pwsh", () => {
  it("parsea sin errores", () => {
    const r = spawnSync(
      "pwsh",
      ["-NoProfile", "-Command", `$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('${SCRIPT}',[ref]$t,[ref]$e);$e.Count`],
      { encoding: "utf8" }
    );
    expect(r.stdout.trim()).toBe("0");
  });

  it("⭐ sin directorio disponible produce el JSON que el agente espera, con el error por consulta", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "asp-ps1-"));
    try {
      const input = path.join(dir, "in.json");
      const output = path.join(dir, "out.json");
      fs.writeFileSync(
        input,
        JSON.stringify({
          runId: "5b1f6a52-8d34-4c41-9a0e-1f6c2d3e4a5b",
          batch: 0,
          evidenceLimit: 200,
          budgetMs: 60000,
          queries: [
            { id: "ASP-AD-KRB-002", query: { kind: "ldap_search", base: "{domainDn}", filter: "(adminCount=1)" } },
            { id: "ASP-AD-DC-001", query: { kind: "registry", path: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters", name: "LDAPServerIntegrity", absentValue: 1 } }
          ]
        })
      );
      const r = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-File", SCRIPT, "-InputPath", input, "-OutputPath", output], { encoding: "utf8", timeout: 60_000 });
      expect(r.status, r.stderr).toBe(0);
      const out = JSON.parse(fs.readFileSync(output, "utf8"));
      // Fuera de un DC no hay contexto de AD: se dice, y cada consulta LDAP
      // lleva ese error en vez de un recuento inventado.
      expect(out.contextError).toBeTruthy();
      expect(out.results["ASP-AD-KRB-002"].ok).toBe(false);
      expect(out.results["ASP-AD-DC-001"]).toHaveProperty("ok");
      expect(typeof out.totalMs).toBe("number");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe.skipIf(!hasPwsh)("asp-ad-collector.ps1 — AspAceHit (qué ACE cuenta como derecho peligroso)", () => {
  // Máscaras de ActiveDirectoryRights.
  const R = { GenericRead: 0x20094, ReadProperty: 0x10, WriteProperty: 0x20, Self: 0x08, ReadControl: 0x20000, ExtendedRight: 0x100, GenericAll: 0xf01ff, WriteDacl: 0x40000 };
  const DCSYNC_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
  const PRV005 = ["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WriteProperty"];
  const PRV006 = ["GenericAll"];

  function run(cases: Array<{ name: string; rights: number; objectType?: string; inheritOnly?: boolean; wanted: string[]; extended?: string[] }>) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "asp-ace-"));
    try {
      const casesPath = path.join(dir, "cases.json");
      fs.writeFileSync(casesPath, JSON.stringify(cases));
      const runner = path.join(dir, "run.ps1");
      fs.writeFileSync(
        runner,
        [
          `$t = $null; $e = $null`,
          `$ast = [System.Management.Automation.Language.Parser]::ParseFile('${SCRIPT}', [ref]$t, [ref]$e)`,
          `$fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'AspAceHit' }, $true) | Select-Object -First 1`,
          `. ([scriptblock]::Create($fn.Extent.Text))`,
          `$out = [ordered]@{}`,
          `foreach ($c in (Get-Content -Raw '${casesPath}' | ConvertFrom-Json)) {`,
          `  $ext = @{}; foreach ($g in @($c.extended)) { if ($g) { $ext[[string]$g] = $true } }`,
          `  $type = if ($c.objectType) { [string]$c.objectType } else { '00000000-0000-0000-0000-000000000000' }`,
          `  $out[[string]$c.name] = AspAceHit ([int]$c.rights) $type ([bool]$c.inheritOnly) ([string[]]@($c.wanted)) $ext`,
          `}`,
          `$out | ConvertTo-Json -Compress`
        ].join("\n")
      );
      const r = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-File", runner], { encoding: "utf8", timeout: 60_000 });
      expect(r.status, r.stderr).toBe(0);
      return JSON.parse(r.stdout) as Record<string, boolean>;
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  it("⭐ los ACE de lectura de MSIG-DOMAIN01 no son DCSync ni escritura en AdminSDHolder (falsos positivos del 14-sep)", () => {
    const out = run([
      // PRV-006, raíz del dominio: los 9 trustees que salieron con la máscara parcial.
      { name: "everyone-read", rights: R.ReadProperty, wanted: PRV006, extended: [DCSYNC_ALL] },
      { name: "prew2k-read", rights: R.ReadProperty | R.ReadControl, wanted: PRV006, extended: [DCSYNC_ALL] },
      { name: "key-admins-rpwp", rights: R.ReadProperty | R.WriteProperty, objectType: "5b47d60f-6090-40b2-9f37-2a4de88f3063", wanted: PRV006, extended: [DCSYNC_ALL] },
      { name: "self", rights: R.Self, wanted: PRV006, extended: [DCSYNC_ALL] },
      { name: "auth-users-read", rights: R.GenericRead, wanted: PRV006, extended: [DCSYNC_ALL] },
      { name: "cloneable-dc", rights: R.ExtendedRight, objectType: "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e", wanted: PRV006, extended: [DCSYNC_ALL] },
      { name: "forest-trust-builders", rights: R.ExtendedRight, objectType: "e2a36dc9-ae17-47c3-b58b-be34c55ba633", wanted: PRV006, extended: [DCSYNC_ALL] },
      // PRV-005, AdminSDHolder.
      { name: "sdholder-auth-users-read", rights: R.GenericRead, wanted: PRV005 },
      { name: "sdholder-everyone-change-password", rights: R.ExtendedRight, objectType: "ab721a53-1e2f-11d0-9819-00aa0040529b", wanted: PRV005 },
      { name: "sdholder-waag-read", rights: R.ReadProperty, wanted: PRV005 }
    ]);
    expect(Object.entries(out).filter(([, hit]) => hit)).toEqual([]);
  });

  it("⭐ y los que sí lo son, cuentan", () => {
    const out = run([
      { name: "dcsync-get-changes-all", rights: R.ExtendedRight, objectType: DCSYNC_ALL, wanted: PRV006, extended: [DCSYNC_ALL] },
      { name: "all-extended-rights", rights: R.ExtendedRight, wanted: PRV006, extended: [DCSYNC_ALL] },
      { name: "generic-all", rights: R.GenericAll, wanted: PRV006, extended: [DCSYNC_ALL] },
      { name: "sdholder-write-dacl", rights: R.WriteDacl | R.ReadControl, wanted: PRV005 },
      { name: "sdholder-write-property", rights: R.ReadProperty | R.WriteProperty, wanted: PRV005 },
      { name: "sdholder-generic-all", rights: R.GenericAll, wanted: PRV005 }
    ]);
    expect(out).toEqual({
      "dcsync-get-changes-all": true,
      "all-extended-rights": true,
      "generic-all": true,
      "sdholder-write-dacl": true,
      "sdholder-write-property": true,
      "sdholder-generic-all": true
    });
  });

  it("un ACE InheritOnly no aplica al objeto, aunque sea GenericAll", () => {
    expect(run([{ name: "inherit-only", rights: R.GenericAll, inheritOnly: true, wanted: PRV006 }])).toEqual({ "inherit-only": false });
  });
});
