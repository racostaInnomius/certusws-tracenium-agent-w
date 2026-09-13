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
