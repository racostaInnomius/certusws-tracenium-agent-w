// test/privsvc/powershell-scripts-parse.test.ts
//
// Parses every PowerShell script embedded in the Windows PrivSvc C# sources.
//
// Why this exists: the `patch.scan` script had a syntax error from its very
// first commit and shipped that way for months. Nothing caught it. C# sees an
// opaque string, so the compiler is silent; the C# tests never run the script;
// and on the endpoint the only symptom was PowerShell writing nothing to
// stdout, which the agent reported as "Inventory Only, 0 patches" — visually
// identical to a healthy machine. Twelve servers in one tenant sat like that
// for weeks.
//
// The specific trap, since it is not obvious: a try/catch used as a hashtable
// VALUE parses only when it is the LAST entry. Put a key after it and the
// catch block's closing brace is consumed as the hashtable's, so the literal
// never closes:
//
//   @{ a = try { 1 } catch { $null } }        # parses
//   @{ a = try { 1 } catch { $null }
//      b = 2 }                                # MissingEndCurlyBrace
//
// Wrapping the value in $( ) is correct in either position. One script was
// only accidentally valid because its try happened to be last — adding a
// field below it would have broken it silently too.

import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "node:child_process";
import { extractBlocks, hasPwsh, IPC_DIR, type Block } from "./embedded-powershell";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

/** Parse errors reported by PowerShell itself, one line each. */
function parseErrors(scriptPath: string): string[] {
  const probe = `
$errs = $null
[void][System.Management.Automation.Language.Parser]::ParseFile('${scriptPath}', [ref]$null, [ref]$errs)
$errs | ForEach-Object { 'L{0}: {1}: {2}' -f $_.Extent.StartLineNumber, $_.ErrorId, $_.Message }
`;
  const out = execFileSync("pwsh", ["-NoProfile", "-Command", probe], {
    encoding: "utf8",
  });
  return out.split("\n").map((l) => l.trim()).filter(Boolean);
}

describe("PrivSvc embedded PowerShell", () => {
  let blocks: Block[];

  beforeAll(() => {
    blocks = extractBlocks();
  });

  it("extracts every embedded script, whole", () => {
    // Guards the harness itself. An extractor that quietly finds nothing —
    // or truncates a script at its first quote — would report a clean bill of
    // health for code that does not parse.
    expect(blocks.length).toBeGreaterThanOrEqual(8);

    // Both C# string forms must be represented; the interpolated one is where
    // the brace-escaping rules differ and are easiest to get wrong.
    expect(blocks.some((b) => b.interpolated)).toBe(true);
    expect(blocks.some((b) => !b.interpolated)).toBe(true);

    for (const b of blocks) {
      // Every one of these is a real script, not a fragment.
      expect(b.body.split("\n").length, `${b.file}:${b.line} looks truncated`)
        .toBeGreaterThan(5);
      // A truncated block usually ends mid-statement; a complete one does not
      // still be inside an unclosed interpolation hole.
      expect(b.body).not.toContain('@"');
    }

    // The install script is the largest and the one most likely to be cut
    // short, because its interpolation holes contain quoted C# literals.
    const install = blocks.find((b) => b.file === "PatchManagement.cs" && b.interpolated);
    expect(install, "interpolated PatchManagement script not found").toBeDefined();
    expect(install!.body.split("\n").length).toBeGreaterThan(100);
  });

  it("parses every embedded script with PowerShell", () => {
    if (!hasPwsh()) {
      // Deliberately loud rather than silent: CI (ubuntu-latest) ships pwsh,
      // so a skip here means a local machine, not a gap in coverage.
      console.warn(
        "[skip] pwsh not installed — PowerShell syntax NOT verified on this machine"
      );
      return;
    }

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "privsvc-ps-"));
    const failures: string[] = [];

    for (const b of blocks) {
      const file = path.join(dir, `${b.file.replace(".cs", "")}_L${b.line}.ps1`);
      fs.writeFileSync(file, b.body, "utf8");
      const errs = parseErrors(file);
      if (errs.length) {
        failures.push(`${b.file}:${b.line} -> ${errs[0]}`);
      }
    }

    expect(failures, `embedded PowerShell does not parse:\n${failures.join("\n")}`)
      .toEqual([]);
  });

  it("never uses try/catch as a non-final hashtable value", () => {
    // A cheap textual backstop that works without pwsh, and names the exact
    // mistake so the next person does not have to rediscover the rule.
    const offenders: string[] = [];
    for (const name of fs.readdirSync(IPC_DIR).filter((f) => f.endsWith(".cs"))) {
      const lines = fs.readFileSync(path.join(IPC_DIR, name), "utf8").split("\n");
      lines.forEach((line, idx) => {
        if (/^\s*\w+\s*=\s*try\s*\{/.test(line)) {
          offenders.push(`${name}:${idx + 1}: ${line.trim()}`);
        }
      });
    }
    expect(
      offenders,
      `wrap the value in $( ):\n${offenders.join("\n")}`
    ).toEqual([]);
  });
});
