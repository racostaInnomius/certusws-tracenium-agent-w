// test/privsvc/embedded-powershell.ts
//
// Pulls the PowerShell scripts embedded as C# verbatim strings out of the
// Windows PrivSvc sources, so tests can parse them — or run them against
// fakes — without a Windows box. Shared by powershell-scripts-parse.test.ts
// (syntax) and patch-install-script.test.ts (behaviour).

import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export const IPC_DIR = path.resolve(
  __dirname,
  "../../privsvc/windows/Tracenium.PrivSvc.Windows/Ipc"
);

export const HOLE = "'__HOLE__'";

export interface Block {
  file: string;
  line: number;
  interpolated: boolean;
  body: string;
}

/**
 * Reads a C# verbatim string body starting just past the opening quote.
 *
 * Handles the three forms these scripts actually use. Getting any of them
 * wrong makes this harness under-report, which is the same failure it exists
 * to catch — hence the self-checks in the first test below.
 */
export function scanString(s: string, start: number, interpolated: boolean): string {
  const buf: string[] = [];
  let i = start;

  while (i < s.length) {
    const c = s[i];

    if (c === '"') {
      if (s[i + 1] === '"') {
        buf.push('"'); // "" is an escaped quote, not the end
        i += 2;
        continue;
      }
      return buf.join("");
    }

    if (interpolated && c === "{") {
      if (s[i + 1] === "{") {
        buf.push("{"); // {{ is a literal brace
        i += 2;
        continue;
      }
      // An interpolation hole. Skip to its matching brace, respecting nesting
      // and C# string literals inside it: a naive scan stops at the first
      // quote of something like string.Join(",", ...) and truncates the
      // script, hiding everything below it.
      let depth = 1;
      i++;
      while (i < s.length && depth > 0) {
        const ch = s[i];
        if (ch === '"' || ch === "'") {
          const quote = ch;
          i++;
          while (i < s.length) {
            if (s[i] === "\\") {
              i += 2;
              continue;
            }
            if (s[i] === quote) {
              i++;
              break;
            }
            i++;
          }
          continue;
        }
        if (ch === "{") depth++;
        else if (ch === "}") depth--;
        i++;
      }
      buf.push(HOLE);
      continue;
    }

    if (interpolated && c === "}" && s[i + 1] === "}") {
      buf.push("}"); // }} is a literal brace
      i += 2;
      continue;
    }

    buf.push(c);
    i++;
  }

  throw new Error("unterminated verbatim string");
}

export function extractBlocks(): Block[] {
  const blocks: Block[] = [];
  for (const name of fs.readdirSync(IPC_DIR).filter((f) => f.endsWith(".cs"))) {
    const full = path.join(IPC_DIR, name);
    const src = fs.readFileSync(full, "utf8");
    // Helper names vary (RunPs, RunPsWithTimeout, ...); some strings are
    // interpolated ($@").
    const re = /RunPs\w*\(\s*(\$?)@"/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(src))) {
      const interpolated = m[1] === "$";
      blocks.push({
        file: name,
        line: src.slice(0, m.index).split("\n").length,
        interpolated,
        body: scanString(src, m.index + m[0].length, interpolated),
      });
    }
  }
  return blocks;
}

export function hasPwsh(): boolean {
  try {
    execSync("command -v pwsh || where pwsh", { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
