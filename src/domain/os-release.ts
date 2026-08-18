// src/domain/os-release.ts
//
// Reads the distribution identity straight from /etc/os-release.
//
// systeminformation obtains this by shelling out
// (`cat /etc/*-release; cat /usr/lib/os-release; ...`). On both Linux servers
// in the fleet that shell-out came back empty, so every device reported
// distro="unknown", release="unknown" — while the kernel, which si takes from
// Node rather than a subprocess, was correct. The same split showed up across
// si's other collectors on those hosts: values read from files arrived, values
// obtained by running a command did not.
//
// Rather than diagnose someone else's subprocess remotely, we read the file.
// os-release is a freedesktop standard present on every systemd distribution,
// it is world-readable, and parsing it needs no shell, no PATH, and no
// privileges — removing an entire class of failure instead of working around
// one instance of it.
//
// This is a FALLBACK: when systeminformation answers, its answer wins, so
// behaviour is unchanged on the machines that already work.

import fs from "node:fs";

// /etc is the operator-editable copy and takes precedence; /usr/lib is the
// vendor default and is what minimal or read-only-root images ship.
const OS_RELEASE_PATHS = ["/etc/os-release", "/usr/lib/os-release"];

export interface OsReleaseInfo {
  /** NAME, e.g. "Ubuntu". */
  distro?: string;
  /** VERSION_ID, e.g. "24.04". */
  release?: string;
}

/**
 * Parses os-release format: KEY=VALUE per line, values optionally quoted,
 * `#` comments, blank lines. Deliberately tolerant — a malformed line must
 * not cost us the lines around it.
 */
export function parseOsRelease(text: string): Record<string, string> {
  const out: Record<string, string> = {};

  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;

    const eq = line.indexOf("=");
    if (eq <= 0) continue;

    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();

    // Values may be single- or double-quoted. Only strip a MATCHED pair, so a
    // value that legitimately contains a quote survives intact.
    if (value.length >= 2) {
      const first = value[0];
      if ((first === '"' || first === "'") && value[value.length - 1] === first) {
        value = value.slice(1, -1);
      }
    }

    if (value) out[key] = value;
  }

  return out;
}

/**
 * Distro identity from os-release, or an empty object when the file is
 * missing or says nothing useful.
 *
 * Never throws: this runs inside inventory collection, where one unreadable
 * file must not cost the whole snapshot.
 */
export function readOsRelease(paths: string[] = OS_RELEASE_PATHS): OsReleaseInfo {
  for (const path of paths) {
    let text: string;
    try {
      text = fs.readFileSync(path, "utf8");
    } catch {
      continue; // absent or unreadable — try the vendor copy
    }

    const fields = parseOsRelease(text);
    // NAME is the human-facing label ("Ubuntu"); ID is the lowercase machine
    // token ("ubuntu") and is the better-than-nothing fallback.
    const distro = fields.NAME || fields.ID;
    // VERSION_ID is the comparable number ("24.04"). VERSION carries the
    // codename too ("24.04.4 LTS (Noble Numbat)") and is second choice.
    const release = fields.VERSION_ID || fields.VERSION;

    if (distro || release) {
      return { ...(distro ? { distro } : {}), ...(release ? { release } : {}) };
    }
  }

  return {};
}

/** Values a collector uses to mean "I could not determine this". */
export function isUnknown(value: unknown): boolean {
  if (typeof value !== "string") return true;
  const v = value.trim().toLowerCase();
  return v === "" || v === "unknown" || v === "-";
}
