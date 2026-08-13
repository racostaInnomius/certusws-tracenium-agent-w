// src/plugins/cdp/process-owner.ts
//
// ADR-0004 (a) — ownership attribution: which process is serving this
// certificate?
//
// Finding certificates is the easy part. The operational question that
// actually blocks a renewal is "whose is it, and what breaks if it
// expires?". A port number alone does not answer that; a process name
// and executable path do, and they are what lets the control plane join
// a certificate to the software inventory AMP already collects.
//
// Per platform, using the cheapest thing that works:
//   linux   — /proc only. The socket inode from /proc/net/tcp is matched
//             against the fd symlinks under /proc/<pid>/fd. No subprocess.
//   macOS   — lsof, which reports command and PID in one pass. `+c 0`
//             matters: without it lsof truncates the command to 9
//             characters ("figma_age" instead of "figma_agent").
//   windows — netstat -ano already carries the PID; tasklist maps PIDs
//             to names in one call rather than one call per port.
//
// PRIVACY: a process name and path say what the user runs. That is the
// same class of data AMP's software inventory already collects, and it
// is treated the same way — but it is worth knowing that this collector
// widens what a listener row reveals.

import fs from "fs";
import os from "os";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

const CMD_TIMEOUT_MS = 10000;
const CMD_MAX_BUFFER = 16 * 1024 * 1024;
/** A host with thousands of processes must not turn into a /proc crawl. */
const MAX_PIDS_SCANNED = 5000;

export type ProcessOwner = {
  pid: number;
  /** Executable name, e.g. "figma_agent" or "nginx". */
  name?: string;
  /** Full path when we can get it cheaply. */
  path?: string;
};

// ── Linux ─────────────────────────────────────────────────────────

/** port → socket inode, from one /proc/net/tcp table. */
export function parseProcNetTcpInodes(content: string): Map<number, string> {
  const out = new Map<number, string>();

  for (const line of String(content).split("\n").slice(1)) {
    const cols = line.trim().split(/\s+/);
    // sl local rem st tx rx tr tm retr uid timeout inode
    if (cols.length < 10 || cols[3] !== "0A") continue;

    const hexPort = String(cols[1]).split(":")[1];
    const port = parseInt(hexPort ?? "", 16);
    const inode = cols[9];
    if (!Number.isInteger(port) || port <= 0 || !inode || inode === "0") continue;
    if (!out.has(port)) out.set(port, inode);
  }

  return out;
}

async function linuxOwners(ports: number[]): Promise<Map<number, ProcessOwner>> {
  const owners = new Map<number, ProcessOwner>();

  const inodeByPort = new Map<number, string>();
  for (const table of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    try {
      for (const [port, inode] of parseProcNetTcpInodes(fs.readFileSync(table, "utf8"))) {
        if (ports.includes(port) && !inodeByPort.has(port)) inodeByPort.set(port, inode);
      }
    } catch {
      /* table absent — not an error */
    }
  }
  if (inodeByPort.size === 0) return owners;

  // Invert: we need inode → pid, so walk each process's fds once.
  const wanted = new Map<string, number>();
  for (const [port, inode] of inodeByPort) wanted.set(`socket:[${inode}]`, port);

  let pids: string[];
  try {
    pids = fs.readdirSync("/proc").filter((entry) => /^\d+$/.test(entry));
  } catch {
    return owners;
  }

  for (const pid of pids.slice(0, MAX_PIDS_SCANNED)) {
    if (wanted.size === 0) break;
    let fds: string[];
    try {
      fds = fs.readdirSync(`/proc/${pid}/fd`);
    } catch {
      // Process exited mid-scan, or is not ours. Both are normal.
      continue;
    }

    for (const fd of fds) {
      let link: string;
      try {
        link = fs.readlinkSync(`/proc/${pid}/fd/${fd}`);
      } catch {
        continue;
      }
      const port = wanted.get(link);
      if (port === undefined) continue;

      owners.set(port, {
        pid: Number(pid),
        name: readProcFile(`/proc/${pid}/comm`),
        path: readLinkSafe(`/proc/${pid}/exe`)
      });
      wanted.delete(link);
    }
  }

  return owners;
}

function readProcFile(path: string): string | undefined {
  try {
    const value = fs.readFileSync(path, "utf8").trim();
    return value || undefined;
  } catch {
    return undefined;
  }
}

function readLinkSafe(path: string): string | undefined {
  try {
    return fs.readlinkSync(path);
  } catch {
    return undefined;
  }
}

// ── macOS ─────────────────────────────────────────────────────────

/**
 * Parse `lsof -nP -iTCP -sTCP:LISTEN +c 0`.
 * Columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
 * NAME is `127.0.0.1:8443` or `*:443`.
 */
export function parseLsofListeners(output: string): Map<number, ProcessOwner> {
  const owners = new Map<number, ProcessOwner>();

  for (const raw of String(output).split("\n").slice(1)) {
    const line = raw.trim();
    if (!line) continue;
    const cols = line.split(/\s+/);
    if (cols.length < 9) continue;

    const command = cols[0];
    const pid = Number(cols[1]);

    // The state is its OWN whitespace-separated token, so the address is
    // not simply the last column — `... TCP *:58676 (LISTEN)` splits into
    // ten fields with "(LISTEN)" at the end. Drop it, then take what is
    // left as NAME.
    const tail = cols[cols.length - 1] === "(LISTEN)" ? cols.slice(0, -1) : cols;
    const name = tail[tail.length - 1] ?? "";
    const port = Number(name.slice(name.lastIndexOf(":") + 1));

    if (!Number.isInteger(pid) || !Number.isInteger(port) || port <= 0) continue;
    if (!owners.has(port)) owners.set(port, { pid, name: command });
  }

  return owners;
}

async function macosOwners(): Promise<Map<number, ProcessOwner>> {
  try {
    // `+c 0` disables lsof's 9-character truncation of COMMAND.
    const { stdout } = await execFileAsync(
      "lsof",
      ["-nP", "-iTCP", "-sTCP:LISTEN", "+c", "0"],
      { timeout: CMD_TIMEOUT_MS, maxBuffer: CMD_MAX_BUFFER }
    );
    const owners = parseLsofListeners(stdout);

    // Executable paths in one extra call, not one per process.
    const pids = [...new Set([...owners.values()].map((o) => o.pid))];
    if (pids.length > 0) {
      try {
        const { stdout: psOut } = await execFileAsync(
          "ps",
          ["-o", "pid=,comm=", "-p", pids.join(",")],
          { timeout: CMD_TIMEOUT_MS, maxBuffer: CMD_MAX_BUFFER }
        );
        const pathByPid = parsePsPaths(psOut);
        for (const owner of owners.values()) {
          const path = pathByPid.get(owner.pid);
          if (path) owner.path = path;
        }
      } catch {
        /* paths are a bonus, not a requirement */
      }
    }

    return owners;
  } catch {
    return new Map();
  }
}

/** Parse `ps -o pid=,comm=` — comm is the full executable path on macOS. */
export function parsePsPaths(output: string): Map<number, string> {
  const out = new Map<number, string>();
  for (const raw of String(output).split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const match = line.match(/^(\d+)\s+(.+)$/);
    if (!match) continue;
    out.set(Number(match[1]), match[2].trim());
  }
  return out;
}

// ── Windows ───────────────────────────────────────────────────────

/** Parse `netstat -ano` — the last column is the owning PID. */
export function parseNetstatPids(output: string): Map<number, number> {
  const out = new Map<number, number>();

  for (const raw of String(output).split("\n")) {
    const line = raw.trim();
    if (!line || !/LISTENING/i.test(line)) continue;
    const cols = line.split(/\s+/);
    if (cols.length < 5) continue;

    const local = cols[1];
    const pid = Number(cols[cols.length - 1]);
    const port = Number(local.slice(local.lastIndexOf(":") + 1));
    if (!Number.isInteger(pid) || !Number.isInteger(port) || port <= 0) continue;
    if (!out.has(port)) out.set(port, pid);
  }

  return out;
}

/** Parse `tasklist /FO CSV /NH` into pid → image name. */
export function parseTasklist(output: string): Map<number, string> {
  const out = new Map<number, string>();
  for (const raw of String(output).split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const fields = line.split('","').map((f) => f.replace(/^"|"$/g, ""));
    if (fields.length < 2) continue;
    const pid = Number(fields[1]);
    if (Number.isInteger(pid) && fields[0]) out.set(pid, fields[0]);
  }
  return out;
}

async function windowsOwners(): Promise<Map<number, ProcessOwner>> {
  const owners = new Map<number, ProcessOwner>();
  try {
    const { stdout } = await execFileAsync("netstat", ["-ano", "-p", "TCP"], {
      timeout: CMD_TIMEOUT_MS,
      maxBuffer: CMD_MAX_BUFFER,
      windowsHide: true
    });
    const pidByPort = parseNetstatPids(stdout);
    if (pidByPort.size === 0) return owners;

    let names = new Map<number, string>();
    try {
      const { stdout: tasks } = await execFileAsync("tasklist", ["/FO", "CSV", "/NH"], {
        timeout: CMD_TIMEOUT_MS,
        maxBuffer: CMD_MAX_BUFFER,
        windowsHide: true
      });
      names = parseTasklist(tasks);
    } catch {
      /* names are a bonus */
    }

    for (const [port, pid] of pidByPort) {
      owners.set(port, { pid, name: names.get(pid) });
    }
  } catch {
    /* leave empty */
  }
  return owners;
}

/**
 * Resolve which process is listening on each of `ports`.
 * Never throws: attribution is an enrichment, and losing it must not
 * cost us the certificate inventory it decorates.
 */
export async function resolveListenerOwners(
  ports: number[],
  platform: NodeJS.Platform = os.platform()
): Promise<Map<number, ProcessOwner>> {
  if (ports.length === 0) return new Map();

  try {
    const all =
      platform === "linux"
        ? await linuxOwners(ports)
        : platform === "darwin"
          ? await macosOwners()
          : platform === "win32"
            ? await windowsOwners()
            : new Map<number, ProcessOwner>();

    // Only hand back what was asked for.
    const wanted = new Set(ports);
    const filtered = new Map<number, ProcessOwner>();
    for (const [port, owner] of all) {
      if (wanted.has(port)) filtered.set(port, owner);
    }
    return filtered;
  } catch {
    return new Map();
  }
}
