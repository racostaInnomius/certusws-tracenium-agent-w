// src/plugins/cdp/listening-ports.ts
//
// Enumerate TCP ports listening on the LOOPBACK interface, per platform.
//
// Loopback only, deliberately: the probe in tls-probe.ts connects to
// 127.0.0.1, so a port bound exclusively to an external interface is not
// reachable anyway, and enumerating it would only produce failed probes.
// Ports bound to 0.0.0.0 / :: are included — those accept on loopback too.
//
// Linux reads /proc/net/tcp directly (no subprocess, no parsing of
// localized CLI output). macOS and Windows shell out to netstat, which
// is present on every supported release and needs no privileges to list
// listening sockets.

import fs from "fs";
import os from "os";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

const NETSTAT_TIMEOUT_MS = 10000;
const NETSTAT_MAX_BUFFER = 8 * 1024 * 1024;

/** TCP_LISTEN in /proc/net/tcp's hex `st` column. */
const PROC_TCP_LISTEN = "0A";

function isLoopbackReachable(addr: string): boolean {
  // Reachable from 127.0.0.1: loopback itself, or a wildcard bind.
  return (
    addr === "127.0.0.1" ||
    addr === "0.0.0.0" ||
    addr === "*" ||
    addr === "::" ||
    addr === "::1" ||
    addr === "[::]" ||
    addr === "[::1]" ||
    addr.endsWith(".0.0.0.0")
  );
}

/**
 * Parse one /proc/net/tcp or /proc/net/tcp6 table.
 * Columns: sl local_address rem_address st ...
 * local_address is HEX_ADDR:HEX_PORT, little-endian per 32-bit word.
 */
export function parseProcNetTcp(content: string): number[] {
  const ports: number[] = [];

  for (const line of String(content).split("\n").slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 4) continue;
    if (cols[3] !== PROC_TCP_LISTEN) continue;

    const [hexAddr, hexPort] = String(cols[1]).split(":");
    if (!hexPort) continue;

    const port = parseInt(hexPort, 16);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) continue;

    // Wildcard binds are all-zero; loopback v4 is 0100007F (LE), v6
    // loopback ends in ...00000001. Anything else is a specific external
    // interface, which 127.0.0.1 cannot reach.
    const addr = String(hexAddr).toUpperCase();
    const isWildcard = /^0+$/.test(addr);
    const isLoopbackV4 = addr === "0100007F";
    const isLoopbackV6 = addr.length === 32 && /0{24}1$/.test(addr.replace(/^0+/, "").padStart(32, "0"));
    if (!isWildcard && !isLoopbackV4 && !isLoopbackV6) continue;

    ports.push(port);
  }

  return ports;
}

/** Parse `netstat -an` output (macOS BSD and Windows formats). */
export function parseNetstat(output: string): number[] {
  const ports: number[] = [];

  for (const raw of String(output).split("\n")) {
    const line = raw.trim();
    if (!line || !/LISTEN/i.test(line)) continue;

    const cols = line.split(/\s+/);
    // BSD: "tcp4  0  0  127.0.0.1.8443  *.*  LISTEN"
    // Win: "  TCP    0.0.0.0:443    0.0.0.0:0    LISTENING"
    const local = cols.find(
      (c) => /[.:]\d+$/.test(c) && !/^LISTEN/i.test(c)
    );
    if (!local) continue;

    const sep = Math.max(local.lastIndexOf(":"), local.lastIndexOf("."));
    if (sep <= 0) continue;

    const addr = local.slice(0, sep);
    const port = Number(local.slice(sep + 1));
    if (!Number.isInteger(port) || port <= 0 || port > 65535) continue;
    if (!isLoopbackReachable(addr)) continue;

    ports.push(port);
  }

  return ports;
}

async function linuxPorts(): Promise<number[]> {
  const ports: number[] = [];
  for (const path of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    try {
      ports.push(...parseProcNetTcp(fs.readFileSync(path, "utf8")));
    } catch {
      // Missing table (no IPv6, container without procfs) is not an error.
    }
  }
  return ports;
}

async function netstatPorts(args: string[]): Promise<number[]> {
  try {
    const { stdout } = await execFileAsync("netstat", args, {
      timeout: NETSTAT_TIMEOUT_MS,
      maxBuffer: NETSTAT_MAX_BUFFER,
      windowsHide: true
    });
    return parseNetstat(stdout);
  } catch {
    return [];
  }
}

/** Deduped, sorted list of loopback-reachable listening TCP ports. */
export async function listListeningPorts(
  platform: NodeJS.Platform = os.platform()
): Promise<number[]> {
  let ports: number[] = [];

  if (platform === "linux") {
    ports = await linuxPorts();
  } else if (platform === "darwin") {
    ports = await netstatPorts(["-an", "-p", "tcp"]);
  } else if (platform === "win32") {
    ports = await netstatPorts(["-an", "-p", "TCP"]);
  }

  return [...new Set(ports)].sort((a, b) => a - b);
}
