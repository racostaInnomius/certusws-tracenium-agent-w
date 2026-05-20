// src/plugins/amp/providers/printers-cups.ts
//
// Shared CUPS-backed printer collector for macOS and Linux. Both
// platforms expose the same `lpstat` tool (CUPS is the default print
// service on macOS since 10.5 and on most desktop Linux distros), so
// we keep ONE parser and reuse it from each platform provider.
//
// We call three lpstat subcommands:
//
//   - `lpstat -p`     → status of each queue
//                       e.g. "printer Officejet is idle.  enabled since ..."
//   - `lpstat -v`     → device URIs
//                       e.g. "device for Officejet: socket://10.0.0.5"
//   - `lpstat -d`     → default destination (single line)
//                       e.g. "system default destination: Officejet"
//
// All three are read-only and non-privileged. On a Linux host with no
// CUPS installed at all (some headless RHEL/server images), lpstat
// isn't on PATH — we return an empty inventory instead of throwing
// (the provider treats that as "no printers" and ships an empty
// snapshot, same as a host that genuinely has no printers).

import { exec } from "child_process";
import { promisify } from "util";
import { Printer, PrinterStatus, isNetworkPort } from "../../../domain/printer";

const execAsync = promisify(exec);

/**
 * Parse the output of `lpstat -p` into status by queue name.
 * Example lines we handle:
 *   "printer Officejet is idle.  enabled since ..."
 *   "printer HP_LaserJet is now printing job 42.  enabled since ..."
 *   "printer Old_Printer disabled since ... - paused"
 *   "no system default destination"   (ignored)
 *
 * Anything we can't categorize cleanly → "unknown". Better than
 * pretending we know.
 */
function parseStatusLine(line: string): { name: string; status: PrinterStatus } | null {
  const m = line.match(/^printer\s+(\S+)\s+(.*)$/i);
  if (!m) return null;
  const name = m[1];
  const rest = m[2].toLowerCase();

  let status: PrinterStatus = "unknown";
  if (/disabled|stopped|paused|offline/.test(rest)) {
    status = "offline";
  } else if (/idle|now printing|enabled/.test(rest)) {
    status = "online";
  } else if (/error|jam|toner|paper/.test(rest)) {
    status = "error";
  }

  return { name, status };
}

/**
 * Parse `lpstat -v` → device URI per queue.
 * Lines look like: "device for Officejet: socket://10.0.0.5:9100"
 */
function parseDeviceLine(line: string): { name: string; uri: string } | null {
  const m = line.match(/^device for\s+(\S+):\s+(.+)$/i);
  if (!m) return null;
  return { name: m[1], uri: m[2].trim() };
}

/**
 * Best-effort wrapper around `lpstat -d` to find the default queue.
 * Returns null if there's no system default OR lpstat isn't installed.
 * "no system default destination" is a perfectly valid state.
 */
function parseDefaultLine(line: string): string | null {
  const m = line.match(/^system default destination:\s+(\S+)$/i);
  return m ? m[1] : null;
}

/**
 * Run a shell command with a hard timeout. Returns "" on any error
 * (command not found, non-zero exit, timeout) — every caller below
 * treats "" as "no data, skip this dimension" which collapses
 * gracefully to an empty inventory on hosts without CUPS.
 */
async function runOrEmpty(cmd: string, timeoutMs = 5_000): Promise<string> {
  try {
    const { stdout } = await execAsync(cmd, {
      timeout: timeoutMs,
      // lpstat occasionally emits warnings on stderr (e.g., "No
      // destinations added.") — those aren't fatal. We only care
      // about stdout.
      windowsHide: true,
      // Force a string return (not Buffer) — promisify(exec)'s typing
      // can land on Buffer depending on @types/node version.
      encoding: "utf8"
    } as any);
    return typeof stdout === "string" ? stdout : (stdout?.toString?.("utf8") ?? "");
  } catch {
    return "";
  }
}

export async function collectCupsPrinters(): Promise<Printer[]> {
  const [statusOut, deviceOut, defaultOut] = await Promise.all([
    runOrEmpty("lpstat -p"),
    runOrEmpty("lpstat -v"),
    runOrEmpty("lpstat -d")
  ]);

  if (!statusOut && !deviceOut) {
    // No CUPS / no printers / lpstat missing. Empty inventory is the
    // honest answer — the caller decides if hasChanges should fire.
    return [];
  }

  // Merge by queue name. The status pass establishes the queue set
  // (so a printer with a device URI but no status row is filtered
  // out as suspect — likely a half-configured queue).
  const byName = new Map<string, { status: PrinterStatus; port: string | null }>();

  for (const line of statusOut.split("\n").map(l => l.trim()).filter(Boolean)) {
    const parsed = parseStatusLine(line);
    if (parsed) {
      byName.set(parsed.name, { status: parsed.status, port: null });
    }
  }

  for (const line of deviceOut.split("\n").map(l => l.trim()).filter(Boolean)) {
    const parsed = parseDeviceLine(line);
    if (!parsed) continue;
    const existing = byName.get(parsed.name);
    if (existing) {
      existing.port = parsed.uri;
    }
    // Intentionally NOT adding queues that only appear in `-v` output
    // — see comment above.
  }

  const defaultName = defaultOut
    .split("\n")
    .map(parseDefaultLine)
    .find(x => !!x) ?? null;

  const detectedAtUtc = new Date().toISOString();

  const printers: Printer[] = [];
  for (const [name, info] of byName) {
    printers.push({
      installId: `cups:${name}`,
      name,
      source: "cups",
      driver: null,            // lpstat doesn't expose driver/PPD info
                               // cheaply; we leave it null for v1. A
                               // future enhancement can parse
                               // /etc/cups/printers.conf or call
                               // `lpoptions -p <q> -l` per queue.
      port: info.port,
      isDefault: name === defaultName,
      isNetwork: isNetworkPort(info.port),
      isShared: false,         // shared-from-here is a cupsd.conf
                               // setting we don't parse in v1.
      location: null,
      comments: null,
      status: info.status,
      detectedAtUtc
    });
  }

  // Deterministic order so the baseline-hash stays stable across runs
  printers.sort((a, b) => a.installId.localeCompare(b.installId));
  return printers;
}
