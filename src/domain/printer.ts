// src/domain/printer.ts
//
// Printer asset model. Mirror of normalize-app.ts (SoftwareApplication)
// but smaller — printers have far fewer fields than apps and don't need
// the same normalization pipeline (no Microsoft Store-equivalent
// noise, no publisher disambiguation, etc.).
//
// `installId` is the stable identity used by the delta engine
// (computePrinterDelta) and by the backend's per-device printer table
// to track adds/removes across snapshots. Per platform:
//
//   - Windows (Get-Printer):    `windows-spooler:${name}`
//   - macOS/Linux (CUPS lpstat): `cups:${queueName}`
//
// Both are stable as long as the printer keeps its name/queue. Renames
// look like a remove + add at the delta layer — same behavior as the
// software inventory baseline.

export type PrinterStatus =
  | "online"
  | "offline"
  | "error"
  | "unknown";

export type PrinterSource =
  | "windows-spooler"
  | "cups";

export interface Printer {
  /**
   * Stable platform-scoped identifier. See file header for the
   * composition formula per source.
   */
  installId: string;

  /**
   * Display name as the OS / print spooler knows it. On Windows this
   * is the `Name` from Get-Printer; on macOS/Linux it's the CUPS queue
   * name (column 2 of `lpstat -p` / `-v`).
   */
  name: string;

  /**
   * Which collector emitted this row. Used by the backend to scope
   * deltas correctly when a host migrates platform (rare, but the
   * delta layer should treat a `windows-spooler:Foo` and `cups:Foo`
   * as different printers).
   */
  source: PrinterSource;

  /**
   * Driver / model. On Windows: `DriverName` (e.g., "HP Universal
   * Printing PCL 6"). On CUPS: PPD-derived (often the model name,
   * sometimes "Generic PostScript Printer" for raw queues).
   */
  driver?: string | null;

  /**
   * Port / device URI.
   *   Windows: `PortName` from Get-Printer (e.g., "USB001",
   *            "TCP/192.168.1.50", "WSD-...", "PORTPROMPT:").
   *   CUPS:    device URI from `lpstat -v` (e.g., "socket://10.0.0.5",
   *            "ipp://printer.local/ipp/print", "usb://HP/...").
   */
  port?: string | null;

  /**
   * Whether this is the user's default printer at the time of
   * collection. Windows: `Default = $true`. CUPS: queue listed first
   * in `lpstat -d`. Can flip between snapshots without the printer
   * itself changing, so the delta engine treats this as a non-identity
   * field (changes here trigger an `updated` event, NOT add/remove).
   */
  isDefault?: boolean;

  /**
   * Network-attached (vs. locally connected via USB / direct port).
   * Derived from port URI: TCP, http(s), ipp → network.
   * USB / LPT / COM / PORTPROMPT → local. Heuristic — there are weird
   * edge cases (a WSD printer over USB-IP, etc.) but it's good enough
   * for UI grouping.
   */
  isNetwork?: boolean;

  /**
   * Shared from this host (Windows: `Shared = $true`; CUPS: queue's
   * "shared = yes" in cupsd.conf). Rare on user desktops, common on
   * print servers — worth tracking.
   */
  isShared?: boolean;

  /**
   * Free-form location string. Often empty. Operators sometimes set
   * "Floor 3, North Wing" or similar.
   */
  location?: string | null;

  /**
   * Free-form comments. Same operator-set field — often empty.
   */
  comments?: string | null;

  /**
   * Current spooler/CUPS-reported status. Heuristic mapping:
   *   - "online"  → ready/idle/printing
   *   - "offline" → not connected / paused / stopped
   *   - "error"   → jammed, out of paper/toner, error state
   *   - "unknown" → couldn't determine
   *
   * Snapshot-time status — useful but volatile. The delta engine
   * IGNORES status when deciding add/remove/update; treating a
   * temporary "offline" as removal would create flapping events.
   * Status changes are surfaced separately by the backend if/when
   * we add an event stream.
   */
  status?: PrinterStatus;

  /**
   * ISO-8601 UTC timestamp of when the agent observed this printer.
   * Populated by the collector at snapshot time. The baseline repo
   * preserves the EARLIEST detected_at_utc across snapshots (so the
   * value approximates "first seen on this device").
   */
  detectedAtUtc: string;
}

/**
 * Heuristic to derive `isNetwork` from a port/URI string. Centralized
 * here so all three collectors share the same definition — otherwise
 * a printer that migrates from one platform to another would flicker
 * isNetwork across snapshots for no real reason.
 */
export function isNetworkPort(port: string | null | undefined): boolean {
  if (!port) return false;
  const p = port.trim().toLowerCase();
  if (!p) return false;

  // CUPS / Unix-style URIs
  if (p.startsWith("socket://")) return true;
  if (p.startsWith("ipp://") || p.startsWith("ipps://")) return true;
  if (p.startsWith("http://") || p.startsWith("https://")) return true;
  if (p.startsWith("lpd://")) return true;
  if (p.startsWith("smb://")) return true;
  if (p.startsWith("dnssd://")) return true;

  // Windows-style port names
  if (p.startsWith("tcp/")) return true;
  if (p.startsWith("wsd-")) return true;        // Web Services for Devices
  if (/^\d{1,3}(\.\d{1,3}){3}/.test(p)) return true; // bare IPv4 portname

  // Local connections (explicit deny list)
  if (p.startsWith("usb")) return false;
  if (p.startsWith("lpt")) return false;
  if (p.startsWith("com")) return false;
  if (p.startsWith("portprompt:")) return false;
  if (p.startsWith("file:")) return false;
  if (p.startsWith("nul:")) return false;

  // Default conservative answer when we genuinely don't know — local.
  // Network is the rarer case; a false negative just means a network
  // printer shows in "Local" group in UI (mild bug), vs. a false
  // positive that would put a local USB printer in "Network" (more
  // confusing for the operator).
  return false;
}
