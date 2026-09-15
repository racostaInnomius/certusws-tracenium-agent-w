// src/plugins/amp/providers/printers-windows.ts
//
// Windows-side printer collector. Bridges to privsvc which runs
// `Get-Printer | ConvertTo-Json` via PowerShell. We route this through
// privsvc (instead of running PowerShell from the agent process)
// because:
//
//   1. Consistency with `software.inventory` and `security.compliance`
//      — both already use privsvc for their OS-native reads, so
//      operators looking at the audit trail see all "what's on this
//      device" calls coming from a single privileged boundary.
//
//   2. Some printer details (port driver type, kernel-mode driver
//      info, IPP authentication metadata) require SeLoadDriverPriv
//      or LocalSystem. We don't read those today, but the boundary
//      is set up correctly for when we extend.
//
//   3. PowerShell process startup is non-trivial (~300ms cold); doing
//      it from a long-lived service avoids re-spawning node-side
//      child processes on every collection cycle.
//
// The agent-side payload contract is: { ok: true, result: { count,
// items: RawPrinter[] } } where RawPrinter has the raw camelCase
// fields that map 1-to-1 from Get-Printer's PSObject output. We
// normalize in this file (rather than in privsvc) so the Printer
// model lives entirely in TS-land and never has to be kept in sync
// with the .NET serializer's casing conventions.

import type { AgentContext } from "../../../core/agent-context";
import { Printer, isNetworkPort, PrinterStatus } from "../../../domain/printer";

interface RawPrinter {
  name?: string | null;
  driverName?: string | null;
  portName?: string | null;
  isDefault?: boolean | null;
  shared?: boolean | null;
  location?: string | null;
  comment?: string | null;
  // Get-Printer's PrinterStatus enum values: Normal, Offline, Error,
  // Paused, Pending, Initializing, IoActive, Busy, Printing,
  // Output, ManualFeed, PaperOut, etc. — we normalize down to our
  // 4-state PrinterStatus.
  printerStatus?: string | null;
  // privsvc ≥ 2026-09-15. Un privsvc anterior no los manda: quedan null.
  shareName?: string | null;
  hostAddress?: string | null;
}

/**
 * Map Get-Printer's PrinterStatus / DetectedErrorState to our
 * narrow PrinterStatus enum. Anything we don't recognize → unknown.
 */
function normalizeStatus(raw?: string | null): PrinterStatus {
  if (!raw) return "unknown";
  const s = raw.toLowerCase();

  if (s.includes("offline") || s.includes("paused") || s.includes("stopped")) {
    return "offline";
  }
  if (
    s.includes("error") ||
    s.includes("jam") ||
    s.includes("paperout") ||
    s.includes("toner") ||
    s.includes("nopaper")
  ) {
    return "error";
  }
  if (
    s.includes("normal") ||
    s.includes("printing") ||
    s.includes("idle") ||
    s.includes("ioactive") ||
    s.includes("busy")
  ) {
    return "online";
  }
  return "unknown";
}

export type WindowsPrinterRead = {
  printers: Printer[];
  /** Ver PrinterInventory.machineScope. `unavailable` = no se pudo mirar. */
  machineScope: string;
  userScope: string;
};

export async function collectWindowsPrinters(ctx: AgentContext): Promise<WindowsPrinterRead> {
  let resp: any;
  try {
    resp = await ctx.priv.call({
      v: 1,
      id: `printers_${Date.now()}`,
      method: "printer.inventory",
      params: {},
      meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
    });
  } catch (err: any) {
    // PrivSvc not reachable / IPC pipe broken. Treat as "no data" so
    // the caller's `try/catch` doesn't blow up the whole AMP cycle.
    // ⚠️ NO es "cero impresoras": es que no se pudo preguntar. El que lo
    // reciba tiene que poder distinguirlo o volvemos al punto de partida.
    ctx.logger?.warn?.("[printers] privsvc call failed, scope unavailable", {
      error: err?.message || String(err)
    });
    return { printers: [], machineScope: "unavailable", userScope: "unavailable" };
  }

  if (!resp?.ok) {
    ctx.logger?.warn?.("[printers] privsvc returned non-ok", {
      code: resp?.error?.code,
      message: resp?.error?.message
    });
    return { printers: [], machineScope: "unavailable", userScope: "unavailable" };
  }

  const items: RawPrinter[] = Array.isArray(resp.result?.items) ? resp.result.items : [];
  const detectedAtUtc = new Date().toISOString();

  const printers: Printer[] = [];
  for (const raw of items) {
    const name = (raw?.name ?? "").trim();
    if (!name) continue; // can't form a stable installId without a name

    const port = raw.portName ?? null;
    const hostAddress = typeof raw.hostAddress === "string" && raw.hostAddress.trim() ? raw.hostAddress.trim() : null;

    printers.push({
      installId: `windows-spooler:${name}`,
      name,
      source: "windows-spooler",
      driver: raw.driverName ?? null,
      port,
      isDefault: Boolean(raw.isDefault),
      // Un puerto con dirección TCP/IP es de red aunque se llame
      // "HP-Finanzas": el nombre del puerto es libre, la dirección no.
      isNetwork: isNetworkPort(port) || hostAddress !== null,
      isShared: Boolean(raw.shared),
      shareName: typeof raw.shareName === "string" && raw.shareName.trim() ? raw.shareName.trim() : null,
      hostAddress,
      location: raw.location ?? null,
      comments: raw.comment ?? null,
      status: normalizeStatus(raw.printerStatus),
      detectedAtUtc
    });
  }

  // Deterministic ordering → stable baseline hash across reruns
  printers.sort((a, b) => a.installId.localeCompare(b.installId));

  // Los alcances viajan tal cual los declara privsvc: aquí no se reinterpretan
  // ni se colapsan en un booleano. Un privsvc viejo no los manda, y entonces
  // se marcan `unknown` — que tampoco es "collected".
  return {
    printers,
    machineScope: typeof resp.result?.machineScope === "string" ? resp.result.machineScope : "unknown",
    userScope: typeof resp.result?.userScope === "string" ? resp.result.userScope : "unknown"
  };
}
