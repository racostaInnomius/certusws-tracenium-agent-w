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
   * Nombre con el que la cola se COMPARTE (Windows `ShareName`). Puede no
   * coincidir con `name`, y es lo que aparece en la conexión del usuario
   * `\\servidor\shareName`: sin él no se une la cola del servidor de impresión
   * con los equipos que la usan. null en CUPS y en colas no compartidas.
   */
  shareName?: string | null;

  /**
   * Dirección real del dispositivo: `PrinterHostAddress` del puerto TCP/IP en
   * Windows (el NOMBRE del puerto es libre — `IP_10.20.11.39`, `HP-Finanzas`) o
   * el host del URI en CUPS (`socket://10.0.0.5:9100` → `10.0.0.5`). Es la clave
   * para contar impresoras FÍSICAS —varias colas pueden apuntar a la misma— y a
   * quién preguntar por SNMP/IPP. null si la cola no tiene dirección (USB, WSD,
   * PDF, una conexión de usuario cuyo destino sólo conoce el servidor).
   */
  hostAddress?: string | null;

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
  //
  // ⚠️ UNC primero. Una cola `\\\\servidor\\cola` es remota por definición, y sin
  // este caso caía al valor conservador "local": medido el 2026-09-11, las 14
  // impresoras que por fin llegaban de Windows —todas conexiones de red de
  // usuario -- se etiquetaron LOCALES las 14. Era inocuo mientras Windows sólo
  // mandaba colas de máquina (`IP_10.0.0.5`, `USB001`); dejó de serlo en cuanto
  // el colector empezó a leer HKEY_USERS, donde el puerto ES el servidor.
  if (p.startsWith("\\\\")) return true;
  if (p.startsWith("tcp/")) return true;
  // `IP_10.20.11.39` es el nombre por defecto que Windows da al puerto TCP/IP
  // estándar. Invisible mientras la lectura de máquina no corría (2026-09-15);
  // en cuanto corra, es el caso MÁS común en un servidor de impresión.
  if (p.startsWith("ip_")) return true;
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

/**
 * Host del URI de una cola CUPS: `socket://10.0.0.5:9100` → `10.0.0.5`,
 * `ipp://printer.local/ipp/print` → `printer.local`. null para lo que no
 * apunta a un host de red (`usb://`, `dnssd://` —el nombre de servicio no es
 * una dirección—, `file:`) o no se deja parsear.
 */
export function hostFromPrinterUri(uri: string | null | undefined): string | null {
  if (!uri) return null;
  const m = uri.trim().match(/^(socket|ipps?|https?|lpd|smb):\/\/(?:[^@/]*@)?(\[[^\]]+\]|[^:/?#]+)/i);
  if (!m) return null;
  const host = m[2].replace(/^\[|\]$/g, "").toLowerCase();
  return host || null;
}

/**
 * Colas que NO son impresoras del equipo y no deben salir de él.
 *
 *   session — impresora redirigida por Escritorio remoto: la del CLIENTE RDP,
 *             vista desde la sesión. Aparece y desaparece con cada conexión,
 *             y cada aparición es un alta y una baja más en el delta.
 *   virtual — no imprime en papel: PDF, XPS, OneNote, fax, controles remotos.
 *
 * ⚠️ Medido en T111 (2026-09-15): de 199 filas en `device_printers`, 90 eran
 * virtuales y 12 de sesión — la mitad del inventario, sin una sola impresora.
 *
 * ⚠️ Lo que se tira aquí no llega NUNCA al backend, así que la regla es
 * deliberadamente más estrecha que la de la pestaña
 * (`certusws-tracenium/modules/printer-inventory/printer-fleet.ts`):
 *
 *   - Una virtual se reconoce SÓLO por el puerto. Las 90 de T111 caen todas por
 *     puerto (`PORTPROMPT:`, `nul:`, `SHRFAX:`, `C:\…\print.pdf`, `AD_Port`…).
 *     El nombre o el driver no bastan: «Fax» o «PDF» en el nombre de una cola
 *     con puerto TCP/IP no demuestra que no haya un aparato detrás.
 *   - Una cola con dirección de red o conexión UNC nunca es virtual.
 *   - Las WSD (`WSD-…`, `IP4_<guid>_<ip>`) SÍ viajan. No cuentan como impresoras
 *     en la pestaña, pero son la única huella de un aparato en equipos sin cola
 *     TCP/IP, y la `IP4_` trae su dirección: tirarlas aquí sería irreversible.
 *
 * El backend conserva su filtro para los agentes anteriores a éste.
 */
export function printerNoiseKind(
  p: Pick<Printer, "name" | "driver" | "port" | "hostAddress">
): "session" | "virtual" | null {
  const port = (p.port || "").trim();
  if (/remote desktop easy print/i.test(p.driver || "")) return "session";
  if (/\(redirected \d+\)\s*$/i.test(p.name || "")) return "session";
  if (/^ts\d{3}$/i.test(port)) return "session";

  if (p.hostAddress || port.startsWith("\\\\")) return null;
  if (VIRTUAL_PORT.test(port)) return "virtual";
  return null;
}

const VIRTUAL_PORT =
  /^(portprompt:|nul:?$|shrfax:|file:|xpsport:|onenote|microsoft\.office\.onenote|pdf[a-z]*:|cups-pdf:|ad_port$|tsprintport:|nitro pdf.*port:?$|[a-z]:\\|documents\\|.*fax_port$)/i;
