// src/plugins/amp/providers/geo.ts
//
// Endpoint positioning for desktops: asks the OPERATING SYSTEM where it is.
//
// Why the OS and not an IP lookup
// -----------------------------------------------------------------------------
// The control plane used to infer a city from the device's public IP. Measured
// against real hosts that was wrong in a way no dataset can fix: machines
// egressing through Starlink gateways reported Chicago and Montreal, because
// the address genuinely belongs to that gateway. The OS, by contrast, resolves
// position from nearby Wi-Fi access points via Microsoft's/Apple's own
// service — accurate to tens of metres, and unaffected by VPNs or satellite
// routing.
//
// Why not scan BSSIDs ourselves
// -----------------------------------------------------------------------------
// We could read nearby BSSIDs and resolve them against a third-party
// geolocation API. That would need a paid API key and would send the customer's
// surrounding network names off-site. Letting the OS do it keeps both the key
// and the BSSIDs where they belong. (It is also the only option on macOS 14+,
// which returns a null BSSID without location permission anyway.)
//
// Everything here is fail-soft: no permission, no location service, an old
// Windows build, a timeout — all resolve to `null`, which the caller treats as
// "no position this tick". A position is a nice-to-have on an inventory tick
// that must not fail because of it.

import os from "os";
import fs from "fs";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

/**
 * Why this device is or is not reporting a position.
 *
 * Reported on EVERY tick, including the failures. Without it a blank Location
 * column is indistinguishable across "the tenant never switched it on", "this
 * OS cannot do it", "the user denied the prompt" and "the agent is too old" —
 * and an MSP looking at five clients' fleets has no way to tell which of those
 * needs action. The absence of a coordinate is data.
 */
export type GeoStatus =
  /** A fix was obtained and is in `geo`. */
  | "ok"
  /** The tenant has not enabled features.locationTracking. */
  | "disabled"
  /** No system location service on this platform (Linux). */
  | "unsupported"
  /** The OS refused: location services off, or consent denied. */
  | "denied"
  /** Supported and permitted, but no fix right now (indoors, cold start). */
  | "unavailable"
  /**
   * macOS: nobody has answered the OS permission prompt yet.
   *
   * Distinct from `denied` (answered: no) and emphatically distinct from
   * `unavailable` (permitted, just no fix): waiting will never resolve this,
   * somebody has to grant it. Reporting it as `unavailable` told operators to
   * wait for something that was never going to happen.
   */
  | "consent_required"
  /**
   * macOS: nobody is logged in at the console.
   *
   * Position is collected by the user-session app, so a Mac sitting at the
   * login window has nothing that COULD collect. Not a fault to chase.
   */
  | "no_user_session"
  /**
   * macOS: somebody is logged in, but the status app is not publishing —
   * not running, crashed, or its last write aged out. This one IS a fault.
   */
  | "agent_not_publishing";

export type GeoResult = {
  geo: AmpGeo | null;
  status: GeoStatus;
  /**
   * The platform's own words, when it refused.
   *
   * The status says WHICH category of failure; this says what the OS actually
   * reported. On Windows that exception text is the only thing that separates
   * "the SYSTEM account has no location consent" from "this SKU has no
   * provider" — and it was being discarded, leaving `denied` with nothing
   * actionable behind it.
   */
  detail?: string;
};

/** Matches the amp.geo shape the backend already reads (lat/lon/accuracyM). */
export type AmpGeo = {
  lat: number;
  lon: number;
  accuracyM: number | null;
  collectedAtUtc: string;
};

/**
 * A generous budget. The first fix after a cold start can take seconds while
 * the OS scans Wi-Fi; anything beyond this is a hung location service, and the
 * inventory tick should move on without it.
 */
const LOOKUP_TIMEOUT_MS = 20_000;

/**
 * PowerShell that asks Windows for a single reading and prints JSON.
 *
 * `Geolocator` is asynchronous WinRT. `GetGeopositionAsync` returns an
 * IAsyncOperation, and PowerShell 5.1 cannot await one directly — hence the
 * reflection dance to reach `AsTask`. This is the standard workaround for
 * calling WinRT async APIs from Windows PowerShell.
 *
 * `ReportInterval` is set so the OS knows we want one prompt reading rather
 * than a subscription it should keep warm.
 */
const WINDOWS_SCRIPT = `
$ErrorActionPreference = 'Stop'

# Check the machine-wide gate BEFORE asking, so "denied" can name the reason.
#
# The agent runs as SYSTEM in session 0, and Windows location consent is
# per-user — but there IS a machine-wide switch (the same one the Settings
# "Location services" toggle writes) that a GPO can set. Distinguishing "the
# machine has location switched off" from "the API refused us" is the
# difference between a fix an admin can deploy fleet-wide and a dead end.
function Read-Consent($root) {
  try { return (Get-ItemProperty -Path ($root + '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location') -Name Value -ErrorAction Stop).Value }
  catch { return 'absent' }
}

# TWO gates, and the second is the one that bit us in the field.
#
# HKLM is the machine-wide "Location services" toggle. HKCU is the consent of
# the account making the call — and this process runs as SYSTEM, whose branch
# is S-1-5-18. A fleet was found with HKLM=Allow and SYSTEM=Deny, which reads
# as "location is on" in Settings while every request from the agent is
# refused. Naming WHICH gate is closed is the difference between a one-line GPO
# and days of guessing.
$machine = Read-Consent 'HKLM:'
$account = Read-Consent 'HKCU:'

if ($machine -ne 'Allow') {
  Write-Output ('ERROR:location_services_off machine-wide (HKLM=' + $machine + ')')
  exit 0
}
if ($account -ne 'Allow') {
  Write-Output ('ERROR:location_denied_for_service_account (HKLM=Allow, HKCU=' + $account + '); the agent runs as SYSTEM and that account has no location consent')
  exit 0
}

try {
  [void][Windows.Devices.Geolocation.Geolocator,Windows.Devices.Geolocation,ContentType=WindowsRuntime]
  $locator = New-Object Windows.Devices.Geolocation.Geolocator
  $locator.ReportInterval = 2000
  $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation\`1'
  })[0]
  $asTask = $asTaskGeneric.MakeGenericMethod([Windows.Devices.Geolocation.Geoposition])
  $task = $asTask.Invoke($null, @($locator.GetGeopositionAsync()))
  if (-not $task.Wait(15000)) { Write-Output 'TIMEOUT'; exit 0 }
  $p = $task.Result.Coordinate.Point.Position
  $acc = $task.Result.Coordinate.Accuracy
  Write-Output (ConvertTo-Json -Compress @{
    lat = $p.Latitude; lon = $p.Longitude; accuracyM = $acc
  })
} catch {
  # Most common causes: location services off for the machine, the
  # CapabilityAccessManager consent store denying it, or a Server SKU with no
  # location provider at all. None are recoverable here.
  Write-Output ('ERROR:' + $_.Exception.Message)
}
`;

/**
 * Parse whatever the platform helper printed.
 *
 * Pure and exported: this is the part that must not regress, and it can be
 * exercised without a Windows box or a location permission. Anything that is
 * not a well-formed, in-range coordinate becomes null rather than a guess.
 */
export function parseGeoOutput(stdout: unknown, now: () => Date = () => new Date()): AmpGeo | null {
  const text = typeof stdout === "string" ? stdout.trim() : "";
  if (!text || text === "TIMEOUT" || text.startsWith("ERROR:")) return null;

  let parsed: any;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;

  const lat = Number(parsed.lat);
  const lon = Number(parsed.lon);
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  if (lat < -90 || lat > 90 || lon < -180 || lon > 180) return null;
  // 0,0 is Null Island — a zeroed struct, not a device in the Gulf of Guinea.
  // The backend rejects it too; catching it here saves a pointless round trip.
  if (lat === 0 && lon === 0) return null;

  const accuracy = Number(parsed.accuracyM);

  // Prefer the timestamp the source stamped on the fix. On macOS the reading
  // is taken by the status app minutes before the daemon reads the file, and
  // restamping it as "now" would report a 40-minute-old position as current.
  // Windows has no such gap and simply omits the field.
  const stamped = typeof parsed.collectedAtUtc === "string" ? Date.parse(parsed.collectedAtUtc) : NaN;
  const collectedAtUtc = Number.isFinite(stamped)
    ? new Date(stamped).toISOString()
    : now().toISOString();

  return {
    lat,
    lon,
    // A negative or absent accuracy means "unknown", not "perfect".
    accuracyM: Number.isFinite(accuracy) && accuracy >= 0 ? accuracy : null,
    collectedAtUtc,
  };
}

/** Platforms where we can actually ask the OS. */
export function supportsOsLocation(platform: string = os.platform()): boolean {
  // Linux has no equivalent system service — those devices keep falling back
  // to the operator's CIDR→site mapping, which is exact anyway.
  return platform === "win32" || platform === "darwin";
}

async function collectWindows(): Promise<string> {
  const { stdout } = await execFileAsync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", WINDOWS_SCRIPT],
    { timeout: LOOKUP_TIMEOUT_MS, windowsHide: true, maxBuffer: 1024 * 64 }
  );
  return String(stdout ?? "");
}

/**
 * How old a published macOS fix may be before it is ignored.
 *
 * The status app refreshes every 15 minutes. This window is wider so a single
 * missed cycle (asleep, no Wi-Fi, a failed request) does not blank the
 * location — but it is finite on purpose: if the app is killed, the user
 * revokes permission, or the machine is carried elsewhere with the lid shut,
 * the last known fix must expire rather than be reported as current forever.
 */
const MACOS_FIX_MAX_AGE_MS = 60 * 60 * 1000;

/**
 * Who is logged in at the console.
 *
 * The position is published into that user's own Application Support
 * directory, so the daemon has to know whose home to look in. Returns null on
 * a machine with nobody logged in (login window, pure server), where there is
 * no session that could have collected anything anyway.
 */
export function parseConsoleUser(stdout: unknown): string | null {
  const name = typeof stdout === "string" ? stdout.trim() : "";
  if (!name || name === "root" || name === "loginwindow") return null;
  // Defensive: this value is interpolated into a filesystem path.
  if (!/^[a-zA-Z0-9._-]+$/.test(name)) return null;
  return name;
}

/**
 * Where a user's home actually is.
 *
 * Assuming /Users/<name> is right on the overwhelming majority of Macs and
 * wrong on exactly the fleets most likely to be centrally managed — network and
 * mobile accounts can live anywhere. dscl is the supported way to ask, and the
 * hard-coded guess stays as the fallback.
 */
async function resolveHomeDirectory(user: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync(
      "/usr/bin/dscl",
      [".", "-read", `/Users/${user}`, "NFSHomeDirectory"],
      { timeout: 5_000 }
    );
    const home = String(stdout ?? "").replace(/^NFSHomeDirectory:\s*/, "").trim();
    if (home.startsWith("/")) return home;
  } catch {
    // Directory service unavailable — fall through to the conventional path.
  }
  return path.join("/Users", user);
}

/**
 * Is this published fix recent enough to report?
 *
 * Pure and exported so the staleness rule can be tested without a clock or a
 * filesystem — it is the guard that keeps a dead status app from pinning a
 * laptop to an office it left days ago.
 */
export function isFixFresh(collectedAtUtc: unknown, now: number = Date.now()): boolean {
  if (typeof collectedAtUtc !== "string" || !collectedAtUtc) return false;
  const at = Date.parse(collectedAtUtc);
  if (!Number.isFinite(at)) return false;
  // A timestamp in the future is a clock skew or a forged file, not a fix.
  if (at > now + 60_000) return false;
  return now - at <= MACOS_FIX_MAX_AGE_MS;
}

/**
 * macOS: read what the menubar app published.
 *
 * The daemon cannot call CoreLocation itself — TCC grants location to a signed
 * .app acting in a user session, and this process is a root LaunchDaemon in
 * session 0 with neither. So the signed status app collects and drops the
 * result here. See macos/TraceniumAgentStatus/Sources/LocationProvider.swift.
 */
async function collectMacos(): Promise<string> {
  const { stdout } = await execFileAsync("/usr/bin/stat", ["-f%Su", "/dev/console"], {
    timeout: 5_000,
  });
  const user = parseConsoleUser(stdout);
  // Distinct sentinels instead of a bare "": the three ways macOS produces no
  // position mean three different things to whoever has to act on them.
  if (!user) return "NO_USER";

  const file = path.join(
    await resolveHomeDirectory(user),
    "Library/Application Support/Tracenium/location.json"
  );

  let raw: string;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch {
    // Somebody is logged in but the status app left nothing behind.
    return "NO_PUBLISHER";
  }

  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return "NO_PUBLISHER";
  }

  // Staleness is enforced HERE rather than in the shared parser: it is a
  // macOS-specific concern, because macOS is the only platform where the fix
  // is produced by a separate process that may have stopped running.
  // A stale document means the app stopped refreshing it — same fault as not
  // publishing at all, and equally worth surfacing.
  if (!isFixFresh(parsed?.collectedAtUtc)) return "NO_PUBLISHER";

  return raw;
}

/**
 * One position, or null.
 *
 * `enabled` is the tenant's `features.locationTracking`. It is checked here —
 * not by the caller — so that every path into this module is gated, and the
 * default of `false` means a forgotten check degrades to collecting nothing.
 */
export async function collectGeo(
  enabled: boolean,
  platform: string = os.platform()
): Promise<GeoResult> {
  if (enabled !== true) return { geo: null, status: "disabled" };
  if (!supportsOsLocation(platform)) return { geo: null, status: "unsupported" };

  let stdout = "";
  try {
    stdout = platform === "win32" ? await collectWindows() : await collectMacos();
  } catch (err: any) {
    // Timeout, missing interpreter, a crashed helper. Reported as denied
    // rather than unavailable: in practice this is overwhelmingly the consent
    // store or a locked-down SKU, and "we could not ask" is closer to denied
    // than to "we asked and got nothing".
    return { geo: null, status: "denied", detail: String(err?.message ?? err).slice(0, 300) };
  }

  return {
    geo: parseGeoOutput(stdout),
    status: classifyGeoOutput(stdout),
    detail: extractDetail(stdout),
  };
}

/**
 * Turn the helper's raw output into a reason.
 *
 * Pure, so every branch is testable without an OS that can refuse us.
 */
const PUBLISHED_STATUSES = new Set<GeoStatus>([
  "ok",
  "denied",
  "unavailable",
  "consent_required",
]);

/**
 * The platform's verbatim complaint, or undefined when it did not complain.
 *
 * Pure, so the extraction is testable without an OS that refuses us.
 */
export function extractDetail(stdout: unknown): string | undefined {
  const text = typeof stdout === "string" ? stdout.trim() : "";
  if (!text.startsWith("ERROR:")) return undefined;
  return text.slice("ERROR:".length).trim().slice(0, 300) || undefined;
}

export function classifyGeoOutput(stdout: unknown): GeoStatus {
  const text = typeof stdout === "string" ? stdout.trim() : "";
  // Empty means the platform helper had nothing to give: on macOS that is the
  // status app not running, no console user, or a fix that aged out.
  if (!text) return "unavailable";
  if (text === "NO_USER") return "no_user_session";
  if (text === "NO_PUBLISHER") return "agent_not_publishing";
  if (text === "TIMEOUT") return "unavailable";
  if (text.startsWith("ERROR:")) return "denied";

  // macOS publishes the REASON alongside (or instead of) a fix, because only
  // the user-session app can see the OS permission state. Trust it over
  // anything we could infer from the absence of coordinates.
  try {
    const published = JSON.parse(text)?.status;
    if (typeof published === "string" && PUBLISHED_STATUSES.has(published as GeoStatus)) {
      // A document claiming "ok" without usable coordinates is not ok.
      if (published === "ok") return parseGeoOutput(text) ? "ok" : "unavailable";
      return published as GeoStatus;
    }
  } catch {
    // Not JSON — fall through to the coordinate check below.
  }

  return parseGeoOutput(text) ? "ok" : "unavailable";
}
