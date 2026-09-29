// privsvc/linux/src/patch-management.ts
//
// Patch scan AND install. We dispatch by distro family — debian → apt,
// rhel → dnf (with yum fallback for RHEL 7), suse → zypper.
//
// Exports `handlePatchScan` (read-only) and `handlePatchInstall`, both
// routed from router.ts. The install side runs fully unattended:
// `apt-get install --only-upgrade -y` with --force-confdef/--force-confold
// so operator-edited conffiles survive, DEBIAN_FRONTEND=noninteractive and
// LANG=C for parseable errors; dnf/zypper use `upgrade -y`. Unlike macOS —
// where an Apple Silicon system update needs a volume-owner credential that
// a root daemon cannot supply — root here is sufficient, so Linux patch
// install genuinely works headless.
//
// The likeliest real-world failure is contention for the apt lock against
// the system's own `apt-daily.timer` / unattended-upgrades; that surfaces as
// "E: Could not get lock" and is handled explicitly below.
//
// Scan philosophy:
//   * NEVER run `apt-get update`, `dnf makecache`, or `zypper refresh`
//     here. Those modify repository metadata caches, take seconds-
//     to-minutes on slow links, and on debian-family they require
//     the apt lock — which we'd contend with the system's daily
//     `apt-daily.timer`. The system's own scheduled refresh keeps
//     metadata fresh; we just READ what's there. A customer with
//     stale caches sees stale data, and that's the expected signal
//     for a separate "metadata stale" catalog rule (Phase 8 candidate).
//   * Every command is timeout-bounded + fails closed. A broken /
//     missing tool returns `{ status: "patch_management_unavailable",
//     items: [] }` rather than throwing — the agent's PMP scheduler
//     keeps running for the OTHER namespaces if PMP can't run.
//   * Output bounded: we cap the `items` array at MAX_ITEMS to keep
//     the FACTS_SNAPSHOT under the 4 MB gRPC limit even on a host
//     that's been offline for 2 years and has 8 000 packages
//     waiting to upgrade.
import { execFile } from "child_process";
import { promisify } from "util";
import fs from "fs";
import { detectFamily } from "./distro";
import { logger } from "./logger";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";

const execFileAsync = promisify(execFile);

// Patch-listing commands can take a while on hosts with thousands of
// upgradeable packages or on slow disks. The `apt list --upgradable`
// path on a 4 000-package fleet box hits 8-12 s when apt's cache is
// hot; cold-cache it can hit 30 s. Bump generously.
const SCAN_TIMEOUT_MS = 60_000;

// 5 000 items is far past anything realistic on a maintained host
// (typical Debian box with stale repos: 200-400 upgradeable). Acts
// as a circuit breaker against runaway output on a wildly broken
// machine — the FACTS message stays under gRPC's 4 MB ceiling and
// the operator sees a clear truncation in the dashboard.
const MAX_ITEMS = 5_000;

type ScanResult = {
  status: "updates_available" | "healthy" | "patch_management_unavailable";
  source: "linux_apt" | "linux_dnf" | "linux_zypper" | "patch_management_unavailable";
  scannedAtUtc: string;
  updateCount: number;
  securityUpdateCount: number;
  items: ScanItem[];
  // Diagnostic — surfaced into the agent's logger context. Not
  // stored in PmpScanItem.
  note?: string;
};

type ScanItem = {
  hotFixId?: string;
  title?: string;
  /**
   * El nombre del paquete, COMO DATO.
   *
   * ⚠️ NACE DE UN FALLO EN CAMPO (T118, 28-sep-2026). La instalación recuperaba
   * este nombre parseando `title` con `/^([^:]+):/`, y `title` es un texto de
   * PRESENTACIÓN que esta misma función escribe de dos maneras: con dos puntos
   * cuando conoce la versión instalada y sin ellos cuando no. En una Ubuntu
   * 26.04 donde `apt list --upgradable` no reportaba la versión vieja, 16 de 23
   * pendientes no tenían dos puntos: el parseo no casaba, el paquete se
   * descartaba en silencio y el job se cerraba como `completed` sin instalar
   * nada.
   *
   * El comentario que justificaba aquel parseo decía que el formato con dos
   * puntos era «always true in scan output». Lo desmentía la rama de al lado.
   *
   * Ausente cuando el identificador no ES un paquete: un aviso de dnf
   * (`FEDORA-2026-…`) agrupa varios y se instala con `--advisory`, no por
   * nombre.
   */
  packageName?: string;
  severity?: "critical" | "important" | "moderate" | "low" | "unknown";
  type?: "security" | "bugfix" | "enhancement" | "update";
  cveIds?: string[];
  rebootRequired?: boolean;
  source?: string;
};

/**
 * Strips ANSI escape sequences from command output.
 *
 * apt 3.0 colourises its diagnostics even when stdout/stderr are pipes rather
 * than a terminal. Two things break as a result:
 *
 *   1. The escape bytes end up verbatim in the scan `note`, which is rendered
 *      to an operator in the dashboard — a diagnostic nobody can read is not a
 *      diagnostic. A real one from the field read:
 *        apt list failed: \x1b[1;33mWarning: \x1b[0m\x1b[1mUnable to read ...
 *
 *   2. More dangerous: the upgradable-package parser matches on line shape.
 *      A colourised stdout would simply fail to match, yielding zero items —
 *      indistinguishable from a machine with nothing to upgrade. That is the
 *      exact silent-failure mode this plugin has already been bitten by.
 *
 * Colour carries no information for a machine reader, so it is removed from
 * both streams at the point of capture rather than at each use site.
 */
export function stripAnsi(text: string): string {
  // CSI sequences (colour, cursor moves) plus stray OSC strings.
  // eslint-disable-next-line no-control-regex
  return text.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "").replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "");
}

async function runCmd(bin: string, args: string[]): Promise<{ stdout: string; stderr: string; code: number | null }> {
  try {
    const { stdout, stderr } = await execFileAsync(bin, args, {
      timeout: SCAN_TIMEOUT_MS,
      maxBuffer: 16 * 1024 * 1024, // 16 MB — `dnf updateinfo --list` on RHEL with 800 advisories ~3 MB
      // ⚠️ EL IDIOMA DEL EQUIPO CAMBIABA LO QUE ENTENDÍAMOS DE ÉL. Todo lo que
      // sale de aquí se parsea con expresiones en INGLÉS —`[upgradable from:
      // …]` en apt, las cabeceras de `dnf check-update`— y apt y dnf traducen su
      // salida al idioma del sistema. En un equipo en español la cadena es
      // `[actualizable desde: …]`, el grupo opcional no casa NUNCA y la versión
      // instalada se pierde en silencio.
      //
      // Visto en campo el 28-sep-2026: en `usuariohl-HP-14` (T118, Ubuntu 26.04)
      // los 23 pendientes salían sin versión vieja, mientras en T1 —un equipo en
      // inglés— casaban los 29. El mismo código, dos comportamientos, y la
      // diferencia era el idioma del portátil.
      //
      // `runInstall` ya fijaba el locale por esto mismo, con un comentario sobre
      // errores de apt en francés. El camino de ESCANEO nunca lo hizo.
      env: { ...process.env, LANG: "C", LC_ALL: "C" },
    });
    return { stdout: stripAnsi(stdout || ""), stderr: stripAnsi(stderr || ""), code: 0 };
  } catch (err: any) {
    return {
      stdout: stripAnsi(err?.stdout || ""),
      stderr: stripAnsi(err?.stderr || ""),
      code: typeof err?.code === "number" ? err.code : null,
    };
  }
}

function unavailable(reason: string): ScanResult {
  return {
    status: "patch_management_unavailable",
    source: "patch_management_unavailable",
    scannedAtUtc: new Date().toISOString(),
    updateCount: 0,
    securityUpdateCount: 0,
    items: [],
    note: reason,
  };
}

function truncateItems(items: ScanItem[]): ScanItem[] {
  if (items.length <= MAX_ITEMS) return items;
  logger.warn("patch_scan_items_truncated", { received: items.length, cap: MAX_ITEMS });
  return items.slice(0, MAX_ITEMS);
}

// ── debian (apt) ──────────────────────────────────────────────────
//
// Strategy:
//   1. `apt list --upgradable` for the full upgradeable set. Output
//      lines look like:
//        openssl/jammy-security 3.0.2-0ubuntu1.21 amd64 [upgradable from: 3.0.2-0ubuntu1.18]
//      The `<suite>` after the slash carries the source pocket; we
//      tag any `*-security` pocket as type=security for the catalog.
//   2. We don't cross-reference CVE feeds — apt doesn't ship advisory
//      metadata locally. CVE drilldowns will need a future Phase 6.5
//      that calls `unattended-upgrades --debug --dry-run` (which lists
//      USN/CVE refs) on a slower cadence. For Phase 6 MVP, security
//      tagging by pocket is the 80% answer.
//   3. Reboot-required hint: if `linux-image-*` or `linux-headers-*`
//      appears in the upgradeable list we set rebootRequired=true on
//      those items. The catalog can layer additional logic if needed.
//
// Note: `apt` (the human-targeted CLI) prints a deprecation warning
// to stderr ("WARNING: apt does not have a stable CLI...") that we
// silence by piping stderr to /dev/null at the runCmd level. Output
/**
 * Las actualizaciones pendientes a partir de la salida de `apt list --upgradable`.
 *
 * ⚠️ EXPORTADA Y PURA A PROPÓSITO. Este parseo estaba enterrado dentro de
 * `scanApt`, detrás de un `execFile`, así que NADIE podía probarlo — y lo que no
 * se puede probar es donde vivió cinco días un fallo que cerraba jobs de parcheo
 * como `completed` sin instalar nada (T118, 28-sep-2026). Sacarlo no es estética:
 * es la única forma de fijar con un test lo que la salida real del comando hace.
 */
export function parseAptUpgradable(stdout: string): ScanItem[] {
  const lines = stdout.split("\n").filter(l => l.trim() && !l.startsWith("Listing"));
  const items: ScanItem[] = [];

  for (const line of lines) {
    // openssl/jammy-security 3.0.2-0ubuntu1.21 amd64 [upgradable from: 3.0.2-0ubuntu1.18]
    const match = line.match(/^([^/]+)\/(\S+)\s+(\S+)\s+\S+\s*(?:\[upgradable from:\s*(\S+)\])?/);
    if (!match) continue;

    const pkg = match[1];
    const suite = match[2];
    const newVersion = match[3];
    const oldVersion = match[4];

    // Pocket-based security detection. Ubuntu/Debian conventionally
    // suffix security pockets with `-security`. ESM (Extended
    // Security Maintenance) uses `-security` too. Anything else
    // (jammy-updates, jammy-backports) is treated as a non-security
    // update.
    const isSecurity = /-security(\b|$)/.test(suite);

    // Kernel/glibc/systemd → reboot-required. We're conservative
    // here; the catalog can decide whether to surface this as a
    // dashboard hint.
    const rebootRequired = /^(linux-image-|linux-headers-|linux-modules-|libc6$|systemd$)/.test(pkg);

    items.push({
      hotFixId: `${pkg}-${newVersion}`,
      // El nombre va como dato. `title` sigue siendo para leerlo un humano —y
      // por eso tiene dos formas—, pero ya no es de donde se saca el paquete.
      packageName: pkg,
      title: oldVersion
        ? `${pkg}: ${oldVersion} → ${newVersion}`
        : `${pkg} ${newVersion}`,
      severity: isSecurity ? "important" : "unknown",
      type: isSecurity ? "security" : "update",
      rebootRequired,
      source: `apt:${suite}`,
    });

    if (items.length >= MAX_ITEMS) break;
  }

  return items;
}

// shape on stdout is stable enough for Phase 6 use.
async function scanApt(): Promise<ScanResult> {
  const r = await runCmd("/usr/bin/apt", ["list", "--upgradable"]);

  if (r.code !== 0 && !r.stdout) {
    return unavailable(`apt list failed: ${r.stderr || "no output"}`);
  }

  const items = parseAptUpgradable(r.stdout);
  // ⚠️ UNA SEÑAL PARA QUE ESTO NO VUELVA A PASAR CALLADO. Un paquete listado por
  // `apt list --upgradable` está instalado por definición, así que SIEMPRE trae
  // su versión actual. Que falte no significa «no la hay»: significa que no
  // supimos leerla —el locale se nos escapó, o apt cambió el formato— y eso hay
  // que decirlo, porque fue lo que enmascaró el fallo de T118 durante el tiempo
  // que estuvo activo.
  const sinVersionVieja = items.filter(it => it.title && !it.title.includes(" → ")).length;
  const note =
    items.length > 0 && sinVersionVieja === items.length
      ? `apt listed ${items.length} upgradable package(s) and NONE reported an installed version; ` +
        `the "[upgradable from: …]" field was not parsed — apt's output format or locale may have changed`
      : undefined;

  return {
    status: items.length > 0 ? "updates_available" : "healthy",
    source: "linux_apt",
    scannedAtUtc: new Date().toISOString(),
    updateCount: items.length,
    securityUpdateCount: items.filter(i => i.type === "security").length,
    items: truncateItems(items),
    ...(note ? { note } : {}),
  };
}

// ── rhel (dnf / yum) ──────────────────────────────────────────────
//
// dnf has the cleanest patch metadata of the three families: every
// security update is shipped as an advisory (RHSA-/ALSA-/RLSA-/etc)
// with a severity tag and a CVE list. We grab two streams and
// correlate:
//
//   1. `dnf updateinfo list --quiet` → advisory id + severity + package
//        Important/Sec.   RHSA-2024-1234   openssl-1:3.0.7-30.el9_2.x86_64
//   2. `dnf check-update --quiet`     → bare upgradeable packages
//        package.arch    new-version    repo
//
// (1) covers security advisories with their severity, (2) covers
// non-security upgrades. Concatenating gives us the full picture.
//
// RHEL 7 still uses yum. The `yum updateinfo` CLI shape is similar
// enough that we use the same parser; the `yum check-update` shape
// is identical to dnf's. The only practical difference is that
// `dnf` is in /usr/bin on RHEL 8+ and `yum` lives in /usr/bin on
// RHEL 7. We probe + dispatch.
async function scanDnf(): Promise<ScanResult> {
  const dnfBin = fs.existsSync("/usr/bin/dnf")
    ? "/usr/bin/dnf"
    : fs.existsSync("/usr/bin/yum")
      ? "/usr/bin/yum"
      : null;

  if (!dnfBin) {
    return unavailable("neither dnf nor yum found in /usr/bin");
  }

  // updateinfo — security/bugfix/enhancement advisories with severity.
  // We use --list (not the default summary) which prints one advisory
  // per line in the parsable shape:
  //   FEDORA-2024-abc123 important/Sec. openssl-3.0.7-30.fc40.x86_64
  //
  // Quiet mode strips the "Updating Subscription Management
  // repositories" preamble that breaks naive line counting.
  const advisoryMap = new Map<string, ScanItem>();
  const ui = await runCmd(dnfBin, ["updateinfo", "list", "--quiet"]);
  if (ui.stdout) {
    for (const line of ui.stdout.split("\n")) {
      // Format: <advisory>  <severity>/<type>  <pkg-NVR>
      // type tokens dnf emits: Sec., bugfix, enhancement, newpackage
      const match = line.trim().match(/^(\S+)\s+(\S+)\s+(\S+)$/);
      if (!match) continue;

      const advisoryId = match[1];
      const tag = match[2].toLowerCase();
      const pkgNvr = match[3];

      // Skip headers like "Updates Information ID..."
      if (advisoryId.toLowerCase() === "updates" || advisoryId.startsWith("===")) continue;

      // Severity parsing. dnf emits forms like:
      //   "important/sec." → severity=important, type=security
      //   "moderate/sec."  → severity=moderate, type=security
      //   "low/sec."       → severity=low, type=security
      //   "critical/sec."  → severity=critical, type=security
      //   "bugfix"         → severity=unknown, type=bugfix
      //   "enhancement"    → severity=unknown, type=enhancement
      //   "newpackage"     → severity=unknown, type=update
      let severity: ScanItem["severity"] = "unknown";
      let type: ScanItem["type"] = "update";
      const [sevPart, typePart] = tag.split("/");
      if (typePart === "sec." || typePart === "sec") {
        type = "security";
        if (sevPart === "critical" || sevPart === "important" || sevPart === "moderate" || sevPart === "low") {
          severity = sevPart;
        }
      } else if (sevPart === "bugfix") {
        type = "bugfix";
      } else if (sevPart === "enhancement") {
        type = "enhancement";
      }

      advisoryMap.set(advisoryId, {
        hotFixId: advisoryId,
        // Sin `packageName` A PROPÓSITO: un aviso agrupa varios paquetes y se
        // instala con `--advisory=<id>`. Ponerle el nombre de uno de ellos
        // instalaría una parte del aviso y lo daría por entero.
        title: `${advisoryId}: ${pkgNvr}`,
        severity,
        type,
        source: `dnf:advisory`,
      });
    }
  }

  // check-update — bare upgradeable packages. Some advisory packages
  // already appear via updateinfo; we add only the ones NOT covered.
  // Exit 100 = updates available, 0 = none, anything else = error.
  const cu = await runCmd(dnfBin, ["check-update", "--quiet"]);
  const items: ScanItem[] = Array.from(advisoryMap.values());

  if (cu.stdout) {
    for (const line of cu.stdout.split("\n")) {
      // Format: <pkg.arch>  <new-version>  <repo>
      // Skip blank lines, "Obsoleting Packages" headers, and
      // continuation lines (start with whitespace).
      if (!line || line.startsWith(" ") || line.toLowerCase().includes("obsoleting")) continue;
      const match = line.trim().match(/^(\S+)\s+(\S+)\s+(\S+)$/);
      if (!match) continue;

      const pkgArch = match[1];
      const version = match[2];
      const repo = match[3];

      // Already covered by updateinfo? Skip — the advisory entry
      // has more useful metadata.
      const dupKey = `${pkgArch}-${version}`;
      if (Array.from(advisoryMap.values()).some(it => it.title?.includes(pkgArch))) continue;

      const rebootRequired = /^kernel(-|$)|^glibc(-|$)|^systemd(-|$)/.test(pkgArch);

      items.push({
        hotFixId: dupKey,
        packageName: pkgArch,
        title: `${pkgArch}: ${version}`,
        severity: "unknown",
        type: "update",
        rebootRequired,
        source: `dnf:repo:${repo}`,
      });

      if (items.length >= MAX_ITEMS) break;
    }
  }

  return {
    status: items.length > 0 ? "updates_available" : "healthy",
    source: "linux_dnf",
    scannedAtUtc: new Date().toISOString(),
    updateCount: items.length,
    securityUpdateCount: items.filter(i => i.type === "security").length,
    items: truncateItems(items),
  };
}

// ── suse (zypper) ─────────────────────────────────────────────────
//
// Stub for Phase 6. SUSE support is deferred to Phase 10 per the
// implementation plan; we return `patch_management_unavailable`
// here so a SUSE host doesn't show up as "PMP error" — it shows up
// as "PMP not implemented for this distro family", which is a clean
// not_applicable on the dashboard.
async function scanZypper(): Promise<ScanResult> {
  return unavailable("SUSE / openSUSE patch scan deferred to Phase 10");
}

// ── Aggregate dispatcher ──────────────────────────────────────────
async function runScan(): Promise<ScanResult> {
  const distro = detectFamily();
  logger.info("patch_scan_start", {
    family: distro.family,
    distro: distro.id,
    versionId: distro.versionId,
  });

  if (distro.family === "debian") return scanApt();
  if (distro.family === "rhel") return scanDnf();
  if (distro.family === "suse") return scanZypper();

  return unavailable(`unsupported family: ${distro.family} (id=${distro.id})`);
}

export async function handlePatchScan(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    const result = await runScan();
    logger.info("patch_scan_complete", {
      status: result.status,
      source: result.source,
      updateCount: result.updateCount,
      securityUpdateCount: result.securityUpdateCount,
      note: result.note,
    });
    return success(req.id, result);
  } catch (err: any) {
    logger.error("patch_scan_failed", { error: err?.message || String(err) });
    return fail(req.id, "patch_scan_failed", err?.message || String(err));
  }
}

// =====================================================================
// Phase 7 — Patch install
// =====================================================================
//
// Contract (mirror of macOS handler shape, verified against the
// agent-side ack reducer in src/transport/grpc-stream.ts case
// "patch_install"):
//
//   request:
//     params.mode          "install" | "download"
//     params.kbArticleIds  string[]  — hotFixId values from the
//                                       previous scan. Empty array =
//                                       "everything available".
//
//   response:
//     status               "success" | "partial" | "failed" | "no_updates"
//     mode                 echoed
//     selectedCount        items we actually attempted
//     installedCount       confirmed successes
//     failedCount
//     rebootRequired       boolean
//     results[]            per-item { updateId, kb, title, result, message? }
//
// Install timeouts: 60 minutes outer cap. Long enough for a fresh
// machine catching up on 2 GB of upgrades; short enough that an
// operator-cancelled run doesn't pin the daemon. apt and dnf both
// honour the SIGTERM that kicks in at timeout — they roll back to
// a consistent dpkg/rpmdb state on interrupt, so a kill mid-install
// never corrupts the package database.

const INSTALL_TIMEOUT_MS = 60 * 60 * 1000;

type InstallItemResult = {
  updateId?: string;
  kb?: string;
  title?: string;
  result: "installed" | "downloaded" | "failed" | "skipped";
  message?: string;
};

type InstallResult = {
  status: "success" | "partial" | "failed" | "no_updates";
  mode: "install" | "download";
  selectedCount: number;
  installedCount: number;
  failedCount: number;
  rebootRequired: boolean;
  results: InstallItemResult[];
};

// Run a long-lived install command. Same contract as runCmd above
// but with the install-scoped timeout and an env override slot so
// callers can drop in DEBIAN_FRONTEND=noninteractive (apt) without
// polluting the privsvc's own environment.
async function runInstall(
  bin: string,
  args: string[],
  env?: Record<string, string>
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  try {
    const { stdout, stderr } = await execFileAsync(bin, args, {
      timeout: INSTALL_TIMEOUT_MS,
      maxBuffer: 32 * 1024 * 1024, // 32 MB — verbose apt-get on 500-pkg upgrade can hit ~10 MB
      env: env ? { ...process.env, ...env } : process.env,
    });
    return { stdout: stripAnsi(stdout || ""), stderr: stripAnsi(stderr || ""), code: 0 };
  } catch (err: any) {
    return {
      stdout: stripAnsi(err?.stdout || ""),
      stderr: stripAnsi(err?.stderr || ""),
      code: typeof err?.code === "number" ? err.code : null,
    };
  }
}

// Result-shape helper. Centralises the "every selected item became X"
// pattern so install paths don't repeat the same map() at three exit
// points each.
/**
 * El motivo cuando un identificador pedido no se puede resolver a un paquete.
 *
 * ⚠️ TIENE QUE DECIR QUÉ HACER. «no se encontró» deja al operador pensando que
 * el parche no existe; lo que suele pasar es que ya se instaló por otra vía o
 * que el escaneo que pintó la lista es viejo, y en los dos casos la salida es la
 * misma: volver a escanear y mirar.
 */
const UNRESOLVED_REASON =
  "not present in the live upgradable list — it may already be installed, or the " +
  "scan behind this list is stale; re-scan the device and check again";

function eachAs(items: ScanItem[], result: InstallItemResult["result"], message?: string): InstallItemResult[] {
  return items.map(it => ({
    updateId: it.hotFixId,
    title: it.title,
    result,
    ...(message ? { message } : {}),
  }));
}

// ── debian / apt install ──────────────────────────────────────────
//
// apt's lock files (`/var/lib/dpkg/lock-frontend`,
// `/var/lib/dpkg/lock`, `/var/lib/apt/lists/lock`) are conventionally
// held by other system processes:
//   * apt-daily.timer / apt-daily-upgrade.timer (Ubuntu/Debian
//     systemd timers running 1-2× daily, holding ~5-15 minutes)
//   * unattended-upgrades (security upgrades, autonomous)
//   * packagekit (GUI installer backends, GNOME Software, etc.)
//
// Racing against any of them → apt aborts with "Could not get lock
// /var/lib/dpkg/lock-frontend". Rather than collide, we probe via
// `fuser` BEFORE invoking apt. If anyone holds the lock, return a
// `failed` result tagged with reason="lock_busy" so the orchestrator
// retries on the next scheduled tick.
async function isAptLockBusy(): Promise<{ busy: boolean; holder?: string }> {
  // `fuser` prints PIDs to stderr (yes, stderr, by design — it
  // separates the file path on stdout from the PID list). Exit 1
  // means "no one is using the file" — the case we want.
  const r = await runCmd("/usr/bin/fuser", [
    "/var/lib/dpkg/lock-frontend",
    "/var/lib/dpkg/lock",
    "/var/lib/apt/lists/lock",
  ]);
  if (r.code === 1 || (!r.stdout && !r.stderr)) return { busy: false };

  // Best-effort holder identification (just for the log message).
  // Output looks like "  1234  5678" on stderr — first PID is enough.
  const pidMatch = (r.stderr || r.stdout).match(/(\d+)/);
  return { busy: true, holder: pidMatch ? `pid=${pidMatch[1]}` : "unknown" };
}

async function installApt(
  selectedItems: ScanItem[],
  mode: "install" | "download",
  selectAll: boolean
): Promise<InstallResult> {
  // Lock probe. If something else is holding apt, fail fast with a
  // recognisable reason so the orchestrator doesn't waste 60 min
  // waiting for our timeout to fire.
  const lock = await isAptLockBusy();
  if (lock.busy) {
    logger.warn("apt_install_lock_busy", { holder: lock.holder });
    return {
      status: "failed",
      mode,
      selectedCount: selectedItems.length,
      installedCount: 0,
      failedCount: selectedItems.length,
      rebootRequired: false,
      results: eachAs(selectedItems, "failed", `lock_busy:${lock.holder || "unknown"}`),
    };
  }

  // Build the package name list. apt's hotFixId is `<pkg>-<version>`
  // — the version part can contain hyphens too, so we re-resolve via
  // the live upgradable list and match by hotFixId. This costs one
  // extra `apt list --upgradable` (~200 ms cached) and avoids the
  // ambiguous suffix-strip parser we'd otherwise need.
  let packageNames: string[] = [];
  /** Lo que el operador pidió y NO se pudo resolver. Nunca se calla. */
  const unresolved: ScanItem[] = [];

  if (selectAll) {
    // Empty kbArticleIds → "everything available". Don't enumerate;
    // pass nothing to apt-get so it picks up the full upgradeable
    // set via dist-upgrade semantics.
    packageNames = [];
  } else {
    const fresh = await scanApt();
    const byId = new Map(fresh.items.map(it => [it.hotFixId, it]));
    for (const want of selectedItems) {
      const found = want.hotFixId ? byId.get(want.hotFixId) : undefined;
      // ⚠️ EL NOMBRE SALE DEL DATO, NO DE PARSEAR `title`. Hasta el 28-sep-2026
      // esto hacía `found.title?.match(/^([^:]+):/)` sobre un texto de
      // presentación que el escáner escribe de DOS formas —con dos puntos sólo
      // cuando conoce la versión instalada—, y el `if` no tenía `else`: en una
      // Ubuntu 26.04 donde apt no reportaba la versión vieja, 16 de 23
      // pendientes se descartaban en silencio y el job salía `completed` sin
      // haber instalado nada (T118, job a6b4c204).
      const name = found?.packageName?.trim();
      if (name) {
        packageNames.push(name);
      } else {
        // Ni lo encontramos en el escaneo fresco, ni el escaneo nos dio nombre.
        // Las dos cosas son «no puedo con esto», y las dos tienen que salir.
        unresolved.push(want);
      }
    }
    // Dedupe — agent-side bulk-install can request the same pkg from
    // both a security tag and a regular tag.
    packageNames = Array.from(new Set(packageNames));

    if (packageNames.length === 0) {
      // ⚠️ ESTO NO ES `no_updates`, Y LA DIFERENCIA ES EL BUG. El operador
      // nombró paquetes y no se resolvió ninguno: eso no es «no había nada que
      // hacer», es «no encontré lo que pediste». Reportarlo como `no_updates`
      // hacía que el agente lo ACKeara con éxito y el portal lo cerrara como
      // `completed`, sobre un equipo donde el parche seguía pendiente.
      //
      // `no_updates` queda para lo que de verdad lo es: un `selectAll` sin nada
      // pendiente, que no pasa por aquí.
      return {
        status: "failed",
        mode,
        selectedCount: selectedItems.length,
        installedCount: 0,
        failedCount: selectedItems.length,
        rebootRequired: false,
        results: eachAs(selectedItems, "failed", UNRESOLVED_REASON),
      };
    }
  }

  // Build args.
  //   --only-upgrade  : refuse to install packages that aren't
  //                     already installed (we never want to add new
  //                     packages — only upgrade existing ones).
  //   -y --no-install-recommends : non-interactive; don't pull in
  //                     "Recommends" packages (those would expand
  //                     the install footprint beyond what the
  //                     operator approved).
  //   --download-only : when mode=download, fetch but don't unpack.
  //                     Useful for staged rollouts.
  //   -o Dpkg::Options::='--force-confdef': keep existing /etc
  //                     conffiles on conflict, don't prompt.
  //   -o Dpkg::Options::='--force-confold': prefer the on-disk version
  //                     of conf files — operator edits survive.
  //
  // The two -o flags together reproduce the conventional "unattended"
  // dpkg behaviour. unattended-upgrades.conf uses the same pair.
  const args: string[] = [
    "install",
    "--only-upgrade",
    "-y",
    "--no-install-recommends",
    "-o", "Dpkg::Options::=--force-confdef",
    "-o", "Dpkg::Options::=--force-confold",
  ];
  if (mode === "download") {
    args.push("--download-only");
  }
  if (selectAll) {
    // No specific packages → fall back to dist-upgrade semantics.
    // `apt-get dist-upgrade` is the right verb when we want apt to
    // decide what to upgrade.
    args[0] = "dist-upgrade";
  } else {
    args.push(...packageNames);
  }

  logger.info("apt_install_start", {
    mode,
    selectAll,
    packageCount: packageNames.length,
    sampleNames: packageNames.slice(0, 10),
  });

  const r = await runInstall("/usr/bin/apt-get", args, {
    DEBIAN_FRONTEND: "noninteractive",
    // LANG=C ensures parseable English output regardless of
    // operator-set locales — French apt errors break our regex
    // matching for "E: Could not get lock".
    LANG: "C",
    LC_ALL: "C",
  });

  // Detect post-install reboot requirement. apt-listchanges drops
  // /var/run/reboot-required when a package needs a reboot (kernel
  // / glibc / systemd / dbus). The file may not exist on stripped-
  // down systems, in which case our heuristic from scan stays in
  // place via the per-item rebootRequired flag.
  let rebootRequired = false;
  try {
    rebootRequired = fs.existsSync("/var/run/reboot-required");
  } catch {}

  // dist-upgrade or single-package install returned 0 → success.
  // dpkg's exit codes for install are: 0 = success, anything else
  // means at least one package failed. Without parsing per-package
  // outcome (apt-get doesn't expose it cleanly), we report
  //   exit 0  → all selected installed
  //   exit !0 → status:partial if dpkg lines say at least one was
  //             "Setting up", else status:failed
  const wasInstall = mode === "install";
  const wasDownload = mode === "download";
  const successResult: InstallItemResult["result"] = wasInstall ? "installed" : "downloaded";

  if (r.code === 0) {
    logger.info("apt_install_ok", {
      mode,
      packageCount: packageNames.length || "all",
      rebootRequired,
    });
    const installedCount = packageNames.length;

    // ⚠️ LA SEGUNDA MITAD DE LA MENTIRA. `eachAs(selectedItems, ...)` marcaba
    // como instalado TODO lo pedido, incluido lo que nunca se llegó a pasar a
    // apt. Con dos paquetes buenos y uno irresoluble, apt sale 0 y los tres
    // salían instalados. apt sólo puede responder por lo que le dimos.
    if (unresolved.length > 0) {
      const enviados = selectedItems.filter(it => !unresolved.includes(it));
      logger.warn("apt_install_partial_unresolved", {
        installed: enviados.length,
        unresolved: unresolved.length,
        sampleUnresolved: unresolved.slice(0, 5).map(it => it.hotFixId),
      });
      return {
        status: "partial",
        mode,
        selectedCount: selectedItems.length,
        installedCount,
        failedCount: unresolved.length,
        rebootRequired,
        results: [
          ...eachAs(enviados, successResult),
          ...eachAs(unresolved, "failed", UNRESOLVED_REASON),
        ],
      };
    }

    return {
      status: "success",
      mode,
      selectedCount: selectedItems.length,
      installedCount,
      failedCount: 0,
      rebootRequired,
      results: eachAs(selectedItems, successResult),
    };
  }

  // Non-zero exit. Try to count successful "Setting up <pkg>" lines
  // in stdout to detect partial success. Each successful unpack +
  // configure produces one such line.
  const setUpCount = (r.stdout.match(/^Setting up /gm) || []).length;
  const failedTail = (r.stderr || "").split("\n").slice(-5).join(" | ");

  if (wasDownload && r.code === 0) {
    // Already handled above, but defensive.
    return {
      status: "success", mode, selectedCount: selectedItems.length,
      installedCount: packageNames.length, failedCount: 0,
      rebootRequired: false, results: eachAs(selectedItems, "downloaded"),
    };
  }

  if (setUpCount > 0 && setUpCount < (packageNames.length || selectedItems.length)) {
    logger.warn("apt_install_partial", { setUpCount, failedTail, rebootRequired });
    return {
      status: "partial",
      mode,
      selectedCount: selectedItems.length,
      installedCount: setUpCount,
      failedCount: Math.max(0, (packageNames.length || selectedItems.length) - setUpCount),
      rebootRequired,
      results: [
        ...selectedItems.slice(0, setUpCount).map(it => ({ updateId: it.hotFixId, title: it.title, result: successResult } as InstallItemResult)),
        ...selectedItems.slice(setUpCount).map(it => ({ updateId: it.hotFixId, title: it.title, result: "failed" as const, message: failedTail })),
      ],
    };
  }

  logger.error("apt_install_failed", { code: r.code, failedTail });
  return {
    status: "failed",
    mode,
    selectedCount: selectedItems.length,
    installedCount: 0,
    failedCount: selectedItems.length,
    rebootRequired,
    results: eachAs(selectedItems, "failed", failedTail || `apt-get exited ${r.code}`),
  };
}

// ── rhel / dnf install ────────────────────────────────────────────
//
// dnf's `lock` semantics differ from apt's: dnf waits up to 10 min
// for the lock by default (`--setopt=metadata_expire=...`) and only
// errors out if the wait expires. So we skip pre-probe and rely on
// dnf's own waiter; our 60 min outer timeout absorbs even a
// cron-driven `dnf-automatic` collision.
//
// Item classification: dnf hotFixIds come in two shapes from Phase 6:
//   * advisory id    "RHSA-2024-1234", "ALSA-2024:1234", "FEDORA-2024-abc"
//                    Install via `dnf upgrade --advisory=id1,id2,...`.
//   * pkg-version    "openssl.x86_64-3.0.7-30.el9_2"
//                    Install via package-name extracted from prefix.
//
// Heuristic: advisory IDs always start with uppercase letters
// followed by `-` and a 4-digit year. Package IDs start with the
// package name (lowercase by Linux convention). Edge cases (an rpm
// named `RHSA`-something) are vanishingly rare and would surface
// as a `dnf: no advisory found by id` error which we'd report as
// failed — acceptable.
const ADVISORY_ID_RE = /^[A-Z]{2,8}-\d{4}[-:]/;

function classifyDnfHotFixIds(items: ScanItem[]): { advisories: string[]; packages: string[] } {
  const advisories: string[] = [];
  const packages: string[] = [];
  for (const it of items) {
    if (!it.hotFixId) continue;
    if (ADVISORY_ID_RE.test(it.hotFixId)) {
      advisories.push(it.hotFixId);
    } else {
      // Trim arch suffix + version. hotFixId "openssl.x86_64-3.0.7-30.el9_2"
      // → package "openssl". The first dot is the arch separator.
      const pkg = it.hotFixId.split(".")[0];
      if (pkg) packages.push(pkg);
    }
  }
  return {
    advisories: Array.from(new Set(advisories)),
    packages: Array.from(new Set(packages)),
  };
}

async function detectRhelRebootRequired(): Promise<boolean> {
  // `needs-restarting -r` from `dnf-utils` (RHEL 8+) / `yum-utils`
  // (RHEL 7). Exit 1 = "Reboot is required to fully utilize these
  // updates." Exit 0 = no reboot needed. Other codes (binary
  // missing, transient error) → assume false rather than surfacing
  // a wrong "yes" that prompts an operator to restart unnecessarily.
  const r = await runCmd("/usr/bin/needs-restarting", ["-r"]);
  return r.code === 1;
}

async function installDnf(
  selectedItems: ScanItem[],
  mode: "install" | "download",
  selectAll: boolean
): Promise<InstallResult> {
  const dnfBin = fs.existsSync("/usr/bin/dnf")
    ? "/usr/bin/dnf"
    : fs.existsSync("/usr/bin/yum")
      ? "/usr/bin/yum"
      : null;

  if (!dnfBin) {
    return {
      status: "failed",
      mode,
      selectedCount: selectedItems.length,
      installedCount: 0,
      failedCount: selectedItems.length,
      rebootRequired: false,
      results: eachAs(selectedItems, "failed", "no dnf or yum binary found"),
    };
  }

  // For "install all available", we use `dnf upgrade --security -y`
  // when no specific items requested — Phase 6 already established
  // that the agent-side bulk-install path filters by severity, so
  // "all" in this context typically means "all of severity=X".
  // We mirror the agent's intent: empty kbArticleIds → upgrade
  // everything (NOT just security), and the orchestrator decides
  // upstream what counts.
  let args: string[] = ["upgrade", "-y"];

  if (mode === "download") {
    args.push("--downloadonly");
  }

  if (!selectAll) {
    const { advisories, packages } = classifyDnfHotFixIds(selectedItems);

    if (advisories.length === 0 && packages.length === 0) {
      return {
        status: "no_updates", mode,
        selectedCount: 0, installedCount: 0, failedCount: 0,
        rebootRequired: false, results: [],
      };
    }

    if (advisories.length > 0) {
      // dnf accepts comma-separated advisory IDs. yum (RHEL 7) uses
      // `--advisory=` too — same flag works on both.
      args.push(`--advisory=${advisories.join(",")}`);
    }

    if (packages.length > 0) {
      args.push(...packages);
    }
  }

  logger.info("dnf_install_start", {
    bin: dnfBin,
    mode,
    selectAll,
    args: args.slice(0, 10), // cap log line
  });

  const r = await runInstall(dnfBin, args, {
    LANG: "C",
    LC_ALL: "C",
  });

  const rebootRequired = await detectRhelRebootRequired();
  const successResult: InstallItemResult["result"] = mode === "download" ? "downloaded" : "installed";

  if (r.code === 0) {
    // dnf prints "Upgraded:" + package list at the end of stdout on
    // success. Counting those lines gives us actual install count
    // (vs trusting selectedItems.length which may include dependencies
    // that dnf decided weren't needed).
    const upgradedMatch = r.stdout.match(/^Upgraded:\s*$([\s\S]*?)^Complete!/m);
    const upgradedCount = upgradedMatch
      ? (upgradedMatch[1].match(/^\s+\S+\.\S+\s+\S+/gm) || []).length
      : selectedItems.length;

    logger.info("dnf_install_ok", { upgradedCount, rebootRequired });
    return {
      status: "success",
      mode,
      selectedCount: selectedItems.length,
      installedCount: upgradedCount,
      failedCount: 0,
      rebootRequired,
      results: eachAs(selectedItems, successResult),
    };
  }

  // dnf returns 1 on partial/full failure. Parse `Failed:` block.
  const failedTail = (r.stderr || r.stdout).split("\n").slice(-10).join(" | ");
  logger.error("dnf_install_failed", { code: r.code, failedTail });

  return {
    status: "failed",
    mode,
    selectedCount: selectedItems.length,
    installedCount: 0,
    failedCount: selectedItems.length,
    rebootRequired,
    results: eachAs(selectedItems, "failed", failedTail || `dnf exited ${r.code}`),
  };
}

// ── suse / zypper install ─────────────────────────────────────────
//
// Stub for Phase 7. Returns failed-with-reason so the orchestrator
// gets a clear "not implemented" signal instead of a hung job. Phase
// 10 lands the real implementation.
async function installZypper(selectedItems: ScanItem[], mode: "install" | "download"): Promise<InstallResult> {
  return {
    status: "failed",
    mode,
    selectedCount: selectedItems.length,
    installedCount: 0,
    failedCount: selectedItems.length,
    rebootRequired: false,
    results: eachAs(selectedItems, "failed", "SUSE / openSUSE patch install deferred to Phase 10"),
  };
}

// ── Aggregate dispatcher ──────────────────────────────────────────
async function runInstall_(
  selectedItems: ScanItem[],
  mode: "install" | "download",
  selectAll: boolean
): Promise<InstallResult> {
  const distro = detectFamily();
  logger.info("patch_install_start", {
    family: distro.family,
    distro: distro.id,
    mode,
    selectAll,
    selectedCount: selectedItems.length,
  });

  if (distro.family === "debian") return installApt(selectedItems, mode, selectAll);
  if (distro.family === "rhel") return installDnf(selectedItems, mode, selectAll);
  if (distro.family === "suse") return installZypper(selectedItems, mode);

  return {
    status: "failed",
    mode,
    selectedCount: selectedItems.length,
    installedCount: 0,
    failedCount: selectedItems.length,
    rebootRequired: false,
    results: eachAs(selectedItems, "failed", `unsupported family: ${distro.family} (id=${distro.id})`),
  };
}

export async function handlePatchInstall(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    const mode = String(req.params?.mode || "install").trim().toLowerCase();
    if (mode !== "install" && mode !== "download") {
      return fail(req.id, "bad_request", "patch.install mode must be install or download");
    }

    const kbArticleIds: string[] = Array.isArray(req.params?.kbArticleIds)
      ? req.params!.kbArticleIds.map((item: unknown) => String(item || "").trim()).filter(Boolean)
      : [];

    logger.info("patch_install_request", {
      id: req.id,
      tenantId: req.meta?.tenantId,
      deviceId: req.meta?.deviceId,
      mode,
      requestedCount: kbArticleIds.length,
    });

    // Re-resolve against the live scan so we drop items that have
    // already been installed by `unattended-upgrades` (debian) or
    // `dnf-automatic` (rhel) since the dashboard-side scan was
    // taken. The orchestrator sees per-item `skipped` results and
    // updates its catalog accordingly.
    const live = await runScan();
    if (live.status === "patch_management_unavailable") {
      return fail(req.id, "patch_install_failed", live.note || "patch management unavailable on this distro");
    }

    const selectAll = kbArticleIds.length === 0;
    const selectedItems = selectAll
      ? live.items
      : live.items.filter(it => it.hotFixId && kbArticleIds.includes(it.hotFixId));

    if (!selectAll && selectedItems.length === 0) {
      // Operator asked for specific items, none of which are still
      // upgradeable. That's not a failure — it's a no-op success.
      return success(req.id, {
        status: "no_updates",
        mode,
        selectedCount: 0,
        installedCount: 0,
        failedCount: 0,
        rebootRequired: false,
        results: [],
      } satisfies InstallResult);
    }

    const result = await runInstall_(selectedItems as ScanItem[], mode as "install" | "download", selectAll);
    logger.info("patch_install_complete", {
      status: result.status,
      mode: result.mode,
      installedCount: result.installedCount,
      failedCount: result.failedCount,
      rebootRequired: result.rebootRequired,
    });
    return success(req.id, result);
  } catch (err: any) {
    logger.error("patch_install_failed", { error: err?.message || String(err) });
    return fail(req.id, "patch_install_failed", err?.message || String(err));
  }
}
