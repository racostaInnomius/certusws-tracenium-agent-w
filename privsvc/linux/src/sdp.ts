// privsvc/linux/src/sdp.ts
//
// SDP — Phase 9 (Linux). Privileged primitives for the agent's
// Software Delivery Plugin. Same three IPC handlers as macOS:
//
//   sdp.detect    — evaluate a DetectionRule against the local system.
//                   Phase 9 covers the cross-platform rule types
//                   (file_exists, command_exit). dpkg_installed and
//                   rpm_installed could land in Phase 9.5 once the
//                   backend catalog ships seed entries that use them.
//   sdp.download  — fetch a URL into a privileged staging directory
//                   (root-owned, mode 700) and verify sha256.
//                   curl(1) does the actual fetch — universal on
//                   Linux distros, battle-tested for HTTPS+redirects.
//   sdp.install   — dispatch by format:
//                     "deb" → apt-get install ./pkg.deb     (debian)
//                     "rpm" → dnf install -y pkg.rpm         (rhel)
//                   Both invocations resolve dependencies from the
//                   system's configured repos, so a package that
//                   needs e.g. libssl3 doesn't fail on a host that
//                   has it pinned to a different version — apt/dnf
//                   pick the right deps.
//
// Staging dir lives under DATA_DIR (= /var/lib/tracenium) at
// /var/lib/tracenium/sdp-staging/. systemd's tracenium-privsvc.service
// runs as root, so the dir is root-owned. mode 700 prevents an
// unprivileged user from tampering between download-verify and
// install (race window otherwise = sha-verify time, ~seconds).
//
// Error codes returned to the agent (mapped to outcome by
// src/plugins/sdp/index.ts):
//   sha256_mismatch        permanent
//   format_unsupported     permanent
//   url_invalid            permanent
//   download_failed        transient (network)
//   install_failed         default → outcome=failed
//   install_timeout        transient → outcome=timed_out
import { execFile } from "child_process";
import { promisify } from "util";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { detectFamily } from "./distro";
import { logger } from "./logger";
import { DATA_DIR } from "./paths";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";

const execFileAsync = promisify(execFile);

// ── Staging dir ───────────────────────────────────────────────────
const STAGING_DIR = path.join(DATA_DIR, "sdp-staging");
const STAGING_TTL_MS = 24 * 60 * 60 * 1000;

// 2 GB cap. Generous for any real installer; anything bigger is a
// bug or an attack and we don't want to fill /var/lib.
const MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024 * 1024;

// 10 min default download — enough for a 2 GB blob over a 30 Mbit
// link. Caller can override via params.timeoutSeconds.
const DEFAULT_DOWNLOAD_TIMEOUT_S = 600;

// 29 min install (60s under the agent orchestrator's 30 min cap).
const DEFAULT_INSTALL_TIMEOUT_S = 1740;

function ensureStagingDir() {
  fs.mkdirSync(STAGING_DIR, { recursive: true });
  try {
    fs.chmodSync(STAGING_DIR, 0o700);
  } catch {
    // Best-effort. If chmod fails (e.g. SELinux denies it on the
    // first run before the policy module landed in Phase 10), the
    // install still works — the parent /var/lib/tracenium is already
    // tracenium:tracenium 0750, so the file is unreachable to other
    // users via path traversal anyway.
  }
}

function sweepOldStagingFiles() {
  let entries: string[] = [];
  try {
    entries = fs.readdirSync(STAGING_DIR);
  } catch {
    return;
  }
  const cutoff = Date.now() - STAGING_TTL_MS;
  for (const name of entries) {
    const full = path.join(STAGING_DIR, name);
    try {
      const st = fs.statSync(full);
      if (st.mtimeMs < cutoff) {
        fs.unlinkSync(full);
        logger.info("sdp_staging_swept", { file: name, ageMs: Date.now() - st.mtimeMs });
      }
    } catch {
      // race with another sweep / agent restart — fine
    }
  }
}

// ── Hash helper ───────────────────────────────────────────────────

function sha256OfFile(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

// ── Detection rule evaluators ─────────────────────────────────────
//
// Linux Phase 9 covers the cross-platform rule types only. The
// per-distro rule types (`dpkg_installed`, `rpm_installed`) need a
// backend catalog migration before they're useful — defer to Phase
// 9.5. Operators who want package-presence detection today can
// express it with `command_exit`:
//
//   { type: "command_exit",
//     cmd: "/usr/bin/dpkg-query",
//     args: ["-W", "-f=${Status}", "nginx"],
//     stdoutMatches: "^install ok installed" }
//
// — same effect as a future native `dpkg_installed` rule, just
// slightly more verbose in the catalog.

type DetectionResult = {
  matched: boolean;
  snapshot: any;
};

async function detectFileExists(rule: { path: string }): Promise<DetectionResult> {
  // Plain stat — no following symlinks beyond the standard, no
  // touching any process state. The catalog supplies an absolute
  // path; we don't try to resolve relative paths because the cwd
  // of the privsvc isn't well-defined for catalog authors.
  let exists = false;
  let stat: fs.Stats | null = null;
  try {
    stat = fs.statSync(rule.path);
    exists = !!stat;
  } catch {
    exists = false;
  }
  return {
    matched: exists,
    snapshot: {
      path: rule.path,
      exists,
      isFile: stat?.isFile() ?? false,
      isDir: stat?.isDirectory() ?? false,
      sizeBytes: stat?.size ?? null,
    },
  };
}

/**
 * Semver-ish comparison mirrored from the macOS/Windows siblings.
 * Splits on `.` and `-`, takes the leading digits of each segment,
 * missing segments default to 0. Returns >0 if a > b, <0 if a < b,
 * 0 if equal.
 *
 * Examples: cmp("1.2.3", "1.2.3") = 0, cmp("1.2.10", "1.2.9") > 0,
 *          cmp("2.0-beta1", "2.0") = 0 (the trailing "-beta" is dropped).
 */
function compareSemver(a: string, b: string): number {
  const parse = (v: string): number[] =>
    (v || "")
      .split(/[.\-]/)
      .map((seg) => {
        const m = /^[0-9]+/.exec(seg);
        return m ? parseInt(m[0], 10) : 0;
      });
  const av = parse(a);
  const bv = parse(b);
  const n = Math.max(av.length, bv.length);
  for (let i = 0; i < n; i++) {
    const ai = i < av.length ? av[i] : 0;
    const bi = i < bv.length ? bv[i] : 0;
    if (ai !== bi) return ai > bi ? 1 : -1;
  }
  return 0;
}

function meetsMinVersion(installed: string | null, minVersion: string | undefined): boolean {
  if (!installed) return false;
  if (!minVersion) return true;
  return compareSemver(installed, minVersion) >= 0;
}

/**
 * Detect a Debian package via `dpkg-query`. Format string `${Status}|${Version}`
 * gives us both the install state and the installed version in one
 * call. "install ok installed" is the only status that means the
 * package is fully present — half-configured / removed-config-left-
 * behind states return matched=false with the actual status in the
 * snapshot for debugging.
 *
 * Wrong distro family (e.g. RHEL): dpkg-query is absent → ENOENT →
 * we surface this as a clear snapshot reason rather than a daemon
 * crash. The catalog operator sees "binary not found" and knows the
 * rule is mis-targeted.
 */
async function detectDpkgInstalled(rule: {
  packageName: string;
  minVersion?: string;
}): Promise<DetectionResult> {
  // execFile (no shell) — the catalog's packageName cannot inject
  // additional dpkg-query flags or shell metas.
  let installedStatus: string | null = null;
  let installedVersion: string | null = null;
  let errorReason: string | null = null;

  try {
    const { stdout } = await execFileAsync(
      "/usr/bin/dpkg-query",
      ["-W", "-f=${Status}|${Version}", rule.packageName],
      { timeout: 10_000, maxBuffer: 256 * 1024 }
    );
    const line = String(stdout || "").trim();
    const [status, version] = line.split("|");
    installedStatus = (status || "").trim();
    installedVersion = (version || "").trim() || null;
  } catch (err: any) {
    // dpkg-query exits with code 1 + stderr "no packages found
    // matching <name>" when the package isn't installed. That's a
    // perfectly valid not-matched result, not an error. Treat ENOENT
    // (binary missing — wrong distro) and EACCES separately.
    if (err?.code === "ENOENT") {
      errorReason = "dpkg-query not found (wrong distro family for this rule)";
    } else {
      const stderr = String(err?.stderr || "");
      // Common cases worth surfacing: package genuinely not installed
      if (/no packages? found matching/i.test(stderr)) {
        installedStatus = "not_installed";
      } else {
        errorReason = stderr.slice(0, 200) || (err?.message ?? "dpkg-query failed");
      }
    }
  }

  const isFullyInstalled = installedStatus === "install ok installed";
  const matched = isFullyInstalled && meetsMinVersion(installedVersion, rule.minVersion);

  return {
    matched,
    snapshot: {
      packageName: rule.packageName,
      minVersion: rule.minVersion ?? null,
      installedStatus,
      installedVersion,
      errorReason,
    },
  };
}

/**
 * Detect an RPM package via `rpm -q --qf`. Sister to `detectDpkgInstalled`.
 * Format string `%{VERSION}-%{RELEASE}` gives us the full installed
 * version (e.g. "1.20.1-9.el9"). For minVersion compare we only use
 * the leading semver-shaped part (compareSemver tolerates the
 * `-9.el9` tail by truncating at the first non-digit).
 *
 * Wrong distro family (Debian): rpm binary may be absent or may
 * return useless results. ENOENT surfaces in snapshot.errorReason.
 */
async function detectRpmInstalled(rule: {
  packageName: string;
  minVersion?: string;
}): Promise<DetectionResult> {
  let installedVersion: string | null = null;
  let errorReason: string | null = null;
  let exitCode = 0;

  try {
    const { stdout } = await execFileAsync(
      "/usr/bin/rpm",
      ["-q", "--qf", "%{VERSION}-%{RELEASE}", rule.packageName],
      { timeout: 10_000, maxBuffer: 256 * 1024 }
    );
    installedVersion = String(stdout || "").trim() || null;
  } catch (err: any) {
    // rpm -q exits 1 when the package isn't installed. stderr usually
    // says "package <name> is not installed". Treat as not-matched
    // rather than an error.
    exitCode = Number.isFinite(Number(err?.code)) ? Number(err.code) : 1;
    if (err?.code === "ENOENT") {
      errorReason = "rpm not found (wrong distro family for this rule)";
    } else {
      const stderr = String(err?.stderr || "");
      if (!/is not installed/i.test(stderr)) {
        errorReason = stderr.slice(0, 200) || (err?.message ?? "rpm -q failed");
      }
    }
  }

  const matched = installedVersion !== null
    && exitCode === 0
    && meetsMinVersion(installedVersion, rule.minVersion);

  return {
    matched,
    snapshot: {
      packageName: rule.packageName,
      minVersion: rule.minVersion ?? null,
      installedVersion,
      exitCode,
      errorReason,
    },
  };
}

async function detectCommandExit(rule: {
  cmd: string;
  args?: string[];
  stdoutMatches?: string;
}): Promise<DetectionResult> {
  // execFile (no shell). The catalog's `cmd` is treated as a binary
  // path; `args` is an array. No shell-syntax interpretation, no
  // injection surface from a malicious catalog entry that puts ;rm
  // -rf / in args.
  let stdout = "";
  let stderr = "";
  let exitCode = -1;
  try {
    const r = await execFileAsync(rule.cmd, rule.args || [], {
      timeout: 30_000,
      maxBuffer: 4 * 1024 * 1024,
    });
    stdout = r.stdout || "";
    stderr = r.stderr || "";
    exitCode = 0;
  } catch (err: any) {
    stdout = String(err?.stdout || "");
    stderr = String(err?.stderr || "");
    exitCode = typeof err?.code === "number" ? err.code : -1;
  }

  let stdoutMatched: boolean | null = null;
  if (rule.stdoutMatches) {
    try {
      stdoutMatched = new RegExp(rule.stdoutMatches).test(stdout);
    } catch {
      // Bad regex from the catalog. Don't crash the daemon —
      // surface as not-matched with a diagnostic snapshot so the
      // operator sees the offending pattern.
      stdoutMatched = false;
    }
  }

  // Match logic mirrors macOS: exit 0 AND (regex matched if provided).
  const matched = exitCode === 0 && (stdoutMatched === null || stdoutMatched === true);

  return {
    matched,
    snapshot: {
      cmd: rule.cmd,
      args: rule.args ?? [],
      exitCode,
      stdoutPreview: stdout.slice(0, 200),
      stderrPreview: stderr.slice(0, 200),
      stdoutMatched,
    },
  };
}

// ── Public IPC handlers ───────────────────────────────────────────

export async function handleSdpDetect(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const rule = req.params?.rule;
  if (!rule || typeof rule !== "object") {
    return fail(req.id, "bad_request", "rule required");
  }

  const ruleType = String(rule.type || "");
  try {
    let result: DetectionResult;
    switch (ruleType) {
      case "file_exists":
        if (typeof rule.path !== "string" || !rule.path.trim()) {
          return fail(req.id, "bad_request", "file_exists.path required");
        }
        result = await detectFileExists({ path: String(rule.path) });
        break;
      case "command_exit":
        if (typeof rule.cmd !== "string" || !rule.cmd.trim()) {
          return fail(req.id, "bad_request", "command_exit.cmd required");
        }
        result = await detectCommandExit({
          cmd: String(rule.cmd),
          args: Array.isArray(rule.args) ? rule.args.map((a: unknown) => String(a)) : undefined,
          stdoutMatches: rule.stdoutMatches ? String(rule.stdoutMatches) : undefined,
        });
        break;
      case "dpkg_installed":
        if (typeof rule.packageName !== "string" || !rule.packageName.trim()) {
          return fail(req.id, "bad_request", "dpkg_installed.packageName required");
        }
        result = await detectDpkgInstalled({
          packageName: String(rule.packageName).trim(),
          minVersion: rule.minVersion ? String(rule.minVersion).trim() : undefined,
        });
        break;
      case "rpm_installed":
        if (typeof rule.packageName !== "string" || !rule.packageName.trim()) {
          return fail(req.id, "bad_request", "rpm_installed.packageName required");
        }
        result = await detectRpmInstalled({
          packageName: String(rule.packageName).trim(),
          minVersion: rule.minVersion ? String(rule.minVersion).trim() : undefined,
        });
        break;
      case "registry_uninstall":
        // Windows-only. The agent's PLATFORM_APPLICABILITY filter
        // should prevent us from receiving this — explicit return
        // catches a misrouted call.
        return success(req.id, {
          matched: false,
          snapshot: { skipped: true, reason: "registry_uninstall_not_applicable_on_linux" },
        });
      case "bundle_version":
      case "pkg_receipt":
        // macOS-only.
        return success(req.id, {
          matched: false,
          snapshot: { skipped: true, reason: `${ruleType}_not_applicable_on_linux` },
        });
      default:
        return fail(req.id, "bad_request", `unknown detection rule type: ${ruleType}`);
    }

    logger.info("sdp_detect", {
      type: ruleType,
      matched: result.matched,
    });
    return success(req.id, result);
  } catch (err: any) {
    logger.error("sdp_detect_failed", {
      type: ruleType,
      error: err?.message || String(err),
    });
    return fail(req.id, "detect_failed", err?.message || String(err));
  }
}

// ── sdp.download ──────────────────────────────────────────────────

export async function handleSdpDownload(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const params = req.params || {};
  const url = String(params.url || "");
  const expectedSha256 = String(params.sha256 || "").toLowerCase();
  const format = String(params.format || "");
  const packageId = Number(params.packageId);
  const sizeBytes = params.sizeBytes ? Number(params.sizeBytes) : null;
  const timeoutSeconds = Number.isFinite(Number(params.timeoutSeconds))
    ? Math.max(60, Math.floor(Number(params.timeoutSeconds)))
    : DEFAULT_DOWNLOAD_TIMEOUT_S;

  // ── Pre-flight validation ──────────────────────────────────────
  if (!/^https:\/\//i.test(url)) {
    return fail(req.id, "url_invalid", "downloadPath must be an https URL");
  }
  if (!/^[0-9a-f]{64}$/i.test(expectedSha256)) {
    return fail(req.id, "url_invalid", "sha256 must be a 64-char hex string");
  }
  if (sizeBytes != null && (!Number.isInteger(sizeBytes) || sizeBytes <= 0 || sizeBytes > MAX_DOWNLOAD_BYTES)) {
    return fail(req.id, "format_unsupported", "sizeBytes outside allowed range");
  }
  if (!Number.isInteger(packageId) || packageId <= 0) {
    return fail(req.id, "bad_request", "packageId required");
  }

  // Whitelist of formats this OS knows how to install. Pre-validate
  // here so we don't waste bandwidth fetching a `.dmg` we'd refuse
  // to install on Linux. The format ↔ family mapping is enforced
  // again in handleSdpInstall.
  const supportedFormats = new Set(["deb", "rpm"]);
  if (!supportedFormats.has(format)) {
    return fail(req.id, "format_unsupported", `format ${format} not supported on linux`);
  }

  ensureStagingDir();
  sweepOldStagingFiles();

  // Filename: pkg-<packageId>-<random>.<format>. We DON'T derive the
  // name from the URL because URLs can carry attacker-controlled
  // chars; our random suffix prevents collisions across concurrent
  // downloads.
  const nonce = crypto.randomBytes(8).toString("hex");
  const stagingPath = path.join(STAGING_DIR, `pkg-${packageId}-${nonce}.${format}`);

  // ── Download with curl ─────────────────────────────────────────
  // -fSL : fail on HTTP errors, follow redirects, silent unless error
  // --max-time / --max-filesize : transfer caps so a malicious server
  //   can't stream forever or fill the disk
  // We DON'T pin TLS or set --tlsv1.3: customer infra varies (some
  // CDNs still do 1.2 only); the sha256 verification below is the
  // actual integrity gate. URL trust comes from the catalog —
  // operators chose what to deliver from where.
  const curlArgs = [
    "-fSL",
    "--max-time", String(timeoutSeconds),
    "--max-filesize", String(MAX_DOWNLOAD_BYTES),
    "-o", stagingPath,
    url,
  ];

  const downloadStart = Date.now();
  try {
    await execFileAsync("/usr/bin/curl", curlArgs, {
      // Outer Node timeout is +30s of curl's --max-time, so curl's
      // own timeout fires first and we get its useful stderr instead
      // of a generic "killed" error from Node.
      timeout: (timeoutSeconds + 30) * 1000,
      maxBuffer: 1024 * 1024,
    });
  } catch (err: any) {
    try { fs.unlinkSync(stagingPath); } catch {}
    const stderr = String(err?.stderr || "");
    logger.warn("sdp_download_failed", {
      packageId,
      url,
      stderrPreview: stderr.slice(0, 300),
      code: err?.code,
    });
    return fail(req.id, "download_failed", stderr.slice(0, 200) || (err?.message || "curl failed"));
  }

  // ── sha256 verify ──────────────────────────────────────────────
  let actualSha256: string;
  try {
    actualSha256 = (await sha256OfFile(stagingPath)).toLowerCase();
  } catch (err: any) {
    try { fs.unlinkSync(stagingPath); } catch {}
    return fail(req.id, "download_failed", `sha256 read failed: ${err?.message || err}`);
  }

  if (actualSha256 !== expectedSha256) {
    // Hash mismatch is permanent — the catalog is wrong, or we got
    // tampered bytes. Either way, retrying won't help. Wipe the file
    // so a malicious install can't be triggered later by a caller
    // that knows the staging path.
    try { fs.unlinkSync(stagingPath); } catch {}
    logger.error("sdp_download_sha256_mismatch", {
      packageId,
      expected: expectedSha256,
      actual: actualSha256,
    });
    return fail(req.id, "sha256_mismatch", `expected sha256 ${expectedSha256}, got ${actualSha256}`);
  }

  // Lock down the file so an unprivileged user can't replace it
  // between download and install. Already root-owned (we run as
  // root) and parent dir is 0700, but be explicit.
  try {
    fs.chmodSync(stagingPath, 0o600);
  } catch {
    // best-effort
  }

  const stat = fs.statSync(stagingPath);
  logger.info("sdp_download_ok", {
    packageId,
    sizeBytes: stat.size,
    sha256: actualSha256,
    durationMs: Date.now() - downloadStart,
  });

  return success(req.id, {
    stagingPath,
    sha256: actualSha256,
    sizeBytes: stat.size,
    durationMs: Date.now() - downloadStart,
  });
}

// ── Install runners ───────────────────────────────────────────────
//
// Both runners share the contract `{ exitCode, stderrExcerpt,
// durationMs }`. Runner-specific failure modes encoded in
// stderrExcerpt — the agent surfaces it through to the operator
// dashboard via the install_results table.

type InstallRunResult = {
  exitCode: number;
  stderrExcerpt?: string;
  durationMs: number;
};

function combinedExcerpt(stdout: unknown, stderr: unknown): string | undefined {
  const out = String(stdout || "").trim();
  const err = String(stderr || "").trim();
  const combined = [out, err].filter(Boolean).join(" | ");
  if (!combined) return undefined;
  return combined.slice(0, 1024);
}

async function runDebInstaller(
  stagingPath: string,
  timeoutSeconds: number
): Promise<InstallRunResult> {
  // `apt-get install ./pkg.deb` is the modern preferred path — it
  // installs the local file AND resolves dependencies from the
  // configured repos in one shot. Bare `dpkg -i` doesn't resolve
  // missing deps and would leave the package in a half-configured
  // state.
  //
  // The leading "./" is REQUIRED for apt to interpret the argument
  // as a local file path rather than a package-name-from-repo query.
  // We construct `./<basename>` and CD into the staging dir — an
  // absolute path also works (`apt-get install /full/path/pkg.deb`)
  // but path-with-dots is the documented invocation.
  const start = Date.now();
  const basename = path.basename(stagingPath);
  try {
    const { stdout, stderr } = await execFileAsync(
      "/usr/bin/apt-get",
      [
        "install",
        "-y",
        "--no-install-recommends",
        "-o", "Dpkg::Options::=--force-confdef",
        "-o", "Dpkg::Options::=--force-confold",
        `./${basename}`,
      ],
      {
        cwd: path.dirname(stagingPath),
        timeout: timeoutSeconds * 1000,
        maxBuffer: 16 * 1024 * 1024,
        env: {
          ...process.env,
          DEBIAN_FRONTEND: "noninteractive",
          // Force English so our error-message regex paths
          // (catch lock collisions etc) match regardless of the
          // operator's locale.
          LANG: "C",
          LC_ALL: "C",
        },
      }
    );
    return {
      exitCode: 0,
      stderrExcerpt: combinedExcerpt(stdout, stderr),
      durationMs: Date.now() - start,
    };
  } catch (err: any) {
    if (err?.killed && err?.signal === "SIGTERM") {
      throw Object.assign(new Error("apt-get install timeout"), { code: "install_timeout" });
    }
    return {
      exitCode: Number.isFinite(Number(err?.code)) ? Number(err.code) : 1,
      stderrExcerpt: combinedExcerpt(err?.stdout, err?.stderr),
      durationMs: Date.now() - start,
    };
  }
}

async function runRpmInstaller(
  stagingPath: string,
  timeoutSeconds: number
): Promise<InstallRunResult> {
  // dnf install <file.rpm> is the modern path — it resolves deps from
  // the configured repos. `rpm -i` alone is the bare equivalent of
  // `dpkg -i` and shares the same "leaves package half-installed if
  // deps missing" problem.
  //
  // RHEL 7 hosts use `yum install <file.rpm>` — same shape, dispatch
  // by binary presence.
  const dnfBin = fs.existsSync("/usr/bin/dnf")
    ? "/usr/bin/dnf"
    : fs.existsSync("/usr/bin/yum")
      ? "/usr/bin/yum"
      : null;

  if (!dnfBin) {
    return {
      exitCode: 1,
      stderrExcerpt: "no dnf or yum binary found in /usr/bin",
      durationMs: 0,
    };
  }

  const start = Date.now();
  try {
    const { stdout, stderr } = await execFileAsync(
      dnfBin,
      ["install", "-y", stagingPath],
      {
        timeout: timeoutSeconds * 1000,
        maxBuffer: 16 * 1024 * 1024,
        env: { ...process.env, LANG: "C", LC_ALL: "C" },
      }
    );
    return {
      exitCode: 0,
      stderrExcerpt: combinedExcerpt(stdout, stderr),
      durationMs: Date.now() - start,
    };
  } catch (err: any) {
    if (err?.killed && err?.signal === "SIGTERM") {
      throw Object.assign(new Error("dnf install timeout"), { code: "install_timeout" });
    }
    return {
      exitCode: Number.isFinite(Number(err?.code)) ? Number(err.code) : 1,
      stderrExcerpt: combinedExcerpt(err?.stdout, err?.stderr),
      durationMs: Date.now() - start,
    };
  }
}

// ── sdp.install ──────────────────────────────────────────────────

export async function handleSdpInstall(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const params = req.params || {};
  const stagingPath = String(params.stagingPath || "");
  const format = String(params.format || "");
  const timeoutSeconds = Number.isFinite(Number(params.timeoutSeconds))
    ? Math.max(60, Math.floor(Number(params.timeoutSeconds)))
    : DEFAULT_INSTALL_TIMEOUT_S;
  const packageId = Number(params.packageId) || 0;

  // ── Validate inputs ────────────────────────────────────────────
  // Defense in depth: even though the agent always passes the
  // staging path WE returned from sdp.download, double-check that
  // the path is inside our staging dir. A compromised agent or a
  // future bug can't talk us into running an installer at /etc/init.d
  // or similar.
  const absStaging = path.resolve(stagingPath);
  if (!absStaging.startsWith(path.resolve(STAGING_DIR) + path.sep)) {
    return fail(req.id, "bad_request", "stagingPath outside privsvc staging dir");
  }
  try {
    fs.accessSync(absStaging, fs.constants.R_OK);
  } catch {
    return fail(req.id, "bad_request", "stagingPath not readable");
  }

  // Format ↔ distro family check. Refuse to run a deb on RHEL or an
  // rpm on Debian — apt/dnf would just produce a confusing error.
  // Surface the mismatch as `format_unsupported` (permanent failure)
  // so the orchestrator marks the deployment as rejected on this
  // device class instead of retrying forever.
  const distro = detectFamily();
  if (format === "deb" && distro.family !== "debian") {
    return fail(req.id, "format_unsupported", `deb package on non-debian family (${distro.family})`);
  }
  if (format === "rpm" && distro.family !== "rhel" && distro.family !== "suse") {
    return fail(req.id, "format_unsupported", `rpm package on non-rpm family (${distro.family})`);
  }

  let result: InstallRunResult;
  try {
    if (format === "deb") {
      result = await runDebInstaller(absStaging, timeoutSeconds);
    } else if (format === "rpm") {
      result = await runRpmInstaller(absStaging, timeoutSeconds);
    } else {
      return fail(req.id, "format_unsupported", `format ${format} not supported on linux`);
    }
  } catch (err: any) {
    if (err?.code === "install_timeout") {
      try { fs.unlinkSync(absStaging); } catch {}
      return fail(req.id, "install_timeout", err?.message || "installer timed out");
    }
    return fail(req.id, "install_failed", err?.message || String(err));
  }

  // Always remove the staged file on success. Saves disk on tenants
  // doing back-to-back deployments. exitCode==0 covers all happy
  // paths on Linux (no "reboot required" exit code analogue to
  // Windows' 3010).
  if (result.exitCode === 0) {
    try { fs.unlinkSync(absStaging); } catch {}
  }

  logger.info("sdp_install_done", {
    packageId,
    format,
    family: distro.family,
    exitCode: result.exitCode,
    durationMs: result.durationMs,
    stderrPreview: result.stderrExcerpt?.slice(0, 200),
  });

  return success(req.id, {
    exitCode: result.exitCode,
    stderrExcerpt: result.stderrExcerpt,
    durationMs: result.durationMs,
  });
}
