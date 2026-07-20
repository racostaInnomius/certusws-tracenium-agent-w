// privsvc/macos/src/sdp.ts
//
// SDP — Phase 1-E (macOS). Privileged primitives for the agent's
// Software Delivery Plugin. Three IPC handlers exposed via router.ts:
//
//   sdp.detect    — evaluate a DetectionRule (bundle_version /
//                   pkg_receipt / file_exists / command_exit) against
//                   the local system. Returns { matched, snapshot }.
//   sdp.download  — fetch a URL into a privileged staging directory
//                   and verify sha256. Returns { stagingPath, sha256 }.
//                   We use curl(1) for the actual fetch — it's
//                   battle-tested for HTTPS+redirects on macOS and
//                   ships in /usr/bin/curl on every supported version,
//                   which beats reinventing the same wheel with
//                   https.get + redirect chasing.
//   sdp.install   — exec the installer (pkg/dmg) with privsvc
//                   privileges and return the captured exit code.
//
// All three are root-only — the runtime gate lives in router.ts via
// the `requiresRoot()` predicate (see the diff there).
//
// Error codes returned to the agent (the SDP plugin maps them to
// permanent vs transient outcomes — see src/plugins/sdp/index.ts):
//   sha256_mismatch        permanent
//   signature_invalid      permanent (Phase 2)
//   format_unsupported     permanent
//   url_invalid            permanent
//   download_failed        transient (network)
//   install_failed         default (mapped to outcome=failed)
//   install_timeout        transient (mapped to outcome=timed_out)

import { execFile } from "child_process";
import { promisify } from "util";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import os from "os";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";
import { DATA_DIR, certPaths } from "./paths";

const execFileAsync = promisify(execFile);

// ── Staging dir ───────────────────────────────────────────────────
//
// Where downloaded packages land before install. Lives under the
// privsvc data dir (root-owned, mode 700) so an unprivileged user
// can't tamper with the binary between download-verify and install.
//
// Layout:
//   /Library/Application Support/Tracenium/PrivSvc/sdp-staging/
//     pkg-<packageId>-<jobNonce>.<format>
//
// Files older than STAGING_TTL_MS get swept on every download (we
// don't need a separate cron — sweep when we know we'll touch the
// dir anyway). 24h TTL: long enough that a job that gets retried
// within the orchestrator window can reuse a download (Phase 2
// optimization), short enough that a couple of bad downloads don't
// fill the disk.
const STAGING_DIR = path.join(DATA_DIR, "sdp-staging");
const STAGING_TTL_MS = 24 * 60 * 60 * 1000;

// Hard cap on download size so a misbehaving (or compromised)
// catalog entry can't fill the disk. 2 GB is generous for any real-
// world installer; anything bigger is a bug or an attack.
const MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024 * 1024;

// Default download timeout (curl --max-time). 10 min covers a 2 GB
// blob on a 30 Mbit link with margin. Caller can override by passing
// `timeoutSeconds` in params.
const DEFAULT_DOWNLOAD_TIMEOUT_S = 600;

// Default install timeout. The plugin asks for 1740s (60s headroom
// under the orchestrator's 30 min cap). Defensive cap here in case
// a future plugin omits the field.
const DEFAULT_INSTALL_TIMEOUT_S = 1740;

function ensureStagingDir() {
  fs.mkdirSync(STAGING_DIR, { recursive: true });
  try {
    fs.chmodSync(STAGING_DIR, 0o700);
  } catch {
    // Best-effort. Newly-installed daemons may already have the
    // right umask; if chmod fails the next download will still work.
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
      // ignore — race with another sweep / agent restart
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

// ── Semver-ish comparison ─────────────────────────────────────────
//
// Accepts dotted numeric strings and ignores trailing non-numeric
// suffixes (e.g. "1.2.3-beta1" → [1,2,3]). The catalog mostly stores
// proper semver but real-world installer versions are messy
// ("17.0.1 (52431)"); we only need to know "is the installed version
// >= the rule's minVersion".
function compareSemver(a: string, b: string): number {
  const parse = (v: string) =>
    String(v || "")
      .split(/[.-]/)
      .map((seg) => {
        const m = /^\d+/.exec(seg);
        return m ? Number(m[0]) : 0;
      });
  const av = parse(a);
  const bv = parse(b);
  const n = Math.max(av.length, bv.length);
  for (let i = 0; i < n; i++) {
    const ai = av[i] ?? 0;
    const bi = bv[i] ?? 0;
    if (ai !== bi) return ai > bi ? 1 : -1;
  }
  return 0;
}

function meetsMinVersion(installed: string, minVersion: string | undefined): boolean {
  if (!minVersion) return true;
  return compareSemver(installed, minVersion) >= 0;
}

// ── Detection rule evaluators ─────────────────────────────────────
//
// Each evaluator returns a uniform shape `{ matched, snapshot }`.
// `snapshot` holds whatever the operator might want to see in the
// UI's `detection_before` / `detection_after` JSONB columns — the
// installed version we observed, the receipt id, the path checked,
// stdout we matched against, etc. Useful when an operator asks
// "why did the rule fail?".

type DetectionResult = {
  matched: boolean;
  snapshot: any;
};

async function detectBundleVersion(rule: { bundleId: string; minVersion?: string }): Promise<DetectionResult> {
  // mdfind locates installed app bundles by CFBundleIdentifier. Spot-
  // light is on by default on macOS; if it's been disabled the query
  // returns empty — that's a "not installed" outcome, not a hard
  // error.
  let paths: string[] = [];
  try {
    const { stdout } = await execFileAsync(
      "/usr/bin/mdfind",
      [`kMDItemCFBundleIdentifier == '${rule.bundleId.replace(/'/g, "")}'`],
      { timeout: 15_000, maxBuffer: 1024 * 1024 }
    );
    paths = stdout.split("\n").map((s) => s.trim()).filter(Boolean);
  } catch {
    paths = [];
  }

  // Fallback: if Spotlight's index is cold (recent disk image, fresh
  // install), scan /Applications directly. Keeps detection working
  // even on first boot post-imaging.
  if (paths.length === 0) {
    try {
      const apps = fs.readdirSync("/Applications").filter((n) => n.endsWith(".app"));
      for (const app of apps) {
        const plistPath = `/Applications/${app}/Contents/Info.plist`;
        try {
          const { stdout } = await execFileAsync(
            "/usr/bin/defaults",
            ["read", plistPath, "CFBundleIdentifier"],
            { timeout: 5_000 }
          );
          if (stdout.trim() === rule.bundleId) {
            paths.push(`/Applications/${app}`);
          }
        } catch {
          // ignore — not all apps have a readable plist
        }
      }
    } catch {
      // /Applications unreadable; treat as not installed.
    }
  }

  if (paths.length === 0) {
    return {
      matched: false,
      snapshot: { bundleId: rule.bundleId, found: false },
    };
  }

  // Read CFBundleShortVersionString (preferred — that's the user-
  // facing version) with CFBundleVersion fallback (build number).
  const appPath = paths[0];
  const plistPath = `${appPath}/Contents/Info.plist`;
  let installed = "";
  for (const key of ["CFBundleShortVersionString", "CFBundleVersion"]) {
    try {
      const { stdout } = await execFileAsync(
        "/usr/bin/defaults",
        ["read", plistPath, key],
        { timeout: 5_000 }
      );
      const v = stdout.trim();
      if (v) {
        installed = v;
        break;
      }
    } catch {
      // try next key
    }
  }

  const matched = installed.length > 0 && meetsMinVersion(installed, rule.minVersion);

  return {
    matched,
    snapshot: {
      bundleId: rule.bundleId,
      found: true,
      path: appPath,
      installedVersion: installed || null,
      minVersion: rule.minVersion ?? null,
    },
  };
}

async function detectPkgReceipt(rule: { pkgId: string; minVersion?: string }): Promise<DetectionResult> {
  // pkgutil --pkg-info exits non-zero when the receipt doesn't exist.
  // We treat that as "not installed", everything else as a real check.
  try {
    const { stdout } = await execFileAsync(
      "/usr/sbin/pkgutil",
      ["--pkg-info", rule.pkgId],
      { timeout: 10_000, maxBuffer: 1024 * 1024 }
    );
    // Output format:
    //   package-id: com.example.foo.installer
    //   version: 1.2.3
    //   volume: /
    //   ...
    const versionLine = stdout
      .split("\n")
      .map((s) => s.trim())
      .find((line) => line.startsWith("version:"));
    const installed = versionLine ? versionLine.replace(/^version:\s*/, "").trim() : "";
    const matched = installed.length > 0 && meetsMinVersion(installed, rule.minVersion);
    return {
      matched,
      snapshot: {
        pkgId: rule.pkgId,
        found: true,
        installedVersion: installed || null,
        minVersion: rule.minVersion ?? null,
      },
    };
  } catch {
    return {
      matched: false,
      snapshot: { pkgId: rule.pkgId, found: false },
    };
  }
}

async function detectFileExists(rule: { path: string }): Promise<DetectionResult> {
  // Path is opaque (could be /usr/local/bin/foo, /opt/foo/bar, etc.).
  // We check existence + readability of the parent so a privacy-
  // protected path (e.g. ~/Library/...) returns "not found" cleanly
  // instead of throwing EPERM at the operator.
  try {
    const st = fs.statSync(rule.path);
    return {
      matched: true,
      snapshot: {
        path: rule.path,
        type: st.isFile() ? "file" : st.isDirectory() ? "dir" : "other",
        sizeBytes: st.size,
      },
    };
  } catch {
    return {
      matched: false,
      snapshot: { path: rule.path, found: false },
    };
  }
}

async function detectCommandExit(rule: { cmd: string; args?: string[]; stdoutMatches?: string }): Promise<DetectionResult> {
  // Open-ended escape hatch. Any installed software that doesn't
  // register itself in a bundle/receipt can still be detected via a
  // CLI version probe ("foo --version" → match a regex). We cap the
  // timeout aggressively (15s) and the buffer (256 KB) so a hung or
  // chatty command can't stall detection.
  let exitCode = -1;
  let stdout = "";
  let stderr = "";
  try {
    const result = await execFileAsync(rule.cmd, rule.args ?? [], {
      timeout: 15_000,
      maxBuffer: 256 * 1024,
    });
    exitCode = 0;
    stdout = String(result.stdout || "");
    stderr = String(result.stderr || "");
  } catch (err: any) {
    exitCode = Number.isFinite(Number(err?.code)) ? Number(err.code) : -1;
    stdout = String(err?.stdout || "");
    stderr = String(err?.stderr || "");
  }

  let stdoutMatched: boolean | null = null;
  if (rule.stdoutMatches) {
    try {
      const re = new RegExp(rule.stdoutMatches);
      stdoutMatched = re.test(stdout);
    } catch {
      // bad regex from the catalog — surface as not matched + a
      // diagnostic snapshot so the operator sees why.
      stdoutMatched = false;
    }
  }

  // Match logic: exit 0 AND (regex matched if provided).
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
      case "bundle_version":
        if (typeof rule.bundleId !== "string" || !rule.bundleId.trim()) {
          return fail(req.id, "bad_request", "bundle_version.bundleId required");
        }
        result = await detectBundleVersion({
          bundleId: String(rule.bundleId),
          minVersion: rule.minVersion ? String(rule.minVersion) : undefined,
        });
        break;
      case "pkg_receipt":
        if (typeof rule.pkgId !== "string" || !rule.pkgId.trim()) {
          return fail(req.id, "bad_request", "pkg_receipt.pkgId required");
        }
        result = await detectPkgReceipt({
          pkgId: String(rule.pkgId),
          minVersion: rule.minVersion ? String(rule.minVersion) : undefined,
        });
        break;
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
      case "registry_uninstall":
        // Windows-only.
        return success(req.id, {
          matched: false,
          snapshot: { skipped: true, reason: "registry_uninstall_not_applicable_on_macos" },
        });
      case "dpkg_installed":
      case "rpm_installed":
        // Linux-only. PLATFORM_APPLICABILITY in the agent normally
        // blocks these; surface explicitly if a misrouted call slips
        // through (defense in depth — better than `unknown rule type`).
        return success(req.id, {
          matched: false,
          snapshot: { skipped: true, reason: `${ruleType}_not_applicable_on_macos` },
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
  if (!/^[0-9a-f]{64}$/i.test(expectedSha256)) {
    return fail(req.id, "url_invalid", "sha256 must be a 64-char hex string");
  }
  if (sizeBytes != null && (!Number.isInteger(sizeBytes) || sizeBytes <= 0 || sizeBytes > MAX_DOWNLOAD_BYTES)) {
    return fail(req.id, "format_unsupported", `sizeBytes outside allowed range`);
  }
  if (!Number.isInteger(packageId) || packageId <= 0) {
    return fail(req.id, "bad_request", "packageId required");
  }
  // Whitelist of formats this OS knows how to install. Anything else
  // is a permanent failure — saves the round-trip of downloading
  // bytes we'd then refuse to install.
  const supportedFormats = new Set(["pkg", "dmg"]);
  if (!supportedFormats.has(format)) {
    return fail(req.id, "format_unsupported", `format ${format} not supported on macOS`);
  }

  // ── Candidate sources (Distribution Phase A) ───────────────────
  // `sources` is an ordered [{tier, url}] list (dp → cdn → origin). The sha256
  // gate below is the arbiter per-source: a failing or corrupt source means
  // "try the next one", never "install its bytes". Absent/invalid sources →
  // single-candidate legacy behavior off `url`.
  type Candidate = { tier: string; url: string };
  const rawSources = Array.isArray((params as any).sources) ? (params as any).sources : null;
  const candidates: Candidate[] = [];
  if (rawSources) {
    for (const s of rawSources) {
      if (s && typeof s.url === "string" && /^https:\/\//i.test(s.url)) {
        candidates.push({ tier: typeof s.tier === "string" && s.tier ? String(s.tier) : "origin", url: String(s.url) });
      }
    }
  }
  if (candidates.length === 0) {
    if (!/^https:\/\//i.test(url)) {
      return fail(req.id, "url_invalid", "downloadPath must be an https URL");
    }
    candidates.push({ tier: "origin", url });
  }

  ensureStagingDir();
  sweepOldStagingFiles();

  let sawNetworkFailure = false;
  let sawShaMismatch = false;
  let lastError = "";

  for (const candidate of candidates) {
    // Filename: pkg-<packageId>-<random>.<format>. We DON'T derive the name
    // from the URL because URLs can carry attacker-controlled chars; the
    // random suffix prevents collisions across concurrent downloads and
    // across candidate attempts.
    const nonce = crypto.randomBytes(8).toString("hex");
    const stagingPath = path.join(STAGING_DIR, `pkg-${packageId}-${nonce}.${format}`);

    // ── Download with curl ───────────────────────────────────────
    // -fSL : fail on HTTP errors, follow redirects, silent unless error.
    // --max-time / --max-filesize: transfer caps. No TLS pinning: the sha256
    // verification below is the actual integrity gate.
    const curlArgs = [
      "-fSL",
      "--max-time", String(timeoutSeconds),
      "--max-filesize", String(MAX_DOWNLOAD_BYTES),
      "-o", stagingPath,
    ];
    // Phase D — per-tenant bandwidth cap (Kbps → curl's k-suffix).
    const rateLimitKbps = Number((params as any).rateLimitKbps);
    if (Number.isInteger(rateLimitKbps) && rateLimitKbps > 0) {
      curlArgs.push("--limit-rate", `${rateLimitKbps}k`);
    }
    if (candidate.tier === "dp") {
      // LAN distribution point: present the enrollment cert (the DP requires
      // a client cert chained to the tenant CA — that's the auth gate) and
      // skip TLS *server* verification: the DP cert's CN is its deviceId, not
      // the LAN IP we dial, so hostname checks can't pass. Safe because the
      // sha256 gate below verifies the BYTES regardless of transport — a
      // spoofed DP can only make us fall through to cdn/origin.
      const idPaths = certPaths();
      curlArgs.push("--cert", idPaths.clientCert, "--key", idPaths.clientKey, "-k");
    }
    curlArgs.push(candidate.url);

    const downloadStart = Date.now();
    try {
      await execFileAsync("/usr/bin/curl", curlArgs, {
        timeout: (timeoutSeconds + 30) * 1000,
        // curl is silent on success, so its stdout/stderr buffer is small.
        maxBuffer: 1024 * 1024,
      });
    } catch (err: any) {
      try { fs.unlinkSync(stagingPath); } catch {}
      const stderr = String(err?.stderr || "");
      sawNetworkFailure = true;
      lastError = stderr.slice(0, 200) || (err?.message || "curl failed");
      logger.warn("sdp_download_source_failed", {
        packageId,
        tier: candidate.tier,
        stderrPreview: stderr.slice(0, 300),
        code: err?.code,
      });
      continue;
    }

    // ── sha256 verify ────────────────────────────────────────────
    let actualSha256: string;
    try {
      actualSha256 = (await sha256OfFile(stagingPath)).toLowerCase();
    } catch (err: any) {
      try { fs.unlinkSync(stagingPath); } catch {}
      sawNetworkFailure = true;
      lastError = `sha256 read failed: ${err?.message || err}`;
      continue;
    }

    if (actualSha256 !== expectedSha256) {
      // Corrupt/tampered bytes from THIS source — wipe and try the next.
      // Only permanent when every source disagrees with the catalog.
      try { fs.unlinkSync(stagingPath); } catch {}
      sawShaMismatch = true;
      lastError = `expected sha256 ${expectedSha256}, got ${actualSha256}`;
      logger.error("sdp_download_sha256_mismatch", {
        packageId,
        tier: candidate.tier,
        expected: expectedSha256,
        actual: actualSha256,
      });
      continue;
    }

    // Lock down the file so an unprivileged user can't replace it
    // between download and install.
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
      servedBy: candidate.tier,
      durationMs: Date.now() - downloadStart,
    });

    return success(req.id, {
      stagingPath,
      sha256: actualSha256,
      sizeBytes: stat.size,
      durationMs: Date.now() - downloadStart,
      servedBy: candidate.tier,
    });
  }

  // All candidates exhausted. Any network-ish failure → transient (a retry may
  // find the source back up); all-sources sha mismatch → permanent (catalog
  // hash is wrong, retrying cannot help).
  if (sawNetworkFailure) {
    return fail(req.id, "download_failed", lastError || "all sources failed");
  }
  if (sawShaMismatch) {
    return fail(req.id, "sha256_mismatch", lastError || "sha256 mismatch on all sources");
  }
  return fail(req.id, "download_failed", lastError || "no usable source");
}

// ── Install runners ───────────────────────────────────────────────
//
// Each format has its own runner. They all share the contract
// `{ exitCode, stderrExcerpt, durationMs }`.

type InstallRunResult = {
  exitCode: number;
  stderrExcerpt?: string;
  durationMs: number;
};

async function runPkgInstaller(
  stagingPath: string,
  timeoutSeconds: number
): Promise<InstallRunResult> {
  // installer(8) is the canonical macOS pkg installer. -target /
  // installs onto the boot volume; -pkg points at our staged file.
  // No `-applyChoiceChangesXML` — we trust the package's own
  // post-install scripts as authored by the catalog operator.
  const start = Date.now();
  try {
    const { stdout, stderr } = await execFileAsync(
      "/usr/sbin/installer",
      ["-pkg", stagingPath, "-target", "/"],
      { timeout: timeoutSeconds * 1000, maxBuffer: 8 * 1024 * 1024 }
    );
    return {
      exitCode: 0,
      stderrExcerpt: combinedExcerpt(stdout, stderr),
      durationMs: Date.now() - start,
    };
  } catch (err: any) {
    if (err?.killed && err?.signal === "SIGTERM") {
      // Promisified execFile sets `signal` when the timeout fires.
      // Surface as install_timeout so the agent maps to outcome=timed_out.
      throw Object.assign(new Error("installer timeout"), { code: "install_timeout" });
    }
    return {
      exitCode: Number.isFinite(Number(err?.code)) ? Number(err.code) : 1,
      stderrExcerpt: combinedExcerpt(err?.stdout, err?.stderr),
      durationMs: Date.now() - start,
    };
  }
}

async function runDmgInstaller(
  stagingPath: string,
  timeoutSeconds: number
): Promise<InstallRunResult> {
  // DMG flow is multi-step — attach the image, find the .app bundle
  // inside, copy it to /Applications, then detach. Any step can fail
  // mid-way and we want to leave the system clean (no orphaned
  // mount, no half-copied app).
  //
  // Why not `hdiutil convert <dmg> -format UDTO -o /tmp/...iso` and
  // then loop-mount as a single step: hdiutil's JSON `attach` output
  // is the simplest way to discover the mount point reliably.
  const start = Date.now();
  let mountPoint: string | null = null;

  try {
    // hdiutil attach without -plist returns tab-separated rows:
    //   /dev/disk4              GUID_partition_scheme
    //   /dev/disk4s1            EFI                             ...
    //   /dev/disk4s2            Apple_HFS                       /Volumes/MyApp
    // The mount point we want is the trailing /Volumes/... path on
    // the row whose middle column matches a real filesystem (HFS,
    // APFS, etc). We pick the last row that has a /Volumes/ field —
    // the disk-image format guarantees the mountable filesystem
    // entity is last in the list.
    //
    // We parse this textually rather than with -plist + plutil
    // because plutil reads its input from stdin (`-`) and that
    // requires spawn(), not execFile. Extra moving parts for no gain;
    // hdiutil's text output is stable for the cases that matter.
    const attachStart = Date.now();
    const { stdout: attachOut } = await execFileAsync(
      "/usr/bin/hdiutil",
      [
        "attach",
        "-nobrowse",
        "-readonly",
        "-noautoopen",
        stagingPath,
      ],
      { timeout: 90_000, maxBuffer: 1024 * 1024 }
    );

    for (const rawLine of attachOut.split("\n")) {
      // Columns are whitespace-separated (often tabs), variable
      // width. The mount point — when present — is always the last
      // column and starts with /Volumes/ or, in unusual cases, a
      // fully-qualified path the dmg author chose.
      const m = rawLine.match(/(\/Volumes\/[^\t\n\r]+|\/private\/[^\t\n\r]+)\s*$/);
      if (m) {
        mountPoint = m[1].trim();
      }
    }

    if (!mountPoint) {
      throw new Error("no mount-point in hdiutil attach output");
    }
    logger.info("sdp_dmg_attached", {
      mountPoint,
      durationMs: Date.now() - attachStart,
    });

    // Find the first .app inside the mounted volume. Most "drag-to-
    // /Applications" DMGs put the bundle at the root of the image.
    const entries = fs.readdirSync(mountPoint);
    const app = entries.find((n) => n.endsWith(".app"));
    if (!app) {
      throw new Error("no .app bundle found in dmg root");
    }
    const sourceApp = path.join(mountPoint, app);
    const targetApp = path.join("/Applications", app);

    // If the target already exists, remove it first. We're
    // intentionally clobbering — the SDP plugin's pre-detection rule
    // is what decides whether to install at all; if we're running
    // here, the operator wants the new version on disk.
    try {
      const st = fs.statSync(targetApp);
      if (st.isDirectory()) {
        await execFileAsync("/bin/rm", ["-rf", targetApp], {
          timeout: 60_000,
          maxBuffer: 1024 * 1024,
        });
      }
    } catch {
      // doesn't exist — fine
    }

    // ditto preserves resource forks, ACLs, and extended attributes
    // on macOS — important for code-signed app bundles. cp -R can
    // strip metadata that gatekeeper checks.
    const remainingMs = Math.max(60_000, timeoutSeconds * 1000 - (Date.now() - start));
    const { stdout, stderr } = await execFileAsync(
      "/usr/bin/ditto",
      [sourceApp, targetApp],
      { timeout: remainingMs, maxBuffer: 8 * 1024 * 1024 }
    );

    return {
      exitCode: 0,
      stderrExcerpt: combinedExcerpt(stdout, stderr),
      durationMs: Date.now() - start,
    };
  } catch (err: any) {
    if (err?.killed && err?.signal === "SIGTERM") {
      throw Object.assign(new Error("dmg install timeout"), { code: "install_timeout" });
    }
    return {
      exitCode: Number.isFinite(Number(err?.code)) ? Number(err.code) : 1,
      stderrExcerpt: combinedExcerpt(err?.stdout, err?.stderr) || (err?.message || ""),
      durationMs: Date.now() - start,
    };
  } finally {
    // Always try to detach if we attached. Force on detach so a
    // process holding a file open doesn't prevent cleanup.
    if (mountPoint) {
      try {
        await execFileAsync(
          "/usr/bin/hdiutil",
          ["detach", "-force", mountPoint],
          { timeout: 30_000, maxBuffer: 256 * 1024 }
        );
      } catch (detachErr: any) {
        logger.warn("sdp_dmg_detach_failed", {
          mountPoint,
          error: detachErr?.message || String(detachErr),
        });
      }
    }
  }
}

function combinedExcerpt(stdout: unknown, stderr: unknown): string | undefined {
  const out = String(stdout || "").trim();
  const err = String(stderr || "").trim();
  const combined = [out, err].filter(Boolean).join(" | ");
  if (!combined) return undefined;
  return combined.slice(0, 1024);
}

// ── sdp.verifySignature ───────────────────────────────────────────
//
// Fail-closed signature gate for macOS packages. The agent's signature-gate
// (src/plugins/sdp/signature-gate.ts) expects `{ trusted: boolean, reason }`
// and treats anything but an explicit trusted verdict as a block.
//
//   pkg → `pkgutil --check-signature` (the canonical macOS pkg trust check:
//         chains to an Apple-issued Developer ID installer cert).
//   dmg → `codesign --verify --strict` (DMGs, when signed, carry a codesign
//         signature; the app inside is separately checked at install by
//         Gatekeeper). Rare, but supported for completeness.
//
// The trust DECISION is a pure function of the tool output so it's unit-testable
// without a real signed artifact (see interpretPkgutilSignature).

/** Pure: decide trust from `pkgutil --check-signature` stdout + exit code. */
export function interpretPkgutilSignature(exitCode: number, stdout: string): { trusted: boolean; reason: string } {
  const text = String(stdout || "");
  // pkgutil prints "Status: signed by a developer certificate issued by Apple
  // (Development)" / "...for distribution" / "signed by a certificate trusted
  // by macOS" when the chain is good; "no signature" / "signed Ad-hoc" otherwise.
  const statusLine = text.split("\n").map((l) => l.trim()).find((l) => l.startsWith("Status:")) || "";
  const status = statusLine.replace(/^Status:\s*/, "").toLowerCase();
  if (exitCode === 0 && /signed by/.test(status) && !/ad-hoc/.test(status)) {
    return { trusted: true, reason: "pkgutil_signed" };
  }
  if (/no signature|ad-hoc/.test(status)) return { trusted: false, reason: "unsigned" };
  return { trusted: false, reason: statusLine ? `untrusted:${status.slice(0, 40)}` : "verify_failed" };
}

async function verifyPkgSignature(stagingPath: string): Promise<{ trusted: boolean; reason: string }> {
  try {
    const { stdout } = await execFileAsync("/usr/sbin/pkgutil", ["--check-signature", stagingPath], {
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
    });
    return interpretPkgutilSignature(0, stdout);
  } catch (err: any) {
    // Non-zero exit (unsigned / broken chain) still gives useful stdout.
    return interpretPkgutilSignature(
      Number.isFinite(Number(err?.code)) ? Number(err.code) : 1,
      String(err?.stdout || "")
    );
  }
}

async function verifyDmgSignature(stagingPath: string): Promise<{ trusted: boolean; reason: string }> {
  try {
    await execFileAsync("/usr/bin/codesign", ["--verify", "--strict", stagingPath], {
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
    });
    return { trusted: true, reason: "codesign_ok" };
  } catch (err: any) {
    const stderr = String(err?.stderr || "").trim();
    return { trusted: false, reason: stderr ? `codesign_fail:${stderr.slice(0, 40)}` : "codesign_fail" };
  }
}

export async function handleSdpVerifySignature(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const params = req.params || {};
  const stagingPath = String(params.stagingPath || "");
  const format = String(params.format || "");

  const absStaging = path.resolve(stagingPath);
  if (!absStaging.startsWith(path.resolve(STAGING_DIR) + path.sep)) {
    return fail(req.id, "bad_request", "stagingPath outside privsvc staging dir");
  }
  try {
    fs.accessSync(absStaging, fs.constants.R_OK);
  } catch {
    return fail(req.id, "bad_request", "stagingPath not readable");
  }

  let verdict: { trusted: boolean; reason: string };
  if (format === "pkg") {
    verdict = await verifyPkgSignature(absStaging);
  } else if (format === "dmg") {
    verdict = await verifyDmgSignature(absStaging);
  } else {
    // Fail-closed: an unknown format can't be trusted.
    verdict = { trusted: false, reason: `unsupported_format_${format}` };
  }

  logger.info("sdp_verify_signature", { format, trusted: verdict.trusted, reason: verdict.reason });
  return success(req.id, { trusted: verdict.trusted, reason: verdict.reason });
}

// ── sdp.uninstall ─────────────────────────────────────────────────
//
// macOS has NO universal uninstaller — .pkg installs don't ship a reverse
// script. Uninstall is by IDENTITY (from the detection rule), skipping download
// entirely. Two supported shapes, honestly scoped:
//
//   bundleId (bundle_version rule) → locate /Applications/<App>.app and rm -rf
//     it. The clean, common "drag-installed app" case.
//   pkgId (pkg_receipt rule) → `pkgutil --files` under the receipt's install
//     root, remove ONLY paths inside a safe-root allowlist, then
//     `pkgutil --forget`. Arbitrary pkg removal isn't universally possible, so
//     anything outside the allowlist is skipped (and logged), never deleted.
//
// A path guard is the crux: a malicious/misparsed receipt must never let us
// rm -rf `/`, `/System`, `/usr/bin`, etc.

const UNINSTALL_SAFE_ROOTS = [
  "/Applications/",
  "/Library/",
  "/usr/local/",
  "/opt/",
  "/private/var/",
];

function isSafeUninstallPath(abs: string): boolean {
  const resolved = path.resolve(abs);
  // Never touch these even if nested under a safe root by symlink trickery.
  if (resolved === "/" || resolved === "/Applications" || resolved === "/Library") return false;
  return UNINSTALL_SAFE_ROOTS.some((root) => resolved.startsWith(root));
}

async function findAppByBundleId(bundleId: string): Promise<string | null> {
  const clean = bundleId.replace(/'/g, "");
  try {
    const { stdout } = await execFileAsync(
      "/usr/bin/mdfind",
      [`kMDItemCFBundleIdentifier == '${clean}'`],
      { timeout: 15_000, maxBuffer: 1024 * 1024 }
    );
    const hit = stdout.split("\n").map((s) => s.trim()).find((p) => p.endsWith(".app"));
    if (hit) return hit;
  } catch {
    // Spotlight cold/off — fall through to a directory scan.
  }
  try {
    const apps = fs.readdirSync("/Applications").filter((n) => n.endsWith(".app"));
    for (const app of apps) {
      const plistPath = `/Applications/${app}/Contents/Info.plist`;
      try {
        const { stdout } = await execFileAsync("/usr/bin/defaults", ["read", plistPath, "CFBundleIdentifier"], {
          timeout: 5_000,
        });
        if (stdout.trim() === bundleId) return `/Applications/${app}`;
      } catch {
        // no readable plist — skip
      }
    }
  } catch {
    // /Applications unreadable
  }
  return null;
}

async function uninstallByBundle(bundleId: string, timeoutSeconds: number): Promise<InstallRunResult> {
  const start = Date.now();
  const appPath = await findAppByBundleId(bundleId);
  if (!appPath) {
    // Already gone — the agent's pre-detect usually catches this; if we get
    // here, report success-shaped (exit 0) so post-detect (absent) confirms.
    return { exitCode: 0, stderrExcerpt: `no app bundle found for ${bundleId}`, durationMs: Date.now() - start };
  }
  if (!isSafeUninstallPath(appPath)) {
    return { exitCode: 1, stderrExcerpt: `refusing to remove unsafe path ${appPath}`, durationMs: Date.now() - start };
  }
  try {
    await execFileAsync("/bin/rm", ["-rf", appPath], { timeout: timeoutSeconds * 1000, maxBuffer: 1024 * 1024 });
    return { exitCode: 0, stderrExcerpt: `removed ${appPath}`, durationMs: Date.now() - start };
  } catch (err: any) {
    return {
      exitCode: Number.isFinite(Number(err?.code)) ? Number(err.code) : 1,
      stderrExcerpt: combinedExcerpt(err?.stdout, err?.stderr) || (err?.message || ""),
      durationMs: Date.now() - start,
    };
  }
}

async function uninstallByPkgReceipt(pkgId: string, timeoutSeconds: number): Promise<InstallRunResult> {
  const start = Date.now();
  // Resolve the receipt's install root (volume + install-location).
  let volume = "/";
  let installLocation = "";
  try {
    const { stdout } = await execFileAsync("/usr/sbin/pkgutil", ["--pkg-info", pkgId], {
      timeout: 10_000,
      maxBuffer: 1024 * 1024,
    });
    for (const line of stdout.split("\n")) {
      const t = line.trim();
      if (t.startsWith("volume:")) volume = t.replace(/^volume:\s*/, "").trim() || "/";
      if (t.startsWith("location:")) installLocation = t.replace(/^location:\s*/, "").trim();
    }
  } catch {
    // Receipt already gone → nothing to remove; forget is a no-op below.
    return { exitCode: 0, stderrExcerpt: `no receipt for ${pkgId}`, durationMs: Date.now() - start };
  }

  const root = path.join(volume, installLocation);
  let removed = 0;
  let skipped = 0;
  try {
    const { stdout } = await execFileAsync("/usr/sbin/pkgutil", ["--files", pkgId], {
      timeout: 30_000,
      maxBuffer: 16 * 1024 * 1024,
    });
    // Longest paths first so files are removed before their parent dirs.
    const rels = stdout.split("\n").map((s) => s.trim()).filter(Boolean).sort((a, b) => b.length - a.length);
    for (const rel of rels) {
      const abs = path.resolve(path.join(root, rel));
      if (!isSafeUninstallPath(abs)) {
        skipped += 1;
        continue;
      }
      try {
        const st = fs.lstatSync(abs);
        if (st.isDirectory()) {
          fs.rmdirSync(abs); // only removes if empty — leaves shared dirs intact
        } else {
          fs.unlinkSync(abs);
        }
        removed += 1;
      } catch {
        // file already gone / dir non-empty / permission — best-effort
      }
    }
  } catch {
    // couldn't list files — still forget below
  }

  // Drop the receipt so the OS no longer considers the package installed.
  try {
    await execFileAsync("/usr/sbin/pkgutil", ["--forget", pkgId], { timeout: 15_000, maxBuffer: 1024 * 1024 });
  } catch {
    // forget failed (already forgotten) — non-fatal
  }

  logger.info("sdp_pkg_uninstall", { pkgId, root, removed, skipped });
  return {
    exitCode: 0,
    stderrExcerpt: `pkg ${pkgId}: removed ${removed} path(s), skipped ${skipped} outside safe roots`,
    durationMs: Date.now() - start,
  };
}

export async function handleSdpUninstall(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const params = req.params || {};
  const identity = (params.identity || {}) as { bundleId?: string; pkgId?: string };
  const bundleId = String(identity.bundleId || "").trim();
  const pkgId = String(identity.pkgId || "").trim();
  const timeoutSeconds = Number.isFinite(Number(params.timeoutSeconds))
    ? Math.max(60, Math.floor(Number(params.timeoutSeconds)))
    : DEFAULT_INSTALL_TIMEOUT_S;
  const packageId = Number(params.packageId) || 0;

  let result: InstallRunResult;
  try {
    if (bundleId) {
      result = await uninstallByBundle(bundleId, timeoutSeconds);
    } else if (pkgId) {
      result = await uninstallByPkgReceipt(pkgId, timeoutSeconds);
    } else {
      return fail(
        req.id,
        "identity_not_found",
        "uninstall requires a bundleId (bundle_version rule) or pkgId (pkg_receipt rule)"
      );
    }
  } catch (err: any) {
    return fail(req.id, "install_failed", err?.message || String(err));
  }

  logger.info("sdp_uninstall_done", {
    packageId,
    bundleId: bundleId || undefined,
    pkgId: pkgId || undefined,
    exitCode: result.exitCode,
    durationMs: result.durationMs,
  });

  return success(req.id, {
    exitCode: result.exitCode,
    stderrExcerpt: result.stderrExcerpt,
    durationMs: result.durationMs,
  });
}

export async function handleSdpInstall(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const params = req.params || {};
  const stagingPath = String(params.stagingPath || "");
  const format = String(params.format || "");
  const timeoutSeconds = Number.isFinite(Number(params.timeoutSeconds))
    ? Math.max(60, Math.floor(Number(params.timeoutSeconds)))
    : DEFAULT_INSTALL_TIMEOUT_S;
  const packageId = Number(params.packageId) || 0;

  // ── Validate inputs ────────────────────────────────────────────
  // Staging path MUST be inside our staging dir — defense in depth
  // against a caller that managed to talk us into running an
  // installer at an arbitrary path. Resolve both sides to absolutes
  // and compare prefix.
  const absStaging = path.resolve(stagingPath);
  if (!absStaging.startsWith(path.resolve(STAGING_DIR) + path.sep)) {
    return fail(req.id, "bad_request", "stagingPath outside privsvc staging dir");
  }
  try {
    fs.accessSync(absStaging, fs.constants.R_OK);
  } catch {
    return fail(req.id, "bad_request", "stagingPath not readable");
  }

  let result: InstallRunResult;
  try {
    if (format === "pkg") {
      result = await runPkgInstaller(absStaging, timeoutSeconds);
    } else if (format === "dmg") {
      result = await runDmgInstaller(absStaging, timeoutSeconds);
    } else {
      return fail(req.id, "format_unsupported", `format ${format} not supported on macOS`);
    }
  } catch (err: any) {
    if (err?.code === "install_timeout") {
      // Try to clean up the staged file anyway — a half-stuck install
      // shouldn't leave the binary on disk indefinitely.
      try { fs.unlinkSync(absStaging); } catch {}
      return fail(req.id, "install_timeout", err?.message || "installer timed out");
    }
    return fail(req.id, "install_failed", err?.message || String(err));
  }

  // Always remove the staged file on success — we don't need it
  // anymore, and the staging dir's TTL sweeper would clean it
  // eventually but eager deletion saves disk for tenants with
  // back-to-back deployments.
  if (result.exitCode === 0 || result.exitCode === 3010) {
    try { fs.unlinkSync(absStaging); } catch {}
  }

  logger.info("sdp_install_done", {
    packageId,
    format,
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
