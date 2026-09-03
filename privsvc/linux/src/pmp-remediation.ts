// privsvc/linux/src/pmp-remediation.ts
//
// PMP v2 — non-patch security remediation handlers for Linux.
// Phase 8 ships 4 checkIds:
//
//   linux.ssh.root_login_disabled
//   linux.ssh.password_auth_disabled
//   linux.cryptography.weak_ssh_kex_disabled
//   linux.firewall.enabled
//
// Same wire contract as macOS / Windows handlers:
//   * pmp.read_check_state → returns { state, isCompliant, supported }
//   * pmp.remediate        → returns { exitCode, stderrExcerpt,
//                                       durationMs, requiresReboot,
//                                       changesApplied[] }
//
// Design choices documented inline. Two patterns dominate this file
// and are worth pulling out up here:
//
// 1. SSH config edits use the DROP-IN approach.
//    We write directives to /etc/ssh/sshd_config.d/99-tracenium-
//    hardening.conf and never touch the operator's /etc/ssh/
//    sshd_config. On modern distros (Debian 11+, Ubuntu 22+, RHEL
//    8+) the main config has `Include /etc/ssh/sshd_config.d/*.conf`
//    near the top, and our drop-in's last-write-wins ordering means
//    `99-tracenium-hardening.conf` overrides any earlier weaker
//    setting from another drop-in. Operator-controlled edits to the
//    main file stay completely separate from our automation.
//
// 2. Every remediation that mutates a config file follows this
//    safety pattern:
//      a. Read existing managed file (or empty if first time).
//      b. Apply directive change in-memory.
//      c. If new content == old content → return success early
//         with empty changesApplied (no-op idempotent).
//      d. Backup current file to <file>.tracenium.<ts>.bak.
//      e. Write new content to <file>.pending (mode 0644).
//      f. Validate via `sshd -t` (which loads main + ALL drop-ins).
//      g. If valid: atomic rename pending → managed file, then
//         `systemctl reload sshd`.
//      h. If invalid: unlink pending, restore from backup if needed,
//         return failure with sshd -t stderr as the reason.
//    Steps (a)..(h) are not factored into a shared helper because
//    the diff per checkId is small and inlining keeps the failure
//    paths obvious to a code reader.
import { execFile } from "child_process";
import fs from "fs";
import path from "path";
import { promisify } from "util";
import { detectFamily } from "./distro";
import { logger } from "./logger";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";

const execFileAsync = promisify(execFile);

// Per-handler timeout. sshd validation + reload is fast (<1s);
// firewall enable can take 2-3s on a busy host. 10s is a generous
// cap that still bounds runaway processes.
const HANDLER_TIMEOUT_MS = 10_000;

const SSHD_DROPIN_DIR = "/etc/ssh/sshd_config.d";
const SSHD_DROPIN_FILE = path.join(SSHD_DROPIN_DIR, "99-tracenium-hardening.conf");

// Safe SSH KexAlgorithms set — 2024 baseline matching the
// CIS L1 server profile. We deliberately exclude:
//   * diffie-hellman-group1-sha1   (DH 1024-bit, broken)
//   * diffie-hellman-group14-sha1  (SHA-1 — deprecated)
//   * diffie-hellman-group-exchange-sha1
//   * any *-sha1 variants
// We keep:
//   * curve25519-sha256(@libssh.org) — preferred
//   * ecdh-sha2-nistp256/384/521    — NIST curves, widely supported
//   * diffie-hellman-group14-sha256 — RFC 8268, modern fallback
//   * diffie-hellman-group16-sha512 — DH 4096-bit
//   * sntrup761x25519-sha512@openssh.com — post-quantum, OpenSSH 9+
const SAFE_SSH_KEX_ALGORITHMS = [
  "sntrup761x25519-sha512@openssh.com",
  "curve25519-sha256",
  "curve25519-sha256@libssh.org",
  "ecdh-sha2-nistp256",
  "ecdh-sha2-nistp384",
  "ecdh-sha2-nistp521",
  "diffie-hellman-group16-sha512",
  "diffie-hellman-group14-sha256",
].join(",");

// ── Generic helpers ───────────────────────────────────────────────

async function runCmd(
  bin: string,
  args: string[],
  timeoutMs = HANDLER_TIMEOUT_MS
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  try {
    const { stdout, stderr } = await execFileAsync(bin, args, {
      timeout: timeoutMs,
      maxBuffer: 1 * 1024 * 1024,
    });
    return { stdout: stdout || "", stderr: stderr || "", code: 0 };
  } catch (err: any) {
    return {
      stdout: err?.stdout || "",
      stderr: err?.stderr || "",
      code: typeof err?.code === "number" ? err.code : null,
    };
  }
}

// Read a file, returning empty string on ENOENT. Other errors throw
// — those represent permissions issues we want to surface, not
// silently swallow.
function readFileSafe(file: string): string {
  try {
    return fs.readFileSync(file, "utf8");
  } catch (err: any) {
    if (err?.code === "ENOENT") return "";
    throw err;
  }
}

function backupTimestamp(): string {
  // YYYYMMDD-HHMMSS in UTC. Ascii-only, sortable, file-system safe.
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return [
    d.getUTCFullYear(),
    pad(d.getUTCMonth() + 1),
    pad(d.getUTCDate()),
    "-",
    pad(d.getUTCHours()),
    pad(d.getUTCMinutes()),
    pad(d.getUTCSeconds()),
  ].join("");
}

// Truncate stderr/stdout for the wire response. We don't want to
// dump multi-MB sshd debug output across IPC + gRPC.
function excerpt(s: string, max = 1024): string {
  if (!s) return "";
  return s.length <= max ? s : s.slice(0, max) + "…[truncated]";
}

// ── SSH drop-in directive editor ──────────────────────────────────
//
// Replaces or appends a single directive in the tracenium-managed
// drop-in. Comments + blank lines preserved. Multiple existing
// occurrences of the same directive (someone hand-edited our file)
// are collapsed into one, with our value winning.
function setDirective(
  content: string,
  directive: string,
  value: string
): string {
  const lines = content.split("\n");
  const lower = directive.toLowerCase();
  let found = false;
  const out: string[] = [];
  for (const raw of lines) {
    const trimmed = raw.trim();
    // Match the directive (case-insensitive per OpenSSH spec).
    // Skip commented-out forms.
    if (!trimmed.startsWith("#")) {
      const m = trimmed.match(/^(\S+)\s+/);
      if (m && m[1].toLowerCase() === lower) {
        if (!found) {
          // First occurrence: replace with our value.
          out.push(`${directive} ${value}`);
          found = true;
        }
        // Drop subsequent duplicates entirely.
        continue;
      }
    }
    out.push(raw);
  }
  if (!found) {
    // Append at end. Ensure there's a trailing newline before our
    // directive so we don't merge into a previous comment.
    if (out.length > 0 && out[out.length - 1].trim() !== "") {
      out.push("");
    }
    out.push(`${directive} ${value}`);
  }
  // Always end the file with exactly one trailing newline.
  while (out.length > 1 && out[out.length - 1] === "") out.pop();
  out.push("");
  return out.join("\n");
}

// Read a directive value from rendered sshd_config (output of
// `sshd -T`). Returns undefined if the directive isn't in the
// effective config (rare — sshd compiles defaults for everything).
function readEffectiveSshd(directive: string, sshdT: string): string | undefined {
  const lower = directive.toLowerCase();
  for (const line of sshdT.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const space = trimmed.indexOf(" ");
    if (space <= 0) continue;
    const key = trimmed.slice(0, space).toLowerCase();
    if (key === lower) return trimmed.slice(space + 1).trim();
  }
  return undefined;
}

// Run `sshd -T` once and cache the parsed map within a single
// handler call (avoids re-running for every read_check). The cache
// is per-call (no module-level state) so a remediation that
// reloads sshd never sees stale values.
async function loadSshdEffective(): Promise<{
  ok: boolean;
  rendered: string;
  stderr: string;
}> {
  const r = await runCmd("/usr/sbin/sshd", ["-T"]);
  return {
    ok: r.code === 0,
    rendered: r.stdout,
    stderr: r.stderr,
  };
}

type EditResult = {
  changedFile: boolean;
  bytesBefore: number;
  bytesAfter: number;
  backupPath?: string;
};

// Apply a single directive change to the drop-in file. Returns info
// about whether the file changed and where we backed it up. Caller
// is responsible for validating + reloading.
async function editSshdDropin(
  directive: string,
  value: string
): Promise<EditResult> {
  // Make sure the directory exists. On modern distros it does, but
  // an extremely stripped image (Alpine, scratch + manual openssh)
  // might not have created it.
  await fs.promises.mkdir(SSHD_DROPIN_DIR, { recursive: true, mode: 0o755 }).catch(() => {});

  const oldContent = readFileSafe(SSHD_DROPIN_FILE);
  const newContent = setDirective(oldContent, directive, value);

  if (oldContent === newContent) {
    return { changedFile: false, bytesBefore: oldContent.length, bytesAfter: newContent.length };
  }

  // Backup first (only if the original file existed — first-time
  // create has nothing to back up).
  let backupPath: string | undefined;
  if (oldContent.length > 0 && fs.existsSync(SSHD_DROPIN_FILE)) {
    backupPath = `${SSHD_DROPIN_FILE}.tracenium.${backupTimestamp()}.bak`;
    fs.copyFileSync(SSHD_DROPIN_FILE, backupPath);
    fs.chmodSync(backupPath, 0o600);
  }

  // Write to .pending, validate, then atomic rename.
  const pending = `${SSHD_DROPIN_FILE}.pending`;
  fs.writeFileSync(pending, newContent, { encoding: "utf8", mode: 0o644 });

  // Validate by running `sshd -t -f` against the would-be combined
  // config. We can't pass a single drop-in to `-f`; what we do
  // instead is temporarily rename the pending into place, run
  // `sshd -t` (which parses the entire stack), and revert if
  // validation fails. This is the only way to validate a drop-in
  // change against the drop-in loader's own logic.
  //
  // The window between rename-in and validate-out is small (< 100ms
  // typically) and during this window any new sshd CHILD processes
  // (incoming ssh sessions) would see the new config. Existing
  // sessions are unaffected. The risk is bounded: the worst case is
  // a 100ms window where new connections briefly see the proposed
  // (and possibly broken) config — but a broken config means
  // CHILD processes refuse to start, not that the running sshd
  // crashes. So during a bad validation window, new ssh attempts
  // get "connection closed" errors and recover when we revert.
  //
  // An alternative would be to assemble the full effective config
  // ourselves and pipe it via `sshd -T -f -`, but that loses
  // include resolution accuracy and reintroduces every parser-
  // incompatibility we'd otherwise dodge.
  //
  // We accept the tradeoff. Most remediations land within seconds
  // and run far from peak ssh-attempt windows.
  fs.renameSync(pending, SSHD_DROPIN_FILE);

  const validate = await runCmd("/usr/sbin/sshd", ["-t"]);
  if (validate.code !== 0) {
    // Roll back: restore from backup OR delete the file we created.
    if (backupPath) {
      fs.copyFileSync(backupPath, SSHD_DROPIN_FILE);
    } else {
      try { fs.unlinkSync(SSHD_DROPIN_FILE); } catch {}
    }
    const err: any = new Error(`sshd -t rejected the new config: ${validate.stderr.trim()}`);
    err.stderrExcerpt = excerpt(validate.stderr);
    throw err;
  }

  return {
    changedFile: true,
    bytesBefore: oldContent.length,
    bytesAfter: newContent.length,
    backupPath,
  };
}

async function reloadSshd(): Promise<{ ok: boolean; stderr: string }> {
  // `systemctl reload sshd` is graceful — existing sessions
  // unaffected, new connections pick up the new config. Both
  // `ssh.service` (Debian) and `sshd.service` (RHEL) are
  // SIGHUP-driven and reload cleanly.
  //
  // We try the unit name conventional to each family. Failure
  // surfaces as a non-zero exit — the caller decides whether
  // that's worth a roll-back.
  const distro = detectFamily();
  const unit = distro.family === "rhel" ? "sshd.service" : "ssh.service";
  const r = await runCmd("/usr/bin/systemctl", ["reload", unit]);
  if (r.code === 0) return { ok: true, stderr: "" };
  // Fall back to the OTHER unit name in case the distro labelled it
  // unconventionally (e.g. someone running RHEL with an Ubuntu-
  // style override).
  const altUnit = unit === "ssh.service" ? "sshd.service" : "ssh.service";
  const r2 = await runCmd("/usr/bin/systemctl", ["reload", altUnit]);
  if (r2.code === 0) return { ok: true, stderr: "" };
  return { ok: false, stderr: r.stderr || r2.stderr };
}

// ── Per-checkId READ handlers ─────────────────────────────────────

async function readSshDirective(
  directive: string,
  desiredValue: string,
  caseInsensitive = false
): Promise<{ state: any; isCompliant: boolean }> {
  const sshd = await loadSshdEffective();
  const current = readEffectiveSshd(directive, sshd.rendered);
  const norm = (v: string | undefined) => caseInsensitive ? String(v || "").toLowerCase() : String(v || "");
  return {
    state: { directive, current, expected: desiredValue, sshdEffective: sshd.ok },
    isCompliant: norm(current) === norm(desiredValue),
  };
}

async function readSshKex(): Promise<{ state: any; isCompliant: boolean }> {
  const sshd = await loadSshdEffective();
  const current = readEffectiveSshd("kexalgorithms", sshd.rendered) || "";
  const list = current.split(",").map(s => s.trim()).filter(Boolean);
  // Compliance: NO weak entries present. We don't require an exact
  // match to SAFE_SSH_KEX_ALGORITHMS (operators may have sane
  // additions of their own).
  const weakRe = /(group1-sha1|group14-sha1|group-exchange-sha1|.+-sha1$)/i;
  const offenders = list.filter(a => weakRe.test(a));
  return {
    state: { current: list, offenders, expectedNoMatch: weakRe.toString() },
    isCompliant: offenders.length === 0,
  };
}

async function readFirewallEnabled(): Promise<{ state: any; isCompliant: boolean }> {
  const distro = detectFamily();
  if (distro.family === "debian") {
    const r = await runCmd("/usr/sbin/ufw", ["status"]);
    const active = /^Status:\s*active/im.test(r.stdout);
    return { state: { impl: "ufw", active }, isCompliant: active };
  }
  if (distro.family === "rhel") {
    const r = await runCmd("/usr/bin/firewall-cmd", ["--state"]);
    const running = /^running/i.test(r.stdout.trim());
    return { state: { impl: "firewalld", running }, isCompliant: running };
  }
  return {
    state: { impl: "unknown", note: `unsupported family: ${distro.family}` },
    isCompliant: false,
  };
}

// ── Per-checkId REMEDIATE handlers ────────────────────────────────

type RemediateOutcome = {
  exitCode: number;
  stderrExcerpt?: string;
  durationMs: number;
  requiresReboot?: boolean;
  changesApplied?: string[];
};

async function remediateSshDirective(
  directive: string,
  value: string
): Promise<RemediateOutcome> {
  const t0 = Date.now();
  try {
    const edit = await editSshdDropin(directive, value);
    if (!edit.changedFile) {
      return {
        exitCode: 0,
        durationMs: Date.now() - t0,
        requiresReboot: false,
        changesApplied: [],
      };
    }

    const reload = await reloadSshd();
    if (!reload.ok) {
      // The new directive is on disk but sshd reload failed. The
      // catch path here is "best effort" — if sshd is currently up
      // it'll pick the change up at next start; the new config is
      // already validated by `sshd -t` so it's safe.
      logger.warn("sshd_reload_failed_post_remediate", { directive, stderr: reload.stderr });
      return {
        exitCode: 1,
        stderrExcerpt: excerpt(reload.stderr),
        durationMs: Date.now() - t0,
        requiresReboot: false,
        changesApplied: [`${directive}=${value}`, "config-staged-not-reloaded"],
      };
    }

    return {
      exitCode: 0,
      durationMs: Date.now() - t0,
      requiresReboot: false,
      changesApplied: [`${directive}=${value}`, "sshd-reloaded"],
    };
  } catch (err: any) {
    return {
      exitCode: 1,
      stderrExcerpt: err?.stderrExcerpt || excerpt(err?.message || String(err)),
      durationMs: Date.now() - t0,
      requiresReboot: false,
      changesApplied: [],
    };
  }
}

async function remediateSshKex(): Promise<RemediateOutcome> {
  return remediateSshDirective("KexAlgorithms", SAFE_SSH_KEX_ALGORITHMS);
}

// ── ufw: SSH antes que el candado ──────────────────────────────────
//
// `ufw --force enable` con la política por defecto (deny incoming) y sin
// reglas corta TODA conexión entrante nueva, SSH incluido. La versión
// anterior de este handler asumía que ufw «traía permitido OpenSSH de
// fábrica»; no es así en Ubuntu: ufw se instala sin reglas y sólo tiene
// la de OpenSSH si un administrador la añadió. Las sesiones vivas
// sobreviven (y el gRPC del agente es saliente), así que el equipo
// seguiría alcanzable desde el shell remoto de Tracenium, pero a un
// cliente le habríamos cortado el SSH en nombre del cumplimiento.
//
// Regla: si hay un sshd activo, se permite su puerto (el EFECTIVO, de
// `sshd -T`, no el 22 por costumbre) ANTES de activar. `ufw allow` es
// idempotente («Skipping adding existing rule»). Si no hay sshd, no se
// abre nada: abrir 22 «por si acaso» sería inventarse superficie.

/** Puertos que sshd escucha según `sshd -T` (líneas `port N`); [22] si no dice ninguno. */
export function sshPortsFromSshdT(rendered: string): number[] {
  const ports: number[] = [];
  for (const line of String(rendered || "").split("\n")) {
    const m = /^\s*port\s+(\d{1,5})\s*$/i.exec(line);
    if (!m) continue;
    const n = Number(m[1]);
    if (n >= 1 && n <= 65535 && !ports.includes(n)) ports.push(n);
  }
  return ports.length ? ports : [22];
}

export type UfwStep = { bin: string; args: string[]; change: string | null };

/**
 * La secuencia de comandos para activar ufw sin cortar SSH. Pura, para
 * poder fijarla en tests: primero las reglas de SSH (si sshd está
 * activo), y el enable SIEMPRE el último.
 */
export function planUfwEnable(input: { sshdActive: boolean; sshdRendered: string }): UfwStep[] {
  const steps: UfwStep[] = [];
  if (input.sshdActive) {
    for (const port of sshPortsFromSshdT(input.sshdRendered)) {
      steps.push({
        bin: "/usr/sbin/ufw",
        args: ["allow", `${port}/tcp`, "comment", "Tracenium: keep SSH reachable"],
        change: `ufw-allow-${port}/tcp`,
      });
    }
  }
  steps.push({ bin: "/usr/sbin/ufw", args: ["--force", "enable"], change: "ufw-enabled" });
  return steps;
}

async function isSshdActive(): Promise<boolean> {
  // Debian/Ubuntu llaman a la unidad `ssh`; el resto, `sshd`.
  for (const unit of ["ssh", "sshd"]) {
    const r = await runCmd("/usr/bin/systemctl", ["is-active", "--quiet", unit]);
    if (r.code === 0) return true;
  }
  return false;
}

async function remediateFirewallEnable(): Promise<RemediateOutcome> {
  const t0 = Date.now();
  const distro = detectFamily();

  if (distro.family === "debian") {
    const sshdActive = await isSshdActive();
    const sshd = sshdActive ? await loadSshdEffective() : { ok: false, rendered: "", stderr: "" };
    const steps = planUfwEnable({ sshdActive, sshdRendered: sshd.ok ? sshd.rendered : "" });

    const changes: string[] = [];
    for (const step of steps) {
      const r = await runCmd(step.bin, step.args);
      if (r.code !== 0) {
        // Si falla la regla de SSH NO se activa el firewall: activar sin
        // la regla es exactamente lo que este bloque existe para evitar.
        return {
          exitCode: 1,
          stderrExcerpt: excerpt(`${step.args.join(" ")}: ${r.stderr || r.stdout}`),
          durationMs: Date.now() - t0,
          requiresReboot: false,
          changesApplied: changes,
        };
      }
      if (step.change) changes.push(step.change);
    }
    return {
      exitCode: 0,
      stderrExcerpt: undefined,
      durationMs: Date.now() - t0,
      requiresReboot: false,
      changesApplied: changes,
    };
  }

  if (distro.family === "rhel") {
    // systemctl enable --now: enables at next boot AND starts now.
    // firewalld with default zone "public" allows ssh, dhcpv6-client.
    // Any operator who's customized the zone is preserved (firewalld
    // persists state in /etc/firewalld/, separate from the unit
    // file we're enabling).
    const r = await runCmd("/usr/bin/systemctl", ["enable", "--now", "firewalld.service"]);
    return {
      exitCode: r.code === 0 ? 0 : 1,
      stderrExcerpt: r.code === 0 ? undefined : excerpt(r.stderr),
      durationMs: Date.now() - t0,
      requiresReboot: false,
      changesApplied: r.code === 0 ? ["firewalld-enabled-and-started"] : [],
    };
  }

  // suse/unknown family — bounce.
  return {
    exitCode: 1,
    stderrExcerpt: `firewall remediation not implemented for family=${distro.family}`,
    durationMs: Date.now() - t0,
    requiresReboot: false,
    changesApplied: [],
  };
}

// ── Dispatch tables ───────────────────────────────────────────────

type ReadHandler = () => Promise<{ state: any; isCompliant: boolean }>;
type RemediateHandler = () => Promise<RemediateOutcome>;

const READ_HANDLERS: Record<string, ReadHandler> = {
  "linux.ssh.root_login_disabled": () => readSshDirective("PermitRootLogin", "no", true),
  "linux.ssh.password_auth_disabled": () => readSshDirective("PasswordAuthentication", "no", true),
  "linux.cryptography.weak_ssh_kex_disabled": () => readSshKex(),
  "linux.firewall.enabled": () => readFirewallEnabled(),
};

const REMEDIATE_HANDLERS: Record<string, RemediateHandler> = {
  "linux.ssh.root_login_disabled": () => remediateSshDirective("PermitRootLogin", "no"),
  "linux.ssh.password_auth_disabled": () => remediateSshDirective("PasswordAuthentication", "no"),
  "linux.cryptography.weak_ssh_kex_disabled": () => remediateSshKex(),
  "linux.firewall.enabled": () => remediateFirewallEnable(),
};

// ── pmp.read_check_state ─────────────────────────────────────────

export async function handlePmpReadCheckState(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const checkId = String(req.params?.checkId || "").trim();
  if (!checkId) return fail(req.id, "bad_request", "checkId required");

  const handler = READ_HANDLERS[checkId];
  if (!handler) {
    logger.info("pmp_read_check_state_unsupported", { checkId });
    return fail(req.id, "unsupported_check", `no read handler for checkId ${checkId} on linux`);
  }

  try {
    const result = await handler();
    return success(req.id, {
      state: result.state,
      isCompliant: result.isCompliant === true,
      supported: true,
    });
  } catch (err: any) {
    logger.error("pmp_read_check_state_failed", {
      checkId,
      error: err?.message || String(err),
    });
    return fail(req.id, "read_state_failed", err?.message || String(err));
  }
}

// ── pmp.remediate ────────────────────────────────────────────────

export async function handlePmpRemediate(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const checkId = String(req.params?.checkId || "").trim();
  if (!checkId) return fail(req.id, "bad_request", "checkId required");

  const handler = REMEDIATE_HANDLERS[checkId];
  if (!handler) {
    logger.info("pmp_remediate_unsupported", { checkId });
    return fail(req.id, "unsupported_check", `no remediation handler for checkId ${checkId} on linux`);
  }

  try {
    logger.info("pmp_remediate_start", { checkId });
    const result = await handler();
    logger.info("pmp_remediate_complete", {
      checkId,
      exitCode: result.exitCode,
      changesApplied: result.changesApplied,
    });
    return success(req.id, {
      exitCode: result.exitCode,
      stderrExcerpt: result.stderrExcerpt ?? null,
      durationMs: result.durationMs,
      requiresReboot: result.requiresReboot === true,
      changesApplied: Array.isArray(result.changesApplied) ? result.changesApplied : [],
    });
  } catch (err: any) {
    logger.error("pmp_remediate_failed", {
      checkId,
      error: err?.message || String(err),
    });
    return fail(req.id, "remediate_failed", err?.message || String(err));
  }
}
