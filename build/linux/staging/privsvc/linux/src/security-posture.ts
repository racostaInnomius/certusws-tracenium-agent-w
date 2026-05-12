// privsvc/linux/src/security-posture.ts
//
// Implements the `security.compliance` IPC method. Every check runs
// in parallel via Promise.all; each one fails closed (returns shape
// with status "unknown" on any error, never throws) so a single
// missing binary or unparseable output can't blow up the whole SCP
// snapshot.
//
// Distro-family awareness: SELinux only applies on RHEL-family,
// AppArmor only on Debian-family. Both blocks return
// `{ applicable: false }` when called on the wrong family — the
// backend catalog uses this to mark catalog entries `not_applicable`
// instead of `unknown`, which surfaces correctly on the dashboard
// (an Ubuntu device shouldn't show "SELinux mode unknown" forever).
//
// Why most checks shell out instead of reading config files:
//   * sshd -T is the EFFECTIVE config including drop-ins under
//     /etc/ssh/sshd_config.d/* and includes the daemon's runtime
//     defaults. Parsing /etc/ssh/sshd_config alone misses both.
//   * `aa-status` needs root to enumerate profiles; we already are.
//   * `firewall-cmd --state` is the canonical "is firewalld running"
//     check; it's faster than `systemctl is-active firewalld`
//     because it hits the dbus interface instead of cold-loading
//     the unit graph.
//
// Output cap on `raw` fields: 4KB each, so a misbehaving sshd that
// prints 100MB of debug to stdout can't blow up the IPC pipe.
import { execFile } from "child_process";
import fs from "fs";
import { promisify } from "util";
import { detectFamily } from "./distro";
import { logger } from "./logger";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";

const execFileAsync = promisify(execFile);

// Per-check timeout. 5 s is generous for any of the local commands
// we run — `sshd -T` is the slowest and benchmarks at ~50 ms even
// on busy hosts. The longer cap absorbs IO contention on overloaded
// VMs (we've seen `firewall-cmd` block for 2-3 s on RHEL boxes
// under heavy dbus traffic).
const CHECK_TIMEOUT_MS = 5_000;

// Cap raw command output at 4 KB before stuffing into the evidence
// block. The backend's IPC + JSON serialisation can't reasonably
// handle multi-MB blobs (gRPC max message size = 4 MB by default
// on the server side, and we want headroom for the rest of the
// fact bundle). Truncated output is still useful for diagnostics —
// the catalog rules look at the parsed fields, not raw.
const RAW_MAX_BYTES = 4 * 1024;

function truncate(s: string, max = RAW_MAX_BYTES): string {
  if (!s) return "";
  if (s.length <= max) return s;
  return s.slice(0, max) + "\n...[truncated]";
}

async function runCheck(bin: string, args: string[], timeoutMs = CHECK_TIMEOUT_MS): Promise<{ stdout: string; stderr: string; code: number | null }> {
  try {
    const { stdout, stderr } = await execFileAsync(bin, args, {
      timeout: timeoutMs,
      maxBuffer: 4 * 1024 * 1024,
    });
    return { stdout: stdout || "", stderr: stderr || "", code: 0 };
  } catch (err: any) {
    // execFile rejects on non-zero exit — capture stdout/stderr/code
    // anyway, since some tools (e.g. `aa-status`) signal "not
    // configured" via a non-zero code with valid stdout.
    return {
      stdout: err?.stdout || "",
      stderr: err?.stderr || "",
      code: typeof err?.code === "number" ? err.code : null,
    };
  }
}

// ── Firewall ──────────────────────────────────────────────────────
//
// Linux has multiple firewall front-ends layered on top of the same
// kernel netfilter/nftables core:
//   * ufw         — Ubuntu/Debian default since 16.04. State via `ufw status`.
//   * firewalld   — RHEL/Rocky/Alma/Fedora default. State via `firewall-cmd --state`.
//   * nftables    — modern direct interface (replaces iptables on RHEL 8+).
//                   Active if `nft list ruleset` returns a non-empty ruleset.
//   * iptables    — legacy. Active if `iptables -L -n` shows non-default rules.
//
// We probe in this order because that matches the conventional
// "highest-level enabled tool wins" — if both ufw and nftables are
// active on the same host (rare but seen), ufw is the right thing
// to report because that's what the operator manages.
async function collectFirewall() {
  // Try ufw first
  const ufw = await runCheck("/usr/sbin/ufw", ["status"]);
  if (ufw.code === 0 && ufw.stdout) {
    // "Status: active" / "Status: inactive"
    const isActive = /^Status:\s*active/im.test(ufw.stdout);
    return {
      status: isActive ? "enabled" : "disabled",
      impl: "ufw",
      raw: truncate(ufw.stdout),
    };
  }

  // firewalld
  const fwd = await runCheck("/usr/bin/firewall-cmd", ["--state"]);
  if (fwd.stdout || fwd.stderr) {
    // `--state` prints "running" + exit 0 when active, "not running"
    // + exit 252 when not. Either case is informative.
    const isRunning = /^running/i.test(fwd.stdout.trim());
    return {
      status: isRunning ? "enabled" : "disabled",
      impl: "firewalld",
      raw: truncate((fwd.stdout || "") + (fwd.stderr || "")),
    };
  }

  // nftables direct
  const nft = await runCheck("/usr/sbin/nft", ["list", "ruleset"]);
  if (nft.code === 0) {
    const hasRules = nft.stdout.trim().length > 0;
    return {
      status: hasRules ? "enabled" : "disabled",
      impl: "nftables",
      raw: truncate(nft.stdout),
    };
  }

  // iptables legacy fallback
  const ipt = await runCheck("/usr/sbin/iptables", ["-L", "-n"]);
  if (ipt.code === 0) {
    // "ACCEPT" alone in default chains means no rules; we count
    // non-policy lines.
    const ruleLines = ipt.stdout.split("\n").filter(l => /^(DROP|ACCEPT|REJECT)\s/i.test(l)).length;
    return {
      status: ruleLines > 3 ? "enabled" : "disabled",
      impl: "iptables",
      raw: truncate(ipt.stdout),
    };
  }

  // None of the tools are present. On a minimal container image
  // this is normal — the kernel still has netfilter, but we have
  // no way to introspect it without root + a userland binary.
  return {
    status: "unknown" as const,
    impl: "none" as const,
    raw: "no firewall front-end (ufw/firewalld/nft/iptables) detected",
  };
}

// ── SSH server config ─────────────────────────────────────────────
//
// `sshd -T` prints the effective config — including drop-ins under
// /etc/ssh/sshd_config.d/* and the daemon's compiled-in defaults.
// All keys are lowercased in the output. We parse into a flat object
// then pull the fields the catalog needs.
async function collectSsh() {
  const r = await runCheck("/usr/sbin/sshd", ["-T"]);

  // sshd -T exits 0 when the config parses cleanly. A non-zero exit
  // typically means "no Listen addresses bound yet" or a config
  // syntax error — we still get partial output, and `unknown` on
  // missing fields is the right signal.
  if (!r.stdout && r.code !== 0) {
    return {
      enabled: "unknown" as const,
      raw: truncate(r.stderr),
    };
  }

  const map: Record<string, string> = {};
  for (const line of r.stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const space = trimmed.indexOf(" ");
    if (space <= 0) continue;
    const key = trimmed.slice(0, space).toLowerCase();
    const value = trimmed.slice(space + 1).trim();
    map[key] = value;
  }

  // Canonical bool parser for sshd's "yes"/"no" fields. `sshd -T`
  // never emits anything else but be defensive.
  const yn = (k: string): boolean | undefined => {
    const v = map[k];
    if (v === "yes") return true;
    if (v === "no") return false;
    return undefined;
  };

  // Comma-separated lists (kex, ciphers, macs).
  const csv = (k: string): string[] | undefined => {
    const v = map[k];
    if (!v) return undefined;
    return v.split(",").map(s => s.trim()).filter(Boolean);
  };

  return {
    enabled: true,
    permitRootLogin: map["permitrootlogin"],
    passwordAuthentication: yn("passwordauthentication"),
    pubkeyAuthentication: yn("pubkeyauthentication"),
    challengeResponseAuthentication: yn("challengeresponseauthentication") ?? yn("kbdinteractiveauthentication"),
    permitEmptyPasswords: yn("permitemptypasswords"),
    protocol: map["protocol"],
    kexAlgorithms: csv("kexalgorithms"),
    ciphers: csv("ciphers"),
    macs: csv("macs"),
    hostKeyAlgorithms: csv("hostkeyalgorithms"),
    loginGraceTime: map["logingracetime"] ? Number(map["logingracetime"]) : undefined,
    maxAuthTries: map["maxauthtries"] ? Number(map["maxauthtries"]) : undefined,
    x11Forwarding: yn("x11forwarding"),
    raw: truncate(r.stdout),
  };
}

// ── SELinux (RHEL-family only) ────────────────────────────────────
//
// `getenforce` is the simplest answer ("Enforcing" / "Permissive" /
// "Disabled"). `sestatus` gives policy name and module info — we
// keep it as raw for diagnostics. Both work as any user.
async function collectSelinux(family: string) {
  if (family !== "rhel") {
    return { applicable: false };
  }

  const enf = await runCheck("/usr/sbin/getenforce", []);
  const stat = await runCheck("/usr/sbin/sestatus", []);

  let mode: "enforcing" | "permissive" | "disabled" | "unknown" = "unknown";
  if (enf.code === 0 && enf.stdout) {
    const v = enf.stdout.trim().toLowerCase();
    if (v === "enforcing") mode = "enforcing";
    else if (v === "permissive") mode = "permissive";
    else if (v === "disabled") mode = "disabled";
  }

  // Parse `sestatus` for policy name. Lines look like:
  //   SELinux status:                 enabled
  //   Loaded policy name:             targeted
  //   Current mode:                   enforcing
  let policy: string | undefined;
  if (stat.stdout) {
    const m = stat.stdout.match(/Loaded policy name:\s*(\S+)/i);
    if (m) policy = m[1];
  }

  return {
    applicable: true,
    mode,
    policy,
    raw: truncate((enf.stdout || "") + "\n" + (stat.stdout || "")),
  };
}

// ── AppArmor (Debian-family only) ─────────────────────────────────
//
// `aa-status` requires root for full enumeration; we already are.
// Without root it still prints a count summary on stderr.
//
// Modes: every loaded profile is in either enforce, complain, or
// unconfined mode. The catalog treats "enforce" as the secure
// state; "complain" means audited but not blocked; unconfined is
// declared but doing nothing.
async function collectApparmor(family: string) {
  if (family !== "debian") {
    return { applicable: false };
  }

  // Is AppArmor even loaded? `cat /sys/kernel/security/apparmor/profiles`
  // requires root and gives the canonical answer. If the file
  // doesn't exist, AppArmor isn't compiled into the running kernel.
  let kernelEnabled = false;
  try {
    kernelEnabled = fs.existsSync("/sys/kernel/security/apparmor/profiles");
  } catch {
    kernelEnabled = false;
  }

  if (!kernelEnabled) {
    return { applicable: true, enabled: false };
  }

  const r = await runCheck("/usr/sbin/aa-status", ["--json"]);
  if (r.code === 0 && r.stdout) {
    try {
      const parsed = JSON.parse(r.stdout);
      // aa-status --json shape:
      // { profiles: { "/usr/bin/foo": "enforce", ... }, processes: { ... } }
      const profiles = parsed?.profiles || {};
      let enforced = 0;
      let complain = 0;
      for (const v of Object.values(profiles)) {
        if (v === "enforce") enforced += 1;
        else if (v === "complain") complain += 1;
      }
      return {
        applicable: true,
        enabled: true,
        profilesEnforced: enforced,
        profilesComplain: complain,
        raw: truncate(r.stdout),
      };
    } catch {
      // Fall through to text-mode parse if JSON output is missing
      // (older aa-status versions don't support --json).
    }
  }

  // Text-mode fallback. `aa-status` (without --json) prints lines
  // like "  N profiles are in enforce mode."
  const text = await runCheck("/usr/sbin/aa-status", []);
  const enf = text.stdout.match(/(\d+)\s+profiles?\s+are\s+in\s+enforce\s+mode/i);
  const com = text.stdout.match(/(\d+)\s+profiles?\s+are\s+in\s+complain\s+mode/i);

  return {
    applicable: true,
    enabled: true,
    profilesEnforced: enf ? Number(enf[1]) : undefined,
    profilesComplain: com ? Number(com[1]) : undefined,
    raw: truncate(text.stdout),
  };
}

// ── Password policy (/etc/login.defs) ─────────────────────────────
//
// /etc/login.defs is a free-form key-value config (whitespace-
// separated, comments with #). Reads cleanly without root.
//
// Note: this only covers the LEGACY useradd defaults. Modern PAM
// stacks (pam_pwquality on RHEL, pam_unix on Debian) layer
// additional rules in /etc/security/pwquality.conf and PAM stack
// files. Phase 5 ships the legacy view; Phase 5.5 can layer
// pwquality if a customer needs it.
function collectPasswordPolicy() {
  let text = "";
  try {
    text = fs.readFileSync("/etc/login.defs", "utf8");
  } catch {
    return { applicable: false };
  }

  const map: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const trimmed = line.replace(/#.*$/, "").trim();
    if (!trimmed) continue;
    const ws = trimmed.search(/\s/);
    if (ws <= 0) continue;
    const key = trimmed.slice(0, ws).toUpperCase();
    const value = trimmed.slice(ws + 1).trim();
    map[key] = value;
  }

  const num = (k: string): number | undefined => {
    const v = map[k];
    if (!v) return undefined;
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  };

  return {
    applicable: true,
    passMinLen: num("PASS_MIN_LEN"),
    passMinDays: num("PASS_MIN_DAYS"),
    passMaxDays: num("PASS_MAX_DAYS"),
    passWarnAge: num("PASS_WARN_AGE"),
    encryptMethod: map["ENCRYPT_METHOD"],
    raw: truncate(text),
  };
}

// ── auditd ────────────────────────────────────────────────────────
//
// Many minimal images (containers, cloud golden images) don't ship
// auditd at all. We probe via the daemon binary + systemctl unit
// state; both check are cheap.
async function collectAuditd() {
  let installed = false;
  try {
    installed = fs.existsSync("/usr/sbin/auditd") || fs.existsSync("/sbin/auditd");
  } catch {}

  if (!installed) {
    return { installed: false };
  }

  const enabled = await runCheck("/usr/bin/systemctl", ["is-enabled", "auditd.service"]);
  const active = await runCheck("/usr/bin/systemctl", ["is-active", "auditd.service"]);

  return {
    installed: true,
    enabled: enabled.stdout.trim() === "enabled",
    active: active.stdout.trim() === "active",
  };
}

// ── Aggregate handler ─────────────────────────────────────────────
export async function handleSecurityPosture(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    const distro = detectFamily();
    logger.info("security_posture_start", {
      family: distro.family,
      distro: distro.id,
      versionId: distro.versionId,
    });

    // Run every check in parallel. Promise.all rejects on the first
    // throw, but each check function is documented as non-throwing
    // (errors → "unknown" status), so we shouldn't ever lose the
    // whole snapshot to one bad check. Belt-and-braces with the
    // outer try/catch.
    const [firewall, ssh, selinux, apparmor, passwordPolicy, auditd] = await Promise.all([
      collectFirewall(),
      collectSsh(),
      collectSelinux(distro.family),
      collectApparmor(distro.family),
      Promise.resolve(collectPasswordPolicy()),
      collectAuditd(),
    ]);

    return success(req.id, {
      collectedAtUtc: new Date().toISOString(),
      distro: {
        id: distro.id,
        family: distro.family,
        versionId: distro.versionId,
        prettyName: distro.prettyName,
      },
      firewall,
      ssh,
      selinux,
      apparmor,
      passwordPolicy,
      auditd,
    });
  } catch (err: any) {
    logger.error("security_posture_failed", { error: err?.message || String(err) });
    return fail(req.id, "security_posture_failed", err?.message || String(err));
  }
}
