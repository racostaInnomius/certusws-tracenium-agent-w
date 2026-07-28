// src/plugins/rcp/path-jail.ts
//
// RCP — filesystem confinement for `rcp.file` sessions.
//
// WHY THIS EXISTS
//
//   FileSession runs inside AgentCore, which is a LocalSystem service on
//   Windows and a root daemon on macOS/Linux. Before this module, every
//   `list` / `download` / `upload` op resolved whatever absolute path the
//   operator's browser sent and acted on it directly. That made `rcp.file`
//   an authenticated arbitrary-read/write primitive over the entire disk:
//   the SAM and SYSTEM registry hives, /etc/shadow, the device's own mTLS
//   private key, or overwriting the agent binary itself. The only control
//   was "the caller is admin_master", which is an authorization check, not
//   a containment boundary.
//
//   This module is that boundary. Every path crossing into the filesystem
//   goes through `jail.check()` first.
//
// MODEL
//
//   Two lists, deny wins:
//     roots  — the only subtrees reachable at all. Platform defaults cover
//              the real support workflow (user profiles, temp, app data);
//              policy can replace them per tenant/device.
//     deny   — subtrees, path segments and file extensions that stay
//              unreachable EVEN INSIDE a root. This is what keeps
//              `C:\ProgramData` usable as a root while the agent's own
//              credential directory underneath it stays sealed.
//
// SYMLINKS ARE THE WHOLE GAME
//
//   A purely lexical check (`path.resolve` + prefix compare) is not a jail:
//   `C:\Users\public\evil -> C:\Windows\System32\config` passes it trivially,
//   and on POSIX any unprivileged local user can plant such a link inside
//   /tmp. So we resolve the path to its REAL location before deciding —
//   including for paths that don't exist yet (uploads), where we realpath
//   the deepest existing ancestor and re-append the non-existent tail. A
//   symlinked ancestor therefore cannot smuggle a write out of the jail.
//
// PURITY / TESTABILITY
//
//   No module-level state, and platform + env + fs are injectable. The
//   Windows semantics (drive letters, backslashes, case-insensitive
//   compares) are exercised from a macOS/Linux test runner by selecting
//   `path.win32` explicitly rather than relying on the host's separator.

import * as fs from "fs";
import * as os from "os";
import * as path from "path";

export type PathJailConfig = {
  /** Absolute subtrees the session may reach. Empty ⇒ platform defaults. */
  roots?: string[];
  /** Extra absolute subtrees to seal, merged with the built-in list. */
  denyPaths?: string[];
  /** Extra file extensions to seal, merged with the built-in list. */
  denyExtensions?: string[];
};

export type JailDeps = {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  realpathSync?: (p: string) => string;
  existsSync?: (p: string) => boolean;
  /** Injectable so a test can pin the temp root instead of inheriting the
   *  host's (which differs per platform and per user on macOS). */
  tmpdir?: string;
};

export type JailDenyCode =
  | "PATH_INVALID"
  | "PATH_OUTSIDE_ROOTS"
  | "PATH_DENIED"
  | "PATH_UNRESOLVABLE";

export type JailDecision =
  | { allowed: true; realPath: string }
  | { allowed: false; code: JailDenyCode; message: string };

// ── Built-in policy ─────────────────────────────────────────────────────────

// Where the agent keeps its enrollment token, mTLS client key and policy
// cache. Mirrors src/bootstrap/paths.ts — kept as literals rather than
// imported so the jail has no import cycle with bootstrap and so a future
// refactor of paths.ts can't silently widen the jail.
function agentDataDirs(platform: NodeJS.Platform, env: NodeJS.ProcessEnv): string[] {
  if (platform === "win32") {
    const programData = env.ProgramData || "C:\\ProgramData";
    return [path.win32.join(programData, "Tracenium")];
  }
  if (platform === "darwin") {
    return ["/Library/Application Support/Tracenium", "/etc/tracenium"];
  }
  return ["/var/lib/tracenium", "/etc/tracenium"];
}

function defaultRoots(
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv,
  tmpdir: string
): string[] {
  // The OS temp directory is always a root: it's where support workflows
  // stage files, and its real location is not guessable from a literal.
  // macOS in particular puts it under a per-user /var/folders/<hash>/T path,
  // so hardcoding /tmp + /var/tmp silently misses the directory that
  // os.tmpdir() — and therefore everything else — actually uses.
  if (platform === "win32") {
    const systemDrive = env.SystemDrive || "C:";
    const programData = env.ProgramData || "C:\\ProgramData";
    const temp = env.TEMP || env.TMP || path.win32.join(systemDrive, "\\Windows\\Temp");
    return [path.win32.join(systemDrive, "\\Users"), programData, temp, tmpdir];
  }
  if (platform === "darwin") {
    return ["/Users", "/tmp", "/private/tmp", "/var/tmp", "/opt", "/srv", tmpdir];
  }
  return ["/home", "/tmp", "/var/tmp", "/opt", "/srv", tmpdir];
}

function defaultDenyPaths(platform: NodeJS.Platform, env: NodeJS.ProcessEnv): string[] {
  const deny = [...agentDataDirs(platform, env)];
  if (platform === "win32") {
    const systemRoot = env.SystemRoot || "C:\\Windows";
    // The registry hives. Reading SAM + SYSTEM offline is a complete
    // local-credential dump, so this stays sealed even though it lives
    // outside the default roots — policy could otherwise add C:\ as a root.
    deny.push(path.win32.join(systemRoot, "System32", "config"));
    deny.push(path.win32.join(systemRoot, "System32", "GroupPolicy"));
    return deny;
  }
  deny.push("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d");
  deny.push("/etc/ssh", "/root");
  return deny;
}

// Any path with one of these as a directory or file component is refused,
// wherever it sits. Catches per-user credential stores that have no fixed
// absolute location (every home directory has its own).
const DENIED_SEGMENTS = new Set([
  ".ssh",
  ".gnupg",
  ".aws",
  ".kube",
  ".docker",
  "id_rsa",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519"
]);

// Private-key and credential container formats. Blunt by design: an IT
// support tool has no routine need to pull these off an endpoint, and the
// blast radius when it happens is total. Tunable via
// `policy.rcp.file.denyExtensions` for tenants that disagree.
const DEFAULT_DENY_EXTENSIONS = [
  ".key",
  ".pem",
  ".pfx",
  ".p12",
  ".jks",
  ".keystore",
  ".ppk"
];

// Bounds — a policy is operator-authored but still crosses a trust boundary
// before reaching a SYSTEM/root process. Same reasoning as
// sanitizeJavaKeystorePaths in core/policy-runtime.ts.
export const JAIL_PATHS_MAX = 32;
export const JAIL_PATH_MAXLEN = 512;

// ── Jail ────────────────────────────────────────────────────────────────────

export class PathJail {
  // `typeof path.win32` rather than path.PlatformPath — the pinned
  // @types/node in this repo doesn't export the latter.
  private readonly P: typeof path.win32;
  private readonly caseSensitive: boolean;
  private readonly realpathSync: (p: string) => string;
  private readonly existsSync: (p: string) => boolean;

  /** Absolute, real (symlink-resolved where possible), comparison-normalized. */
  private readonly roots: string[];
  private readonly denyPaths: string[];
  private readonly denyExtensions: string[];
  /** Display copies — real paths, not case-folded. Shown to the operator. */
  private readonly rootsForDisplay: string[];

  constructor(config: PathJailConfig = {}, deps: JailDeps = {}) {
    const platform = deps.platform ?? process.platform;
    const env = deps.env ?? process.env;
    this.P = platform === "win32" ? path.win32 : path.posix;
    this.caseSensitive = platform !== "win32";
    this.realpathSync = deps.realpathSync ?? fs.realpathSync;
    this.existsSync = deps.existsSync ?? fs.existsSync;

    const tmpdir = deps.tmpdir ?? os.tmpdir();
    const configuredRoots = sanitizeAbsolutePaths(config.roots, platform);
    const rawRoots = configuredRoots.length
      ? configuredRoots
      : defaultRoots(platform, env, tmpdir);

    // Roots are resolved through realpath too: on macOS /tmp is a symlink to
    // /private/tmp, so a lexical root of "/tmp" would never match the real
    // path of anything inside it.
    this.rootsForDisplay = rawRoots.map((r) => this.tryReal(r));
    this.roots = this.rootsForDisplay.map((r) => this.forCompare(r));

    this.denyPaths = [
      ...defaultDenyPaths(platform, env),
      ...sanitizeAbsolutePaths(config.denyPaths, platform)
    ]
      .map((d) => this.tryReal(d))
      .map((d) => this.forCompare(d));

    this.denyExtensions = [
      ...DEFAULT_DENY_EXTENSIONS,
      ...(Array.isArray(config.denyExtensions) ? config.denyExtensions : [])
    ]
      .filter((e) => typeof e === "string" && e.startsWith(".") && e.length <= 16)
      .map((e) => e.toLowerCase());
  }

  /** Roots to show the operator as starting points. Real, display-cased. */
  listRoots(): string[] {
    return [...this.rootsForDisplay];
  }

  /**
   * The single entry point. Returns the REAL path to operate on when the
   * request is inside the jail — callers must use `realPath`, never the
   * path they were handed, or a symlink swap between check and use
   * reopens the hole this module closes.
   */
  check(input: unknown): JailDecision {
    if (typeof input !== "string") {
      return deny("PATH_INVALID", "Path must be a string");
    }
    const raw = input.trim();
    if (!raw) return deny("PATH_INVALID", "Path is empty");
    // A NUL truncates the string inside libc: "safe.txt\0/etc/shadow" would
    // pass a JS-side check and open something else entirely.
    if (raw.includes("\0")) {
      return deny("PATH_INVALID", "Path contains a NUL byte");
    }
    if (raw.length > JAIL_PATH_MAXLEN) {
      return deny("PATH_INVALID", "Path is too long");
    }

    // Resolve `..` and relative segments lexically first, then follow
    // symlinks. Order matters: realpath on an unresolved "a/../b" would
    // still be correct, but resolving first keeps the ancestor walk short.
    let absolute: string;
    try {
      absolute = this.P.resolve(raw);
    } catch {
      return deny("PATH_INVALID", "Path could not be resolved");
    }

    let real: string;
    try {
      real = this.resolveReal(absolute);
    } catch (err: any) {
      return deny(
        "PATH_UNRESOLVABLE",
        `Path could not be resolved on the device: ${err?.message || String(err)}`
      );
    }

    const cmp = this.forCompare(real);

    // Deny before allow — a denied subtree inside an allowed root must lose.
    for (const denied of this.denyPaths) {
      if (this.isWithin(cmp, denied)) {
        return deny("PATH_DENIED", "This location is blocked by the remote access policy");
      }
    }
    for (const segment of this.segmentsOf(real)) {
      if (DENIED_SEGMENTS.has(segment.toLowerCase())) {
        return deny("PATH_DENIED", "This location is blocked by the remote access policy");
      }
    }
    const ext = this.P.extname(real).toLowerCase();
    if (ext && this.denyExtensions.includes(ext)) {
      return deny("PATH_DENIED", `Files of type ${ext} are blocked by the remote access policy`);
    }

    for (const root of this.roots) {
      if (this.isWithin(cmp, root)) return { allowed: true, realPath: real };
    }
    return deny(
      "PATH_OUTSIDE_ROOTS",
      "This path is outside the locations remote file access is allowed to reach"
    );
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  /**
   * realpath the deepest EXISTING ancestor and re-append the tail that
   * doesn't exist yet. Uploads target a file that isn't there, and we still
   * need to know whether its parent chain leaves the jail.
   */
  private resolveReal(absolute: string): string {
    const tail: string[] = [];
    let probe = absolute;

    while (!this.existsSync(probe)) {
      const parent = this.P.dirname(probe);
      // dirname of a root is itself — nothing of this path exists.
      if (parent === probe) return absolute;
      tail.unshift(this.P.basename(probe));
      probe = parent;
    }

    const realBase = this.realpathSync(probe);
    return tail.length ? this.P.join(realBase, ...tail) : realBase;
  }

  /** Best-effort realpath for configured roots/denies, which may not exist. */
  private tryReal(p: string): string {
    try {
      return this.resolveReal(this.P.resolve(p));
    } catch {
      return this.P.resolve(p);
    }
  }

  private forCompare(p: string): string {
    // Strip a trailing separator so "C:\Users\" and "C:\Users" compare equal.
    const trimmed =
      p.length > 1 && (p.endsWith(this.P.sep) || p.endsWith("/"))
        ? p.slice(0, -1)
        : p;
    return this.caseSensitive ? trimmed : trimmed.toLowerCase();
  }

  /**
   * True when `child` is `parent` or sits underneath it. The separator check
   * is what stops the classic prefix bug where "C:\Users-evil" matches the
   * root "C:\Users".
   */
  private isWithin(child: string, parent: string): boolean {
    if (child === parent) return true;
    const withSep = parent.endsWith(this.P.sep) ? parent : parent + this.P.sep;
    if (child.startsWith(withSep)) return true;
    // Windows accepts both separators; normalize the alternative too.
    if (!this.caseSensitive) {
      const alt = parent.replace(/\\/g, "/");
      const childAlt = child.replace(/\\/g, "/");
      return childAlt === alt || childAlt.startsWith(alt.endsWith("/") ? alt : alt + "/");
    }
    return false;
  }

  private segmentsOf(p: string): string[] {
    return p.split(/[\\/]+/).filter(Boolean);
  }
}

function deny(code: JailDenyCode, message: string): JailDecision {
  return { allowed: false, code, message };
}

/**
 * Shared sanitizer for operator-authored path lists. Absolute only, bounded
 * length, bounded count, de-duplicated. Exported so policy-runtime applies
 * the identical rules when it ingests the policy document.
 */
export function sanitizeAbsolutePaths(
  input: unknown,
  platform: NodeJS.Platform = process.platform
): string[] {
  if (!Array.isArray(input)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  const caseSensitive = platform !== "win32";

  for (const raw of input) {
    if (out.length >= JAIL_PATHS_MAX) break;
    if (typeof raw !== "string") continue;
    const trimmed = raw.trim();
    if (!trimmed || trimmed.length > JAIL_PATH_MAXLEN) continue;
    if (trimmed.includes("\0")) continue;
    const isAbsolute = trimmed.startsWith("/") || /^[a-zA-Z]:[\\/]/.test(trimmed);
    if (!isAbsolute) continue;
    const key = caseSensitive ? trimmed : trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(trimmed);
  }
  return out;
}
