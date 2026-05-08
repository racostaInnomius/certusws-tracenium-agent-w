// privsvc/linux/src/paths.ts
//
// Filesystem layout for the Linux privsvc daemon. Same idea as the
// macOS paths.ts but rooted at the FHS-canonical directories. Each
// path can be overridden by env var so a developer can run the
// daemon from a checkout without owning /etc.
//
// systemd-managed locations:
//   /run/tracenium/                  tmpfs, created by RuntimeDirectory=
//                                    in tracenium-privsvc.service. Hosts
//                                    privsvc.sock. systemd nukes it on
//                                    service stop, which is exactly the
//                                    behaviour we want — no stale sockets.
//   /etc/tracenium/                  config + certs. Persists across uninstall
//                                    (postrm preserves it on .deb/.rpm).
//   /var/lib/tracenium/              outbox.db, baselines, anything stateful
//                                    that shouldn't live in /etc.
//   /var/log/tracenium/              file logs (also go to journald via
//                                    StandardOutput=journal).
//
// Note on /var/run vs /run: on every systemd distro `/var/run` is a
// symlink to `/run`, so either path resolves to the same tmpfs. We
// expose the canonical /run path here but the agent's
// `src/priv/privsvc-client-linux.ts` currently hardcodes
// /var/run/tracenium/privsvc.sock — both paths reach the same socket
// via the symlink, no conflict.
import fs from "fs";
import path from "path";

const configuredSocketPath = process.env.TRACENIUM_PRIVSVC_SOCKET_PATH;

export const RUN_DIR = configuredSocketPath
  ? path.dirname(configuredSocketPath)
  : "/run/tracenium";
export const SOCKET_PATH = configuredSocketPath || path.join(RUN_DIR, "privsvc.sock");

// /etc/tracenium is the canonical config + cert root. The certs subdir
// is locked down 0750 root:tracenium so the agent (running as user
// `tracenium`) can read the public CA/client cert but cannot read the
// private key (which we further restrict to 0600 root:root inside
// crypto-store.ts in Phase 2).
export const CONFIG_DIR = process.env.TRACENIUM_PRIVSVC_CONFIG_DIR || "/etc/tracenium";
export const CERT_DIR = path.join(CONFIG_DIR, "certs");

// /var/lib for stateful data. Owned tracenium:tracenium so the agent
// can write outbox.db, baselines, etc. The privsvc only reads from
// here for asset detection inputs.
export const DATA_DIR = process.env.TRACENIUM_PRIVSVC_DATA_DIR || "/var/lib/tracenium";
export const ASSETS_DIR = path.join(DATA_DIR, "assets");

// Logs. Both privsvc and agent dump here AND to journald — file logs
// survive `journalctl --rotate` and are easier to grep retroactively
// for incident forensics.
export const LOG_DIR = process.env.TRACENIUM_PRIVSVC_LOG_DIR || "/var/log/tracenium";

// Group whose members are allowed to connect to the privsvc IPC socket.
// Phase 4 (postinstall.sh) creates this group and adds the `tracenium`
// agent user to it; until then the daemon falls back to root-only
// (0600) and the agent cannot connect. The group lookup is best-effort
// — if the group doesn't exist (dev run, broken install) we log a
// warning and leave the socket root-only.
export const SOCKET_GROUP = process.env.TRACENIUM_PRIVSVC_SOCKET_GROUP || "tracenium";

export function ensurePrivSvcDirs() {
  for (const dir of [RUN_DIR, CONFIG_DIR, CERT_DIR, DATA_DIR, ASSETS_DIR, LOG_DIR]) {
    try {
      fs.mkdirSync(dir, { recursive: true });
    } catch (err: any) {
      // Permission denied on /etc creation under a non-root dev run is
      // expected — we don't want startup to abort just because a
      // checkout doesn't have /etc/tracenium yet. The downstream open
      // calls will surface a clearer error if the dir is genuinely
      // required.
      if (err?.code !== "EACCES" && err?.code !== "EPERM") throw err;
    }
  }

  // Tighten modes where we own the directory. Failures are logged-only
  // — in a dev run as a regular user we won't own /etc/tracenium and
  // chmod will EPERM, which is fine. Production install runs postinst
  // hooks that set these explicitly anyway.
  const modes: Array<[string, number]> = [
    [RUN_DIR, 0o750],
    [CONFIG_DIR, 0o755],
    [CERT_DIR, 0o750],
    [DATA_DIR, 0o755],
    [ASSETS_DIR, 0o755],
    [LOG_DIR, 0o755],
  ];
  for (const [dir, mode] of modes) {
    try { fs.chmodSync(dir, mode); } catch {}
  }
}

export function certPaths() {
  return {
    clientKey: path.join(CERT_DIR, "client.key.pem"),
    clientCsr: path.join(CERT_DIR, "client.csr.pem"),
    clientCert: path.join(CERT_DIR, "client.crt.pem"),
    caBundle: path.join(CERT_DIR, "ca-bundle.crt.pem"),
    bundledRootCa: path.join(ASSETS_DIR, "root-ca.crt"),
  };
}

// Resolve the gid of SOCKET_GROUP from /etc/group. Returns null if the
// group doesn't exist — caller (server.ts) treats null as "lock the
// socket to root only", which is the safe degradation path for a
// half-installed system.
//
// We parse /etc/group directly instead of shelling out to `getent`
// because (a) `getent` isn't always in PATH for a daemon launched
// from systemd with a minimal env, (b) we don't need NSS/sssd
// resolution — `tracenium` is created locally by our postinst
// script, so it's always in the local /etc/group. If a customer
// later moves user management to LDAP/AD this becomes a real bug
// and we'll revisit then.
export function lookupSocketGid(): number | null {
  try {
    const text = fs.readFileSync("/etc/group", "utf8");
    for (const line of text.split("\n")) {
      const parts = line.split(":");
      if (parts[0] === SOCKET_GROUP) {
        const gid = Number(parts[2]);
        return Number.isFinite(gid) ? gid : null;
      }
    }
  } catch {
    // /etc/group unreadable would be a wildly broken system; fall
    // through to null so the socket goes root-only.
  }
  return null;
}
