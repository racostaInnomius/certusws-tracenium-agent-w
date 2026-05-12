// privsvc/linux/src/logger.ts
//
// Structured (JSON-line) logger. Same shape as macOS so log shippers
// configured for one platform can ingest the other unchanged.
//
// Routes:
//   1. stdout — captured by systemd's journald via StandardOutput=journal
//      in tracenium-privsvc.service. journalctl is the operator's first
//      stop on every incident, so we want every line there.
//   2. /var/log/tracenium/tracenium-privsvc-linux.log — durable file
//      log that survives `journalctl --rotate` and is easier to grep
//      retroactively.  Append-only, no rotation here — Phase 10 wires
//      logrotate.d.
import fs from "fs";
import path from "path";
import { LOG_DIR, ensurePrivSvcDirs } from "./paths";

function line(level: string, message: string, details?: any) {
  const record = {
    atUtc: new Date().toISOString(),
    level,
    message,
    details: details ?? undefined,
  };
  return JSON.stringify(record);
}

export function log(level: "debug" | "info" | "warn" | "error", message: string, details?: any) {
  const entry = line(level, message, details);
  console.log(entry);

  try {
    ensurePrivSvcDirs();
    fs.appendFileSync(path.join(LOG_DIR, "tracenium-privsvc-linux.log"), entry + "\n", "utf8");
  } catch {
    // Never let a log write failure kill the daemon. journald has the
    // line; the file copy is belt-and-braces.
  }
}

// `debug` is for expected no-op breadcrumbs (e.g. "delete-identity
// found nothing to remove"). Same routing as the other levels — we
// just tag them differently so production logs can be filtered without
// losing the diagnostic trail.
export const logger = {
  debug: (message: string, details?: any) => log("debug", message, details),
  info: (message: string, details?: any) => log("info", message, details),
  warn: (message: string, details?: any) => log("warn", message, details),
  error: (message: string, details?: any) => log("error", message, details),
};
