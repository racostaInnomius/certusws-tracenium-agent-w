import fs from "fs";
import path from "path";
import { LOG_DIR, ensurePrivSvcDirs } from "./paths";

function line(level: string, message: string, details?: any) {
  const record = {
    atUtc: new Date().toISOString(),
    level,
    message,
    details: details ?? undefined
  };
  return JSON.stringify(record);
}

export function log(level: "debug" | "info" | "warn" | "error", message: string, details?: any) {
  const entry = line(level, message, details);
  console.log(entry);

  try {
    ensurePrivSvcDirs();
    fs.appendFileSync(path.join(LOG_DIR, "tracenium-privsvc-macos.log"), entry + "\n", "utf8");
  } catch {}
}

// `debug` is for expected no-op breadcrumbs (e.g. "delete-identity found
// nothing to remove"). Same routing as the other levels — launchd
// captures stdout and the file tail is cheap to grep — we just tag them
// differently so production logs can be filtered without losing the
// diagnostic trail.
export const logger = {
  debug: (message: string, details?: any) => log("debug", message, details),
  info: (message: string, details?: any) => log("info", message, details),
  warn: (message: string, details?: any) => log("warn", message, details),
  error: (message: string, details?: any) => log("error", message, details)
};
