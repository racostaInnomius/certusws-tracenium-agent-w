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

export function log(level: "info" | "warn" | "error", message: string, details?: any) {
  const entry = line(level, message, details);
  console.log(entry);

  try {
    ensurePrivSvcDirs();
    fs.appendFileSync(path.join(LOG_DIR, "tracenium-privsvc-macos.log"), entry + "\n", "utf8");
  } catch {}
}

export const logger = {
  info: (message: string, details?: any) => log("info", message, details),
  warn: (message: string, details?: any) => log("warn", message, details),
  error: (message: string, details?: any) => log("error", message, details)
};
