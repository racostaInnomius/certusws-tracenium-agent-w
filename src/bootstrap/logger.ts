// src/bootstrap/logger.ts
//
// Console logger. The agent runs under a service wrapper on every
// platform (WinSW / launchd / systemd), and each of those captures
// stdout+stderr into the rotated log files — so writing to the console
// IS writing to the log. Nothing here opens files.
//
// ── Levels + the debug switch ──────────────────────────────────────
//
// Until 2026-08 there was no `debug` level at all: the ~16
// `logger?.debug?.(...)` call sites across the codebase were silent
// no-ops thanks to optional chaining. Level filtering was added so the
// chattiest diagnostics (full SDP offers, every ICE candidate, every
// push payload) could move OFF the default path — they were the single
// largest driver of log volume on endpoints.
//
// Two ways to turn debug back on when triaging a device, in priority
// order:
//
//   1. env `TRACENIUM_LOG_LEVEL` = error | warn | info | debug
//      Set in the service definition (WinSW xml / launchd plist /
//      systemd unit). Requires a service restart.
//
//   2. a marker file `debug.flag` in the agent data dir
//      (e.g. C:\ProgramData\Tracenium\Agent\debug.flag). Create it and
//      debug output starts within ~30 s; delete it and it stops. No
//      restart, no config edit — this is the field-support path, and
//      the reason a file switch exists at all.
//
// The file is stat'd at most once every DEBUG_FLAG_TTL_MS so a hot log
// path can't turn into a syscall storm.

import fs from "fs";
import path from "path";
import { agentDataDir } from "./paths";

type Level = "error" | "warn" | "info" | "debug";

const LEVEL_ORDER: Record<Level, number> = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3
};

const DEBUG_FLAG_TTL_MS = 30_000;

function envLevel(): Level | null {
  const raw = String(process.env.TRACENIUM_LOG_LEVEL || "").trim().toLowerCase();
  return raw in LEVEL_ORDER ? (raw as Level) : null;
}

// Resolved once: an explicit env level pins the level for the whole
// process and disables the file-flag check (an operator who set the env
// var meant it).
const pinnedLevel = envLevel();

let debugFlagCachedAt = 0;
let debugFlagPresent = false;

function debugFlagEnabled(): boolean {
  const now = Date.now();
  if (now - debugFlagCachedAt < DEBUG_FLAG_TTL_MS) {
    return debugFlagPresent;
  }
  debugFlagCachedAt = now;
  try {
    debugFlagPresent = fs.existsSync(path.join(agentDataDir(), "debug.flag"));
  } catch {
    // Data dir unreadable — never let the logger throw.
    debugFlagPresent = false;
  }
  return debugFlagPresent;
}

function activeLevel(): Level {
  if (pinnedLevel) return pinnedLevel;
  return debugFlagEnabled() ? "debug" : "info";
}

function enabled(level: Level): boolean {
  return LEVEL_ORDER[level] <= LEVEL_ORDER[activeLevel()];
}

export const logger = {
  info: (...args: any[]) => {
    if (enabled("info")) console.log("[INFO]", ...args);
  },
  error: (...args: any[]) => {
    if (enabled("error")) console.error("[ERROR]", ...args);
  },
  warn: (...args: any[]) => {
    if (enabled("warn")) console.warn("[WARN]", ...args);
  },
  debug: (...args: any[]) => {
    if (enabled("debug")) console.log("[DEBUG]", ...args);
  },
  /** Current effective level — logged at startup so a captured log
   *  always states whether debug was on when it was taken. */
  level: (): Level => activeLevel()
};
