// src/update/updater-runner.ts

import { spawn } from "child_process";
import fs from "fs";
import type { RunUpdateResult } from "./update-types";

export function runWindowsMsiUpdate(msiPath: string): RunUpdateResult {
  if (!fs.existsSync(msiPath)) {
    throw new Error(`msi_not_found: ${msiPath}`);
  }

  const args = ["/i", msiPath, "/qn", "/norestart"];

  try {
    const child = spawn("msiexec", args, {
      detached: true,
      stdio: "ignore",
      windowsHide: true
    });

    child.on("error", (err) => {
      console.error("[update] msiexec spawn error", {
        error: err?.message || err,
        path: msiPath
      });
    });

    child.unref();

    console.log("[update] msiexec launched", {
      path: msiPath,
      pid: child.pid
    });

    return {
      started: true,
      command: "msiexec",
      args
    };
  } catch (err: any) {
    console.error("[update] failed to start msiexec", {
      error: err?.message || err,
      path: msiPath
    });

    throw err;
  }
}