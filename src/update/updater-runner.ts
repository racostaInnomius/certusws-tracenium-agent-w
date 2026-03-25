// src/update/updater-runner.ts

import { spawn } from "child_process";
import type { RunUpdateResult } from "./update-types";

export function runWindowsMsiUpdate(msiPath: string): RunUpdateResult {
  const args = ["/i", msiPath, "/qn", "/norestart"];

  const child = spawn("msiexec", args, {
    detached: true,
    stdio: "ignore",
    windowsHide: true
  });

  child.unref();

  return {
    started: true,
    command: "msiexec",
    args
  };
}