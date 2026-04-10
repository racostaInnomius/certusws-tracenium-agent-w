// src/bootstrap/paths.ts
import os from "os";
import path from "path";
import fs from "fs";

function resolveProgramData(): string {
  return (
    process.env.PROGRAMDATA ||
    process.env.ProgramData ||
    "C:\\ProgramData"
  );
}

export function agentDataDir(): string {
  if (os.platform() === "win32") {
    return path.join(resolveProgramData(), "Tracenium", "Agent");
  }
  return path.join(os.homedir(), ".tracenium", "agent");
}

export function ensureAgentDataDir(): string {
  const dir = agentDataDir();
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

export function getDataRoot(): string {
  return agentDataDir();
}

export function getSoftwareBaselineDbPath(): string {
  return path.join(agentDataDir(), "agent.db");
}

export function getLegacySoftwareBaselineDbPath(): string {
  return path.join(process.cwd(), "data", "agent.db");
}
