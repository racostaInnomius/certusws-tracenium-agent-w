// src/bootstrap/paths.ts
import os from "os";
import path from "path";
import fs from "fs";

const MACOS_AGENT_DATA_DIR = "/Library/Application Support/Tracenium/Agent";

function resolveProgramData(): string {
  return (
    process.env.PROGRAMDATA ||
    process.env.ProgramData ||
    "C:\\ProgramData"
  );
}

export function getLegacyAgentDataDir(): string | null {
  if (os.platform() === "darwin") {
    return path.join(os.homedir(), ".tracenium", "agent");
  }
  return null;
}

export function agentDataDir(): string {
  if (os.platform() === "win32") {
    return path.join(resolveProgramData(), "Tracenium", "Agent");
  }
  if (os.platform() === "darwin") {
    return process.env.TRACENIUM_AGENT_DATA_DIR || MACOS_AGENT_DATA_DIR;
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
