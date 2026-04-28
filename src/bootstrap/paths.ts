// src/bootstrap/paths.ts
import os from "os";
import path from "path";
import fs from "fs";

const MACOS_AGENT_DATA_DIR = "/Library/Application Support/Tracenium/Agent";
const AGENT_STATUS_DIR_NAME = "status";
const TRAY_STATUS_FILE_NAME = "tray-status.json";

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

/**
 * El status dir vive como hermano del Agent dir, NO dentro de él.
 *
 * Razón: el Agent dir está en mode 700 (solo root) porque contiene
 * archivos sensibles — enrollment.token, .env, agent.db, certs mTLS.
 * Si pusiéramos el status JSON dentro de Agent/, el tray app (que
 * corre como user UID 501 vía LaunchAgent) no podría siquiera
 * traversear el dir para llegar al archivo, sin importar los perms
 * del archivo mismo.
 *
 * Layout final en macOS:
 *   /Library/Application Support/Tracenium/      mode 755 (root:wheel)
 *   /Library/Application Support/Tracenium/Agent/   mode 700 (sensitive)
 *   /Library/Application Support/Tracenium/status/  mode 755 (world-readable)
 *   /Library/Application Support/Tracenium/status/tray-status.json  mode 644
 *
 * El JSON contiene info del agente (hostname, deviceId, tenantId,
 * agentVersion, gRPC connection state, jobs, policy version) — nada
 * de eso es secreto, todo es operacionalmente útil para el tray.
 */
export function getAgentStatusDir(): string {
  // path.dirname() del Agent dir = el directorio padre (Tracenium/),
  // luego /status. Funciona en mac, win y linux con el mismo código.
  return path.join(path.dirname(agentDataDir()), AGENT_STATUS_DIR_NAME);
}

export function ensureAgentStatusDir(): string {
  const dir = getAgentStatusDir();
  fs.mkdirSync(dir, { recursive: true });
  // Aseguramos 755 explícitamente — depende del umask actual del
  // proceso, que en LaunchDaemons es típicamente 022 pero no
  // garantizado. Si el dir ya existía con perms más estrictos
  // (heredados de una instalación anterior), forzamos a 755.
  try {
    fs.chmodSync(dir, 0o755);
  } catch {
    // Ignore — si chmod falla (ej. en Windows o permission denied),
    // el dir queda con whatever perms tenía. El tray manejará el
    // caso "can't read" con el fallback de "No local status snapshot".
  }
  return dir;
}

export function getTrayStatusFilePath(): string {
  return path.join(getAgentStatusDir(), TRAY_STATUS_FILE_NAME);
}
