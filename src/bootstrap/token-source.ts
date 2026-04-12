// src/bootstrap/token-source.ts
import { execSync } from "child_process";
import fs from "fs";
import os from "os";

function enrollmentTokenFilePath(): string | null {
  if (process.env.TRACENIUM_ENROLLMENT_TOKEN_FILE) {
    return process.env.TRACENIUM_ENROLLMENT_TOKEN_FILE;
  }

  if (os.platform() === "darwin") {
    return "/Library/Application Support/Tracenium/Agent/enrollment.token";
  }

  if (os.platform() === "linux") {
    return "/var/lib/tracenium/enrollment.token";
  }

  return null;
}

function readTokenFile(): string | null {
  const file = enrollmentTokenFilePath();
  if (!file) return null;

  try {
    if (!fs.existsSync(file)) return null;
    const token = fs.readFileSync(file, "utf8").trim();
    return token.length > 0 ? token : null;
  } catch {
    return null;
  }
}

export function readEnrollmentToken(): string | null {
  // environment (funciona en dev / testing)
  if (process.env.ENROLLMENT_TOKEN) {
    return process.env.ENROLLMENT_TOKEN;
  }

  const tokenFromFile = readTokenFile();
  if (tokenFromFile) {
    return tokenFromFile;
  }

  // registry (usado en producción)
  if (os.platform() === "win32") {
    try {
      const out = execSync(
        'reg query "HKLM\\Software\\CertusWS\\Tracenium" /v ENROLLMENT_TOKEN',
        { stdio: ["pipe", "pipe", "ignore"] }
      ).toString();

      const parts = out.split("REG_SZ");
      if (parts.length > 1) {
        return parts[1].trim();
      }
    } catch {}
  }

  return null;
}

export function clearEnrollmentTokenFile(): void {
  const file = enrollmentTokenFilePath();
  if (!file) return;

  try {
    if (fs.existsSync(file)) {
      fs.rmSync(file, { force: true });
    }
  } catch {}
}
