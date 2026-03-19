// src/bootstrap/token-source.ts
import { execSync } from "child_process";

export function readEnrollmentToken(): string | null {
  // environment (funciona en dev / testing)
  if (process.env.ENROLLMENT_TOKEN) {
    return process.env.ENROLLMENT_TOKEN;
  }

  // registry (usado en producción)
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

  return null;
}