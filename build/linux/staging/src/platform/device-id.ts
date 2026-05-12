// src/platform/device-id.ts
import os from "os";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { execSync } from "child_process";

function getWindowsDeviceId(): string {
  const regPath = "HKLM\\Software\\CertusWS\\Tracenium";

  try {
    const query = execSync(`reg query "${regPath}" /v DeviceId`, { encoding: "utf8" });

    const match = query.match(/DeviceId\s+REG_SZ\s+([^\r\n]+)/);

    if (match && match[1]) {
      return match[1].trim();
    }
  } catch {}

  const deviceId = crypto.randomUUID();

  try {
    execSync(`reg add "${regPath}" /f`);
    execSync(`reg add "${regPath}" /v DeviceId /t REG_SZ /d "${deviceId}" /f`);
  } catch {}

  return deviceId;
}

function getUnixDeviceId(): string {
  const baseDir = "/var/lib/tracenium";
  const file = path.join(baseDir, "device-id");

  try {
    if (fs.existsSync(file)) {
      return fs.readFileSync(file, "utf8").trim();
    }
  } catch {}

  const id = crypto.randomUUID();

  try {
    fs.mkdirSync(baseDir, { recursive: true });
    fs.writeFileSync(file, id, "utf8");
  } catch {}

  return id;
}

export function getDeviceId(): string {
  const platform = os.platform();

  if (platform === "win32") {
    return getWindowsDeviceId();
  }

  if (platform === "linux" || platform === "darwin") {
    return getUnixDeviceId();
  }

  throw new Error(`Unsupported platform for deviceId: ${platform}`);
}