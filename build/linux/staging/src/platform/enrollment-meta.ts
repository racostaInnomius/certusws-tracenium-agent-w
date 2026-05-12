// src/platform/enrollment-meta.ts
import os from "os";
import fs from "fs";
import path from "path";
import { spawnSync } from "child_process";

const WINDOWS_REG_PATH = "HKLM\\Software\\CertusWS\\Tracenium";
const UNIX_BASE_DIR = "/var/lib/tracenium";

type Metadata = {
  tenantId: string;
  enrolledAtUtc: string;
  agentVersion: string;
};

async function writeWindowsMetadata(meta: Metadata) {
  const regPath = WINDOWS_REG_PATH;

  function runReg(args: string[]) {
    const result = spawnSync("reg", args, { stdio: "ignore" });
    if (result.status !== 0) {
      throw new Error(`Registry command failed: reg ${args.join(" ")}`);
    }
  }

  runReg(["add", regPath, "/f"]);
  runReg(["add", regPath, "/v", "TenantId", "/t", "REG_SZ", "/d", meta.tenantId, "/f"]);
  runReg(["add", regPath, "/v", "EnrolledAt", "/t", "REG_SZ", "/d", meta.enrolledAtUtc, "/f"]);
  runReg(["add", regPath, "/v", "AgentVersion", "/t", "REG_SZ", "/d", meta.agentVersion, "/f"]);
}

async function writeUnixMetadata(meta: Metadata) {
  const baseDir = UNIX_BASE_DIR;
  const file = path.join(baseDir, "enrollment-meta.json");

  fs.mkdirSync(baseDir, { recursive: true });

  const tmpFile = file + ".tmp";

  fs.writeFileSync(
    tmpFile,
    JSON.stringify(meta, null, 2),
    "utf8"
  );

  fs.renameSync(tmpFile, file);
}

export async function writeEnrollmentMetadata(meta: Metadata) {
  const platform = os.platform();

  console.log("[Platform] Persisting enrollment metadata for platform:", platform);

  if (platform === "win32") {
    return writeWindowsMetadata(meta);
  }

  if (platform === "linux" || platform === "darwin") {
    return writeUnixMetadata(meta);
  }

  throw new Error(`Unsupported platform for enrollment metadata: ${platform}`);
}