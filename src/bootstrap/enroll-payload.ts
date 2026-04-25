// src/bootstrap/enroll-payload.ts
import os from "os";
import si from "systeminformation";
import pkg from "../../package.json";

export async function buildEnrollmentPayload() {
  const osInfo = await si.osInfo();
  const system = await si.system();

  return {
    agent: {
      // Read from package.json so a release-version bump is a
      // single-file change. See bootstrap/config.ts for the full
      // rationale (avoids the silent desync that produced agents
      // self-reporting the previous version after a successful
      // self-update).
      agentVersion: pkg.version,
      coreVersion: pkg.version,
      platform: os.platform(),
      arch: os.arch(),
    },
    device: {
      hostname: os.hostname(),
      os: {
        family: os.platform() === "win32" ? "windows" : os.platform() === "darwin" ? "macos" : "linux",
        version: osInfo.release,
        build: osInfo.build,
      },
      hardware: {
        manufacturer: system.manufacturer,
        model: system.model,
        serialNumber: system.serial,
        uuid: system.uuid,
      }
    }
  };
}
