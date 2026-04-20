// src/bootstrap/enroll-payload.ts
import os from "os";
import si from "systeminformation";

export async function buildEnrollmentPayload() {
  const osInfo = await si.osInfo();
  const system = await si.system();

  return {
    agent: {
      agentVersion: "1.0.88",
      coreVersion: "1.0.88",
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
