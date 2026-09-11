// src/bootstrap/enroll-payload.ts
import os from "os";
import si from "systeminformation";
import pkg from "../../package.json";
import { reportedOsArch } from "../domain/os-arch";

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
      // ⚠️ La de la MÁQUINA, no la del proceso: es el primer valor que el
      // control plane guarda del equipo y el que decide qué instalador se le
      // ofrece después. `os.arch()` —lo que había aquí— contesta para qué
      // arquitectura se compiló este Node, y en Windows on ARM eso no es lo
      // mismo. Ver domain/os-arch.ts.
      arch: reportedOsArch(),
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
