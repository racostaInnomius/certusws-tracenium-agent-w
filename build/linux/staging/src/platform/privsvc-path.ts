// src/platform/privsvc-path.ts
import os from "os";

export function getPrivSvcPipePath(): string {
  const platform = os.platform();

  if (platform === "win32") {
    return "\\\\.\\pipe\\tracenium.privsvc.v1";
  }

  if (platform === "linux") {
    return "/var/run/tracenium/privsvc.sock";
  }

  if (platform === "darwin") {
    return "/var/run/tracenium/privsvc.sock";
  }

  throw new Error(`Unsupported platform for PrivSvc: ${platform}`);
}