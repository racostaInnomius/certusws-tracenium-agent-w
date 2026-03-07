// src/plugins/amm/providers/index.ts
import { windowsProvider } from "./windows";
import { macProvider } from "./macos";
import { linuxProvider } from "./linux";

export function getProvider(platform: string) {
  if (platform === "win32") return windowsProvider;
  if (platform === "darwin") return macProvider;
  if (platform === "linux") return linuxProvider;

  throw new Error(`Unsupported platform: ${platform}`);
}