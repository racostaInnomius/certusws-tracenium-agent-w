// src/plugins/amm/providers/index.ts
import { windowsProvider } from "./windows";
import { macProvider } from "./macos";
import { linuxProvider } from "./linux";

import type { AgentContext } from "../../../core/agent-context";
import type { AmmNamespace } from "../../../domain/amm-types";

export interface AmmProvider {
  collect(ctx: AgentContext): Promise<AmmNamespace>;
}

export function getProvider(platform: NodeJS.Platform): AmmProvider {
  switch (platform) {
    case "win32":
      return windowsProvider;

    case "darwin":
      return macProvider;

    case "linux":
      return linuxProvider;

    default:
      throw new Error(`Unsupported platform: ${platform}`);
  }
}