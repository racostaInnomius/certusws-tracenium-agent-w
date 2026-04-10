// src/plugins/amp/providers/index.ts
import { windowsProvider } from "./windows";
import { macProvider } from "./macos";
import { linuxProvider } from "./linux";

import type { AgentContext } from "../../../core/agent-context";
import type { AmpNamespace } from "../../../domain/amp-types";

export interface AmpProvider {
  collect(ctx: AgentContext): Promise<AmpNamespace>;
}

export function getProvider(platform: NodeJS.Platform): AmpProvider {
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