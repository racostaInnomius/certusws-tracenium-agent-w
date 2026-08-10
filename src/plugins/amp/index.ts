// src/plugins/amp/index.ts
import os from "os";
import { getProvider } from "./providers";
import { collectGeo } from "./providers/geo";
import type { AgentContext } from "../../core/agent-context";
import type { AmpNamespace } from "../../domain/amp-types";

export async function collectAMP(ctx: AgentContext): Promise<AmpNamespace> {
  const platform = os.platform();
  const provider = getProvider(platform);

  const result = await provider.collect(ctx);

  // Defensa básica (evita romper scheduler si un provider falla silenciosamente)
  if (!result || typeof result !== "object") {
    throw new Error(`AMP provider returned invalid result for platform ${platform}`);
  }

  // Position is collected AFTER the inventory and merged in, never inside a
  // provider: it is gated by its own policy switch, it is the one field that is
  // personal data, and a slow or hung location service must not be able to
  // delay the rest of the snapshot.
  //
  // collectGeo re-checks the gate itself and swallows every failure, so this
  // stays a plain merge with no error handling of its own.
  const geo = await collectGeo(
    Boolean(ctx.policyRuntime?.isFeatureEnabled?.("locationTracking")),
    platform
  );
  if (geo) {
    result.geo = geo;
  }

  return result;
}