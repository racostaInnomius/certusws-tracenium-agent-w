// src/plugins/amp/index.ts
import os from "os";
import { getProvider } from "./providers";
import { collectGeo } from "./providers/geo";
import { applyWindowsLocationConsent } from "./providers/windows-location-consent";
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
  // Windows gates location on the consent of the CALLING account, and this
  // service runs as LocalSystem — a branch no UI shows and no admin can be
  // expected to find. Bring it in line with the policy before asking, and give
  // it back when the policy is switched off.
  const consentNote = await applyWindowsLocationConsent(
    Boolean(ctx.policyRuntime?.isFeatureEnabled?.("locationTracking")),
    platform
  );
  if (consentNote) {
    ctx.logger?.info?.(`AMP geo: ${consentNote}`);
  }

  const { geo, status, detail } = await collectGeo(
    Boolean(ctx.policyRuntime?.isFeatureEnabled?.("locationTracking")),
    platform
  );
  if (geo) {
    result.geo = geo;
  }
  // Always reported, including the failures: a blank Location column is
  // useless to an MSP unless it says WHY it is blank.
  result.geoStatus = status;

  // The OS's own words, when it refused. Only to the log: the wire carries the
  // category, and support needs the text to tell a consent-store problem from
  // an SKU that has no location provider at all.
  if (detail) {
    ctx.logger?.warn?.(`AMP geo: ${status} — ${detail}`);
  }

  return result;
}