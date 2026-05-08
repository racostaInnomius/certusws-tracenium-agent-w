// src/plugins/sdp/detection.ts
//
// SDP — Phase 1. Detection rule normalization + privsvc dispatch.
//
// The agent doesn't EVALUATE the rule itself — it can't, because
// every rule type needs OS-level access (registry hives, /Applications
// bundles, pkgutil, etc.) that requires privsvc context. This module
// is a thin shim that:
//
//   1. Normalizes the rule shape arriving from the backend (defends
//      against missing fields / wrong types if a future server
//      writes a malformed rule).
//   2. Sanity-checks platform fit (a `registry_uninstall` rule on a
//      macOS device would always evaluate to "not matched"; we
//      surface that explicitly instead of silently returning false).
//   3. Calls `priv.call("sdp.detect", { rule })` and parses the
//      response.
//
// The privsvc owns the actual evaluation. See P1-E for that side.

import os from "os";
import type { AgentContext } from "../../core/agent-context";

// Mirror of backend/agent shared shape. We re-declare it here
// (instead of importing from a hypothetical shared types package)
// because the agent + backend live in separate repos and there's no
// shared module yet. Keep both in lockstep — when adding a new rule
// type, update both files.
export type DetectionRule =
  | {
      type: "registry_uninstall";
      displayNameLike: string;
      minVersion?: string;
    }
  | {
      type: "bundle_version";
      bundleId: string;
      minVersion?: string;
    }
  | {
      type: "pkg_receipt";
      pkgId: string;
      minVersion?: string;
    }
  | {
      type: "file_exists";
      path: string;
    }
  | {
      type: "command_exit";
      cmd: string;
      args?: string[];
      stdoutMatches?: string;
    };

export type DetectionEvaluation = {
  matched: boolean;
  // Free-form snapshot of what the privsvc actually saw — for the
  // result row's `detection_before` / `detection_after` JSONB
  // columns. Useful when an operator asks "why did the rule say not
  // matched, what did it actually find?".
  snapshot?: any;
  // Why the rule wasn't even attempted (e.g. "registry_uninstall not
  // applicable on darwin"). Distinct from `matched=false` which means
  // "ran the check, came back empty".
  skipped?: boolean;
  skipReason?: string;
};

/**
 * Map rule.type → applicable platforms. A rule that doesn't apply
 * to the device's OS doesn't get sent to privsvc; we return a
 * skipped evaluation immediately. This avoids a privsvc round-trip
 * AND gives the operator a clearer error than "matched=false".
 */
const PLATFORM_APPLICABILITY: Record<DetectionRule["type"], Set<NodeJS.Platform>> = {
  registry_uninstall: new Set<NodeJS.Platform>(["win32"]),
  bundle_version: new Set<NodeJS.Platform>(["darwin"]),
  pkg_receipt: new Set<NodeJS.Platform>(["darwin"]),
  // file_exists and command_exit work cross-platform — Linux Phase 9
  // SDP relies on these as the only detection types it supports
  // until backend catalog seeds add native dpkg_installed /
  // rpm_installed types in a future migration.
  file_exists: new Set<NodeJS.Platform>(["win32", "darwin", "linux"]),
  command_exit: new Set<NodeJS.Platform>(["win32", "darwin", "linux"]),
};

/**
 * Normalize a raw rule from the runJob payload. We ALSO re-validate
 * minimally — the backend already validated on insert, but that was
 * potentially weeks ago and a future schema-loose backend could let
 * a malformed rule through. Cheap insurance.
 */
export function normalizeRule(raw: any): DetectionRule | null {
  if (!raw || typeof raw !== "object") return null;
  const type = String(raw.type || "");

  switch (type) {
    case "registry_uninstall": {
      if (typeof raw.displayNameLike !== "string") return null;
      const out: DetectionRule = { type, displayNameLike: raw.displayNameLike };
      if (typeof raw.minVersion === "string" && raw.minVersion.trim()) {
        (out as any).minVersion = String(raw.minVersion).trim();
      }
      return out;
    }
    case "bundle_version": {
      if (typeof raw.bundleId !== "string") return null;
      const out: DetectionRule = { type, bundleId: raw.bundleId };
      if (typeof raw.minVersion === "string" && raw.minVersion.trim()) {
        (out as any).minVersion = String(raw.minVersion).trim();
      }
      return out;
    }
    case "pkg_receipt": {
      if (typeof raw.pkgId !== "string") return null;
      const out: DetectionRule = { type, pkgId: raw.pkgId };
      if (typeof raw.minVersion === "string" && raw.minVersion.trim()) {
        (out as any).minVersion = String(raw.minVersion).trim();
      }
      return out;
    }
    case "file_exists": {
      if (typeof raw.path !== "string") return null;
      return { type, path: raw.path };
    }
    case "command_exit": {
      if (typeof raw.cmd !== "string") return null;
      const out: DetectionRule = { type, cmd: raw.cmd };
      if (Array.isArray(raw.args)) {
        (out as any).args = raw.args.map((a: unknown) => String(a));
      }
      if (typeof raw.stdoutMatches === "string" && raw.stdoutMatches) {
        (out as any).stdoutMatches = raw.stdoutMatches;
      }
      return out;
    }
    default:
      return null;
  }
}

/**
 * Run a detection rule via privsvc.
 *
 * Returns `{ matched: false, skipped: true, skipReason: ... }` when:
 *   * The rule type is unknown.
 *   * The rule type doesn't apply to this OS.
 *
 * The caller treats `skipped` as "we cannot tell" — for pre-install
 * detection that means "go ahead and install". For post-install
 * detection it means "we trust the exit code".
 */
export async function evaluate(
  ctx: AgentContext,
  rule: DetectionRule | null,
  jobId: string
): Promise<DetectionEvaluation> {
  if (rule == null) {
    return {
      matched: false,
      skipped: true,
      skipReason: "no_rule",
    };
  }

  const platform = os.platform();
  const applicable = PLATFORM_APPLICABILITY[rule.type]?.has(platform) ?? false;
  if (!applicable) {
    return {
      matched: false,
      skipped: true,
      skipReason: `rule_type_not_applicable_on_${platform}`,
    };
  }

  try {
    const resp = await ctx.priv.call({
      v: 1,
      id: `sdp-detect-${jobId}-${Date.now()}`,
      method: "sdp.detect",
      params: { rule },
      meta: {
        tenantId: ctx.enrollment.tenantId,
        deviceId: ctx.enrollment.deviceId,
      },
    });

    if (!resp?.ok) {
      // Privsvc method-not-implemented yet (P1-E hasn't landed) or
      // a runtime failure — treat as "cannot tell" so the install
      // still proceeds. Logging surfaces the cause.
      ctx.logger?.warn?.("[sdp.detect] privsvc returned not ok", {
        rule: rule.type,
        error: (resp as any)?.error,
      });
      return {
        matched: false,
        skipped: true,
        skipReason: `privsvc_error:${(resp as any)?.error?.code || "unknown"}`,
      };
    }

    const result = resp.result || {};
    return {
      matched: result.matched === true,
      snapshot: result.snapshot,
    };
  } catch (err: any) {
    ctx.logger?.warn?.("[sdp.detect] threw", {
      rule: rule.type,
      error: err?.message || String(err),
    });
    return {
      matched: false,
      skipped: true,
      skipReason: `privsvc_threw:${err?.message || "unknown"}`,
    };
  }
}
