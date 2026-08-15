// src/plugins/amp/providers/windows-location-consent.ts
//
// Grants THIS SERVICE ACCOUNT the Windows location consent, when the tenant's
// policy says location is on — and gives it back when the policy is switched
// off.
//
// Why this is needed at all
// -----------------------------------------------------------------------------
// Windows evaluates location consent in two places: a machine-wide switch
// (HKLM) that the Settings "Location services" toggle writes, and the consent
// of the account making the call (HKCU). The agent runs as LocalSystem, so its
// HKCU is HKU\S-1-5-18 — a branch no human ever visits and that no UI shows.
//
// A fleet was found with HKLM=Allow and SYSTEM=Deny: Settings said location was
// on, and every request from the agent was refused anyway. Nothing in the
// operating system surfaces that discrepancy, so it is not something an
// administrator can reasonably be expected to find.
//
// What we deliberately do NOT touch
// -----------------------------------------------------------------------------
// HKLM. That switch is the human's — it is what they see and set in Settings,
// and overriding it would be taking a decision that is visibly theirs. If it is
// Deny we report it and collect nothing; the operator turns it on if they mean
// to. We only grant the consent of our own service account, which is invisible
// in every UI and is the gate they cannot see to open.
//
// Reversal
// -----------------------------------------------------------------------------
// The value that was there before we touched it is recorded, and restored when
// the policy is switched off. Blanket-writing Deny on the way out would clobber
// an administrator's deliberate Allow — the switch has to leave the machine as
// it found it.

import fs from "fs";
import os from "os";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

const CONSENT_KEY =
  "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location";

/** Where the pre-existing value is remembered, so it can be given back. */
function priorValueFile(): string {
  const base = process.env.PROGRAMDATA || process.env.ProgramData || "C:\\ProgramData";
  return path.join(base, "Tracenium", "Agent", "location-consent-prior.json");
}

/**
 * Pull the value out of `reg query` output.
 *
 * Pure, and the only part of this module with real parsing to get wrong. The
 * output looks like:
 *
 *     HKEY_CURRENT_USER\SOFTWARE\...\location
 *         Value    REG_SZ    Allow
 *
 * Returns null when the key or the value is absent, which is meaningfully
 * different from "Deny": absent means nobody ever expressed a preference.
 */
export function parseRegValue(stdout: unknown): string | null {
  const text = typeof stdout === "string" ? stdout : "";
  // The value name is exactly "Value"; anchor on it so a key named
  // "ValueSomethingElse" cannot match.
  const m = text.match(/^\s*Value\s+REG_SZ\s+(\S+)\s*$/mi);
  return m ? m[1] : null;
}

/**
 * What we should write, given the policy and what is already there.
 *
 * Pure so the whole decision table is testable without a registry:
 *   - already correct        → nothing to do
 *   - enabling               → Allow, remembering what was there
 *   - disabling, we had set  → put the old value back
 *   - disabling, never set   → leave it alone; it was never ours
 */
export type ConsentPlan =
  | { action: "none"; reason: string }
  | { action: "set"; value: string; remember: string | null }
  | { action: "restore"; value: string }
  | { action: "clear" };

export function planConsent(
  enabled: boolean,
  current: string | null,
  prior: string | null | undefined
): ConsentPlan {
  const weHaveTouchedIt = prior !== undefined;

  if (enabled) {
    if (current === "Allow") return { action: "none", reason: "already allowed" };
    // Remember what was there — including "nothing", which restores as a delete.
    return { action: "set", value: "Allow", remember: current };
  }

  if (!weHaveTouchedIt) {
    // Never ours to change. An administrator's Deny (or Allow) stays exactly
    // as it is: switching our feature off is not licence to rewrite their
    // machine's settings.
    return { action: "none", reason: "not set by us" };
  }
  if (prior === null) return { action: "clear" };
  return { action: "restore", value: prior };
}

function readPrior(): string | null | undefined {
  try {
    const raw = fs.readFileSync(priorValueFile(), "utf8");
    const parsed = JSON.parse(raw);
    // `null` is a real remembered state (the value did not exist), so only an
    // outright missing field means "we never touched it".
    return "prior" in parsed ? parsed.prior : undefined;
  } catch {
    return undefined;
  }
}

function writePrior(value: string | null): void {
  const file = priorValueFile();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ prior: value, at: new Date().toISOString() }));
}

function forgetPrior(): void {
  try {
    fs.unlinkSync(priorValueFile());
  } catch {
    /* already gone */
  }
}

/**
 * Bring the service account's location consent in line with the tenant policy.
 *
 * Returns a short description of what happened, for the log. Never throws: this
 * runs on the inventory tick, and a registry that refuses us must degrade to
 * "no position" rather than break the snapshot.
 */
export async function applyWindowsLocationConsent(
  enabled: boolean,
  platform: string = os.platform()
): Promise<string | null> {
  if (platform !== "win32") return null;

  try {
    let current: string | null = null;
    try {
      const { stdout } = await execFileAsync("reg", ["query", CONSENT_KEY, "/v", "Value"], {
        timeout: 10_000,
        windowsHide: true,
      });
      current = parseRegValue(stdout);
    } catch {
      // Key absent entirely — same as no preference expressed.
      current = null;
    }

    const plan = planConsent(enabled, current, readPrior());

    switch (plan.action) {
      case "none":
        return null;

      case "set":
        await execFileAsync("reg", ["add", CONSENT_KEY, "/v", "Value", "/t", "REG_SZ", "/d", plan.value, "/f"], {
          timeout: 10_000,
          windowsHide: true,
        });
        writePrior(plan.remember);
        return `granted location consent to the service account (was ${plan.remember ?? "unset"})`;

      case "restore":
        await execFileAsync("reg", ["add", CONSENT_KEY, "/v", "Value", "/t", "REG_SZ", "/d", plan.value, "/f"], {
          timeout: 10_000,
          windowsHide: true,
        });
        forgetPrior();
        return `restored the service account's prior location consent (${plan.value})`;

      case "clear":
        await execFileAsync("reg", ["delete", CONSENT_KEY, "/v", "Value", "/f"], {
          timeout: 10_000,
          windowsHide: true,
        });
        forgetPrior();
        return "removed the location consent we had added to the service account";
    }
  } catch (err: any) {
    return `could not adjust the service account's location consent: ${String(err?.message ?? err).slice(0, 200)}`;
  }
}
