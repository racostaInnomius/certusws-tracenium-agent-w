// test/priv/ipc-timeouts.test.ts
//
// Guards the IPC timeout invariant: the CALLER must outwait the HANDLER.
//
// A live endpoint failed its agent self-update with `PrivSvc timeout`. The
// cause was not the privileged work — it was that every SDP/update method fell
// through to the 8s default while the privsvc side budgets 600s for a download
// and 1740s for an install. The client hung up long before the handler could
// possibly answer, and because the failure surfaced as a generic timeout it
// read like a broken PrivSvc rather than a misconfigured budget.
//
// These assertions are deliberately about ORDERING against the privsvc-side
// ceilings, not about exact values, so tuning a budget stays easy while making
// it hard to reintroduce a client that gives up first.

import { describe, expect, it } from "vitest";
import fs from "fs";
import path from "path";

const CLIENTS = ["windows", "macos", "linux"] as const;

// Ceilings the privsvc side / the agent's own request uses, in seconds.
// Sources: privsvc Sdp.cs DefaultDownloadTimeoutSeconds / DefaultInstall-
// TimeoutSeconds, and plugins/sdp/dp.ts (prefetch asks for 840s).
const HANDLER_CEILING_SECONDS: Record<string, number> = {
  "sdp.download": 600,
  "sdp.install": 1740,
  "sdp.uninstall": 1740,
  "sdp.dp.prefetch": 840,
};

function clientSource(platform: string): string {
  return fs.readFileSync(
    path.join(__dirname, "..", "..", "src", "priv", `privsvc-client-${platform}.ts`),
    "utf8"
  );
}

/** Pull `case "<method>":` → returned milliseconds out of getTimeoutForMethod. */
function timeoutsFor(src: string): Map<string, number> {
  const fn = src.slice(
    src.indexOf("function getTimeoutForMethod"),
    src.indexOf("const CONNECT_TIMEOUT_MS")
  );
  const out = new Map<string, number>();
  // Cases stack up before a single return, so collect pending labels and
  // assign them all once the return is reached.
  let pending: string[] = [];
  for (const line of fn.split("\n")) {
    const c = line.match(/case\s+"([^"]+)"\s*:/);
    if (c) {
      pending.push(c[1]);
      continue;
    }
    const r = line.match(/return\s+([0-9*\s]+);/);
    if (r && pending.length) {
      // eslint-disable-next-line no-eval
      const ms = eval(r[1]) as number;
      for (const m of pending) out.set(m, ms);
      pending = [];
    }
  }
  return out;
}

describe.each(CLIENTS)("privsvc-client-%s IPC timeouts", (platform) => {
  const timeouts = timeoutsFor(clientSource(platform));

  it("gives every SDP/update method an explicit budget (never the 8s default)", () => {
    for (const method of [
      "sdp.download",
      "sdp.install",
      "sdp.uninstall",
      "sdp.dp.prefetch",
      "sdp.verifySignature",
      "sdp.detect",
      "agent.install",
    ]) {
      expect(timeouts.has(method), `${method} has no explicit timeout`).toBe(true);
    }
  });

  it("outwaits the privsvc-side ceiling for every long-running operation", () => {
    for (const [method, ceilingSeconds] of Object.entries(HANDLER_CEILING_SECONDS)) {
      const clientMs = timeouts.get(method)!;
      expect(
        clientMs,
        `${method}: client waits ${clientMs}ms but the handler may run ${ceilingSeconds * 1000}ms`
      ).toBeGreaterThan(ceilingSeconds * 1000);
    }
  });

  it("keeps signature verification well above the default (chain build can do network I/O)", () => {
    expect(timeouts.get("sdp.verifySignature")!).toBeGreaterThanOrEqual(30 * 1000);
  });
});
