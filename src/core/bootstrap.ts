// src/core/bootstrap.ts
import { ensureEnrolled } from "../bootstrap/enroll";
import { EnrollmentStore } from "../bootstrap/enrollment-store";
import { AgentContext } from "./agent-context";
import { config } from "../bootstrap/config";
import { createPrivSvcClient } from "../priv";
import { maybeRenewClientCertificate } from "../bootstrap/cert-renewal";
import { PolicyStore } from "./policy-store";
import { PolicyRuntime } from "./policy-runtime";
import { PluginManager } from "./plugin-manager";
import { logger } from "../bootstrap/logger";
import { TrayStatusStore } from "../status/tray-status-store";
import { outbox } from "../queue/sqlite-outbox";
import { loadUpdateState } from "../update/update-state";
import { decideSourceReport, sourceReportPayload } from "../update/update-source-report";

export async function bootstrapContext(): Promise<AgentContext> {

  const store = new EnrollmentStore();
  let enrollment = await ensureEnrolled();
  const priv = createPrivSvcClient();

  try {
    enrollment = await maybeRenewClientCertificate({
      enrollment,
      store,
      priv,
      logger
    });
  } catch (err: any) {
    logger.warn("[cert-renewal] renewal failed; continuing with existing certificate", err?.message || err);
  }

  const policy = new PolicyStore();
  await policy.load();

  const policyRuntime = new PolicyRuntime(policy, logger);
  await policyRuntime.init();

  const pluginManager = new PluginManager();
  const trayStatus = new TrayStatusStore();

  const agent = {
    version: config.agentVersion,
    platform: process.platform === "win32" ? "windows" : process.platform
  };

  const ctx: AgentContext = {
    config,
    agent,
    enrollment,
    store,
    priv,
    policy,
    policyRuntime,
    plugins: pluginManager,
    trayStatus,
    logger
  };

  await pluginManager.init(ctx);

  reportUpdateSource(agent.version);

  return ctx;
}

/**
 * Tell the control plane who served the installer for the version now running.
 *
 * The periodic update check has no job and no ACK behind it, so its `servedBy`
 * was computed and then dropped — leaving the one mechanism that moves the
 * fleet on its own as the one we could not measure. The tier is on disk, so the
 * report waits for the boot AFTER the install rather than racing the installer
 * that is about to replace this process.
 *
 * Enqueued on the outbox, not written to the stream: the outbox already gives
 * this durability and retry across reconnects, and it dedupes identical
 * payloads that are still pending.
 *
 * ⚠️ NOT CLEARED AFTERWARDS, DELIBERATELY.
 *
 * The first version of this wiped `lastServedBy` as soon as it enqueued, which
 * turned one lost delivery into permanent data loss — and the window where that
 * happens is exactly a rollout, when the agent can boot and report before the
 * backend that knows how to store it is live. That is not hypothetical: the
 * first fleet-wide run of this reported into a control plane that had no table
 * yet, and the state was already gone by the time it did.
 *
 * Re-reporting is free instead: the backend upserts on
 * (tenant, device, version), so a repeat is the same row written twice, and the
 * version guard stops it as soon as the endpoint moves on. Idempotent
 * reconciliation over fire-and-forget — the same reason the DP warmer states a
 * desired world every tick rather than firing a command once.
 *
 * Best effort throughout. This is telemetry; an agent that cannot report where
 * its bytes came from must still finish starting up.
 */
function reportUpdateSource(runningVersion: string): void {
  try {
    const report = decideSourceReport(loadUpdateState(), runningVersion);
    if (!report) return;

    outbox.enqueue({ type: "FACTS_SNAPSHOT", payload: sourceReportPayload(report) });
    logger.info("[update] reported install source", report);
  } catch (err: any) {
    logger.warn("[update] could not report install source", err?.message || err);
  }
}
