// src/core/bootstrap.ts
import { ensureEnrolled } from "../bootstrap/enroll";
import { EnrollmentStore } from "../bootstrap/enrollment-store";
import { AgentContext } from "./agent-context";
import { config } from "../bootstrap/config";
import { PrivSvcClient } from "../priv/privsvc-client-windows";
import { PolicyStore } from "./policy-store";
import { PolicyRuntime } from "./policy-runtime";
import { PluginManager } from "./plugin-manager";
import { logger } from "../bootstrap/logger";

export async function bootstrapContext(): Promise<AgentContext> {

  const store = new EnrollmentStore();
  const enrollment = await ensureEnrolled();
  const priv = new PrivSvcClient();

  const policy = new PolicyStore();
  await policy.load();

  const policyRuntime = new PolicyRuntime(policy, logger);
  await policyRuntime.init();

  const pluginManager = new PluginManager();

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
    logger
  };

  await pluginManager.init(ctx);

  return ctx;
}