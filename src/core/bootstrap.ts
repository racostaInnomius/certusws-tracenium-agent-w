// src/core/bootstrap.ts
import { ensureEnrolled } from "../bootstrap/enroll";
import { EnrollmentStore } from "../bootstrap/enrollment-store";
import { AgentContext } from "./agent-context";
import { config } from "../bootstrap/config";
import { PrivSvcClient } from "../priv/privsvc-client-windows";
import { PolicyStore } from "./policy-store";
import { PolicyRuntime } from "./policy-runtime";
import { pluginManager } from "./plugin-manager";

export async function bootstrapContext(): Promise<AgentContext> {

  const store = new EnrollmentStore();
  const enrollment = await ensureEnrolled();
  const priv = new PrivSvcClient();

  const policy = new PolicyStore();
  await policy.load();

  const policyRuntime = new PolicyRuntime(policy);
  await policyRuntime.init();

  await pluginManager.init({
     config,
     enrollment,
     store,
     priv,
     policy,
     policyRuntime,
     plugins: pluginManager
  } as any);

  return {
     config,
     enrollment,
     store,
     priv,
     policy,
     policyRuntime,
     plugins: pluginManager
  };
}