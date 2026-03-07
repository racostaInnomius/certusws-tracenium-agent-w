// src/core/agent-context.ts
import { EnrollmentState } from "../bootstrap/enrollment-state";
import { config } from "../bootstrap/config";
import { EnrollmentStore } from "../bootstrap/enrollment-store";
import { PrivSvcClient } from "../priv/privsvc-client-windows";

export type AgentContext = {
  config: typeof config;
  enrollment: EnrollmentState;
  store: EnrollmentStore;
  priv: PrivSvcClient;
};