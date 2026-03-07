// src/core/bootstrap.ts
import { ensureEnrolled } from "../bootstrap/enroll";
import { EnrollmentStore } from "../bootstrap/enrollment-store";
import { AgentContext } from "./agent-context";
import { config } from "../bootstrap/config";
import { PrivSvcClient } from "../priv/privsvc-client-windows";

export async function bootstrapContext(): Promise<AgentContext> {
  const store = new EnrollmentStore();
  const enrollment = await ensureEnrolled();
  const priv = new PrivSvcClient();
  return { config, enrollment, store, priv };
}