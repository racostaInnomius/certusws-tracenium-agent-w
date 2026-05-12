// src/core/agent-context.ts
import { EnrollmentState } from "../bootstrap/enrollment-state";
import { config } from "../bootstrap/config";
import { EnrollmentStore } from "../bootstrap/enrollment-store";
import { PolicyStore } from "./policy-store";
import { PolicyRuntime } from "./policy-runtime";
import { PluginManager } from "./plugin-manager";
import { TrayStatusStore } from "../status/tray-status-store";

export interface IPrivSvcClient {
  call(req: any): Promise<any>;
  close(): void;
  on?(event: string, cb: (...args: any[]) => void): void;
}

export type AgentContext = {
  config: typeof config;
  agent: {
    version: string;
    platform: string;
  };
  enrollment: EnrollmentState;
  store: EnrollmentStore;
  priv: IPrivSvcClient;
  policy: PolicyStore;
  policyRuntime: PolicyRuntime;
  plugins: PluginManager;
  trayStatus: TrayStatusStore;
  logger: any;
};
