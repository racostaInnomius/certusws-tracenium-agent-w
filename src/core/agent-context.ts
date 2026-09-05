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
  // RCP M1.S1 — outbound control-message write surface for plugins
  // that don't follow the FACTS / job lifecycle (i.e. RCP signaling).
  // The grpc-stream module assigns this on init; it wraps
  // `ctx.priv.call("grpc.send", { ... })`. Optional in the type so
  // tests / unit modules that don't bring up the gRPC bridge don't
  // need to provide it.
  sendControl?: (msg: any) => void;
  // RCP user-attended approval — endpoint-side consent prompter. Optional:
  // when absent, the RCP session manager falls back to the fail-closed default
  // (see plugins/rcp/consent-prompt.ts), which denies until a platform-native
  // prompt is wired here.
  consentPrompter?: import("../plugins/rcp/consent-prompt").ConsentPrompter;
  /**
   * ADR-0015 — reemitir la identidad mTLS AHORA, sin mirar el umbral de
   * 30 días. Lo invoca el manejador de `rotateCert` del stream gRPC.
   *
   * Es un callback y no una llamada directa a `maybeRenewClientCertificate`
   * a propósito: la renovación de verdad no es sólo pedir el certificado,
   * es además comprobar que nadie mutó el enrolamiento mientras se
   * esperaba (TOCTOU) y **reiniciar el puente gRPC** cuando la huella
   * cambia. Todo eso ya vive en el bucle de `service.ts`, y llamarlo
   * desde dentro del propio manejador del stream significaría reiniciar
   * el puente desde el mensaje que está atendiendo.
   *
   * Opcional: quien no levante el ciclo de vida completo —tests, o el
   * arranque antes de que el servicio esté en pie— simplemente no lo
   * tiene, y el manejador lo dice en el log en vez de fallar.
   */
  requestCertRotation?: (reason: string) => void;
};
