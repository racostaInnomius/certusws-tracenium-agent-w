// src/priv/ipc-types.ts

/**
 * Methods that Node can invoke on PrivSvc (request/response IPC).
 *
 * NOTE: Push notifications from PrivSvc back to Node (acks/control events)
 * use the `PrivSvcPushMethod` union below.
 */
export type PrivSvcMethod =
  | "ping"
  | "identity"
  | "software.inventory"
  // Faltaba en la union: el metodo lleva en el Router del PrivSvc desde
  // 1.1.18 y el agente lo llama, pero el tipo nunca lo supo — y sin entrada
  // en el mapa de presupuestos heredaba el default de 8s.
  | "printer.inventory"
  // Listas de extensiones de Chrome/Edge en HKLM (ver BrowserPolicyList.cs).
  | "browser.policy_list.read"
  | "browser.policy_list.write"
  | "security.compliance"
  | "patch.scan"
  | "patch.install"
  // Patch Management v2 — non-patch security remediation (TLS,
  // ciphers, SMB, firewall, etc) routed through the same PMP
  // plugin. Two methods:
  //   * `pmp.read_check_state` — read-only probe of the local
  //                              system state for a given checkId.
  //                              Used pre-install (idempotency
  //                              compute), pre-apply (state_before),
  //                              and post-apply (verification +
  //                              state_after). Returns
  //                              { state, isCompliant, supported }.
  //   * `pmp.remediate`        — apply the registry / plist /
  //                              powershell change. Privsvc dispatches
  //                              by checkId to a hardcoded whitelist
  //                              — NEVER executes catalog-supplied
  //                              scripts. Returns
  //                              { exitCode, stderrExcerpt,
  //                                durationMs, requiresReboot,
  //                                changesApplied[] }.
  | "pmp.read_check_state"
  | "pmp.remediate"
  // CDP — Crypto Discovery Plugin. Read-only enumeration of the
  // LocalMachine certificate stores via C# X509Store. Returns
  // { certificates: [{ store, rawDerBase64, hasPrivateKey }] }.
  // NEVER exports private key material — hasPrivateKey is the store
  // attribute only. Same read-only class as security.compliance.
  | "cdp.certs.read"
  // Faltaba en la union aunque el cliente ya le daba presupuesto: el
  // tipo se quedo atras cuando se anadio el metodo.
  | "cdp.certs.readUser"
  // ADR-0011 decision 10 — quitar la confianza a un ancla. DESCONFIAR,
  // no borrar: en Windows se anade a `Disallowed`, en macOS es un trust
  // setting de denegacion. Ver CdpAnchorDistrust.cs.
  | "cdp.anchor.distrust"
  // ── Los que faltaban, añadidos el 2026-09-24 ───────────────────────
  //
  // ⚠️ No se añadieron para callar al compilador: se comprobó uno por uno
  // que el router del PrivSvc los acepta, y en qué plataformas. Un método
  // que NO estuviera enrutado sería un fallo de campo esperando —como el
  // del indicador de Linux— y meterlo en la unión lo escondería.
  //
  // Enrutados en las tres (`privsvc/{linux,macos}/src/router.ts` y
  // `windows/…/Ipc/Router.cs`):
  | "cdp.anchor.state"
  | "cdp.csr.generate"
  | "cdp.cert.install"
  | "cdp.key.list"
  | "cdp.key.destroy"
  | "crypto.cert.renew"
  // Solo Windows: ADCS es un servicio de Active Directory.
  | "cdp.adcs.read"
  // ⚠️ Estos seis heredan el presupuesto por defecto (8 s) porque no están
  // en `getTimeoutForMethod` de ningún cliente. Queda dicho, no tocado:
  // subir un techo tiene consecuencias en campo y esto es cosa de CDP.
  | "crypto.csr.generate" // enrollment CSR generation
  | "crypto.cert.stage" // ADR-0015 pto.10: deja el bundle de CA en espera, en su propio mensaje
  | "crypto.cert.install" // install client cert (bind to existing key)
  // ADR-0013 — la clave con la que se abre la credencial de vCenter.
  //
  // Separada de la de enrolamiento porque esa NO puede descifrar: en
  // Windows se crea solo-firma y CNG lo hace cumplir, y en Linux/macOS
  // descifrar con ella contradice su propia KeyUsage critica.
  //
  // Vive con el rol de gateway y no con el equipo: es la unica clave del
  // parque capaz de descifrar, y solo existe donde hace falta.
  //   * `crypto.gwkey.ensure`  — params { deviceId }. Idempotente.
  //     Devuelve { certPem, fingerprintSha256, notAfter }.
  //   * `crypto.gwkey.destroy` — params { deviceId }. Idempotente.
  | "crypto.gwkey.ensure"
  | "crypto.gwkey.destroy"
  // gRPC bridge (PrivSvc owns mTLS private key + channel)
  // RCP — el agente avisa de que el DataChannel se abrió. Va por el mismo
  // camino que los demás: PrivSvc es el único dueño de la conexión gRPC.
  | "grpc.send.remoteSessionConnected"
  // ADR-0012 — la clave con la que se descifra la grabación de una sesión de
  // pantalla. Sin ella el vídeo es ilegible para siempre.
  | "grpc.send.remoteRecordingReady"
  | "grpc.connect"
  | "grpc.facts.send"
  | "grpc.facts.chunk"
  | "grpc.heartbeat"
  | "grpc.close"
  // Software Delivery Plugin (SDP) — Phase 1. The plugin lives in
  // src/plugins/sdp/ and orchestrates these three primitives:
  //   * `sdp.detect`   — evaluate a DetectionRule (registry /
  //                      bundle_version / pkg_receipt / file /
  //                      command). Returns { matched, snapshot }.
  //                      Used both pre-install (idempotency) and
  //                      post-install (verification of silent
  //                      installer success).
  //   * `sdp.download` — fetch the package binary into a privileged
  //                      staging dir and verify sha256. Returns
  //                      { stagingPath, sha256 }.
  //   * `sdp.install`  — exec the installer (msiexec / installer / etc)
  //                      with privsvc privileges. Returns
  //                      { exitCode, stderrExcerpt, durationMs }.
  | "sdp.detect"
  | "sdp.download"
  | "sdp.install"
  //   * `sdp.verifySignature` — full Authenticode verification of a
  //     downloaded package via the OS (WinVerifyTrust): digest + chain
  //     to the Windows trust store + revocation. Returns { trusted,
  //     reason }. Gate before install when the package requires signing.
  | "sdp.verifySignature"
  // Enrutados en las tres. `sdp.uninstall` (ADR-0019) y el prefetch del
  // Distribution Point.
  | "sdp.uninstall"
  | "sdp.dp.prefetch"
  // Solo Linux, y a propósito: la auto-actualización por paquete del SO
  // (deb/rpm). En Windows y macOS el camino es otro.
  | "agent.install"
  // ── RCP, solo Linux ────────────────────────────────────────────────
  //
  // Los cuatro son de Linux: en Windows y macOS el aviso vive en la bandeja
  // y el pty lo abre otro camino.
  //
  // ⚠️ Faltaban los cuatro, y no daban error de compilación porque sus
  // llamadas iban con `(ctx.priv as any).call(...)`. Un cast es un agujero
  // del mismo tamaño que el `any` que acaba de cerrarse: con él, a
  // `rcp.indicator.show` le habría pasado igual aunque el tipo existiera.
  | "rcp.indicator.show"
  | "rcp.indicator.hide"
  | "rcp.consent.request"
  | "rcp.pty.open"
  | "rcp.pty.close"
  // Los dos que mueven la pantalla, también escondidos tras un cast.
  // `screen.capture` está en las tres; `input.inject` no en Linux, donde
  // el control remoto de teclado y ratón todavía no existe.
  | "screen.capture"
  | "input.inject"
  // Infrastructure Gateway — vCenter credential custody. PrivSvc runs as
  // SYSTEM/root and already owns the mTLS private key, so it is the only
  // component that can open a credential envelope sealed against this
  // device's certificate, and the only one that should touch the OS
  // credential store. The control plane never sees the plaintext: the
  // admin's BROWSER seals it against the gateway's public key and the
  // backend only relays ciphertext it has no key for. See ADR-0001 (C).
  //
  //   * `credential.provision` — params { ref, envelope }. Opens the sealed
  //     envelope with the enrollment private key and writes the credential to
  //     the OS store (Windows Credential Manager / macOS Keychain / libsecret,
  //     falling back to an AES-256-GCM file at mode 0600). Returns
  //     { ok, certFingerprint } or fails with code
  //     `stale_envelope` when it was sealed against a certificate that has
  //     since rotated — deliberately distinct from a decrypt failure so the
  //     UI can tell the admin to re-enter rather than "invalid credential".
  //   * `credential.retrieve` — params { ref }. Returns { username, password }
  //     for the duration of ONE vCenter operation. Callers must not cache it.
  //   * `credential.remove`   — params { ref }. Used when a gateway is
  //     de-registered so the secret does not outlive its purpose.
  | "credential.provision"
  | "credential.retrieve"
  | "credential.remove";

export type GrpcAckParams = {
  eventId: string;
  status: number;
  message?: string;
  receivedAtUtc?: string;
};

/**
 * Methods that PrivSvc can PUSH to Node (unsolicited events).
 * Node must subscribe to these via a push sink / session.
 */
export type PrivSvcPushMethod =
  | "grpc.connected"
  | "grpc.ack"
  | "grpc.control.rotateCert"
  | "grpc.control.runJob"
  | "grpc.control.policyUpdate"
  | "grpc.control.disconnect"
  | "grpc.control.agentUpdate"
  | "grpc.control.streamClosed"
  | "grpc.disconnected"
  | "log";

export type PrivSvcRequest = {
  v: 1;
  /**
   * Correlation id (client-generated). If omitted, the IPC client may generate one.
   */
  id: string;
  method: PrivSvcMethod;
  params?: Record<string, any>;
  meta?: {
    tenantId: string;
    deviceId: string;
    traceId?: string;
  };
};

export type PrivSvcResponse =
  | { v: 1; id: string; ok: true; result: any; error: null }
  | { v: 1; id: string; ok: false; result: null; error: { code: string; message: string } };

/**
 * Push envelope format coming from PrivSvc.
 *
 * Examples:
 *  - { v:1, id:"...", method:"grpc.ack", params:{eventId,status,message,receivedAtUtc}, meta:{...} }
 */
export type PrivSvcPush =
  | {
      v: 1;
      id?: string;
      method: "grpc.ack";
      params: GrpcAckParams;
      meta?: {
        tenantId?: string;
        deviceId?: string;
        traceId?: string;
        connectionId?: string;
      };
    }
  | {
      v: 1;
      id?: string;
      method: Exclude<PrivSvcPushMethod, "grpc.ack">;
      params?: Record<string, any>;
      meta?: {
        tenantId?: string;
        deviceId?: string;
        traceId?: string;
        connectionId?: string;
      };
    };
