// src/plugins/rcp/screen-session.ts
//
// RCP M3.S4 — screen capture + streaming + input forwarding.
//   - M3.S1: capture loop + JPEG frame delivery
//   - M3.S2: chunked frame delivery for large frames (SCTP 65 KB cap)
//   - M3.S3: cursor position embedded in frame/frameStart for overlay
//   - M3.S4: synthetic input (mouse/keyboard) forwarded to PrivSvc.SendInput
//
// One ScreenSession is created per active rcp.screen DataChannel.
// It drives a periodic capture loop using the PrivSvc screen.capture
// IPC method (C# GDI+, works in Windows Session 0) and streams JPEG
// frames + cursor pos to the browser over the DataChannel.
//
// Protocol (see ScreenShareViewer.jsx for the browser side):
//
//   Agent → Browser:
//     { op: "screenInfo",  width, height, fps }                  // once at open
//     { op: "frame",  seq, width, height, data, cursorX, cursorY,
//                     full, x, y, rw, rh }                     // small (≤ limit)
//     { op: "frameStart", seq, width, height, chunks, cursorX, cursorY,
//                     full, x, y, rw, rh }                     // large
//     { op: "frameChunk", seq, idx, data }                       // one chunk
//     { op: "frameDone",  seq }                                  // all chunks sent
//     { op: "error", code, message, terminal }
//
//   Browser → Agent:
//     { op: "setQuality",  fps, quality }            // 1-100 JPEG quality
//     { op: "stop" }                                 // graceful close
//     { op: "mouseMove",  x, y }                     // M3.S4 — display-native px
//     { op: "mouseDown",  button, x, y }             // button: 0=L 1=M 2=R
//     { op: "mouseUp",    button, x, y }
//     { op: "wheel",      deltaX, deltaY, x, y }     // browser pixel deltas
//     { op: "keyDown",    code }                     // JS KeyboardEvent.code
//     { op: "keyUp",      code }
//     { op: "releaseAll" }                           // emergency release
//
// cursorX/Y are -1 when PrivSvc couldn't read the position (rare:
// lock screen, RDP detach). The browser hides the overlay in that case.
//
// Dirty rects: `width`/`height` are always the FULL desktop size (the browser
// sizes its canvas from them, and input coordinates map through them).
// `full` says whether `data` is the whole desktop or just the changed region
// at (`x`,`y`) sized `rw`×`rh`, which the browser blits onto what it already
// has. A response without `full` is a full frame — that's what the macOS and
// Linux helpers, which only do whole-screen grabs, produce.
//
// Error semantics (`op: "error"`):
//   `code` is PrivSvc's OWN stable code, forwarded verbatim — the browser
//   branches on it to explain the situation to the operator (no interactive
//   desktop, Wayland session, macOS TCC denied, …). This used to be collapsed
//   into a single hardcoded "CAPTURE_FAILED", which made every one of those
//   branches in ScreenShareViewer.jsx unreachable AND turned the routine
//   idle-desktop timeout into a fatal "Connection error".
//   `terminal` tells the browser whether the device can recover on its own:
//   false = transient blip, keep showing the stream; true = nothing will
//   arrive until something changes on the endpoint.
//
// The agent also fires RemoteScreenAudit gRPC events at "started" and
// "stopped"/"error" via the sendScreenAudit callback so the backend
// can persist session-level audit rows.

import type { AgentContext } from "../../core/agent-context";
import { consumeRevokeRequest } from "../../status/remote-session-revoke";
import {
  failClosedConsentPrompter,
  CONTROL_CONSENT_TIMEOUT_S,
  type ConsentDecision
} from "./consent-prompt";
import {
  controlGate,
  stateAfterDecision,
  shouldNotifyOperator,
  type ControlConsentState
} from "./control-consent";
import { recordingEnabled } from "./recording-policy";
import { ScreenRecorder } from "./screen-recorder";
import {
  fileSha256,
  removeRecording,
  writeConfirmedMarker
} from "./recording-handoff";

export type ScreenAuditPayload = {
  event: string;      // "started" | "stopped" | "error"
  width: number;
  height: number;
  fps: number;
  errorMessage: string;
};

type ScreenSessionArgs = {
  sessionId: string;
  ctx: AgentContext;
  /** Operador que abrió la sesión, para el indicador del endpoint. */
  operator?: string;
  sendScreenAudit: (audit: ScreenAuditPayload) => void;
  /**
   * Entrega la clave de la grabación al control plane (ADR-0012). Opcional
   * porque las sesiones de shell y de ficheros no graban.
   */
  sendRecordingReady?: (r: RecordingReadyPayload) => void;
  onTeardown: (reason: string) => void;
};

export type RecordingReadyPayload = {
  sessionId: string;
  keyBase64: string;
  bytes: number;
  frames: number;
  width: number;
  height: number;
  durationMs: number;
  truncated: boolean;
  stopReason: string;
  sha256: string;
};

const DEFAULT_FPS = 5;
const DEFAULT_QUALITY = 60;
const MIN_FPS = 1;
const MAX_FPS = 15;
const MIN_QUALITY = 10;
const MAX_QUALITY = 90;

// M3.S2 — max base64 chars per DataChannel message. Keeps each SCTP
// payload under the practical ~65 KB limit including JSON envelope
// overhead. 48 KB base64 ≈ 36 KB binary, well inside the limit.
const FRAME_CHUNK_MAX = 48_000;

// DXGI returns this whenever AcquireNextFrame times out with nothing new to
// hand over — i.e. the desktop simply didn't change. On an idle machine that
// fires every 500 ms. It is NOT a failure: the browser still has the last
// frame painted on its canvas, so we stay quiet and let the loop poll again.
const NO_FRAME_CODE = "screen_capture_no_frame";

// Cada cuánto se mira si la persona pulsó "detener" en su bandeja.
//
// 500 ms, no los 5 s del canal del catálogo. Esto es una REVOCACIÓN: el retraso
// entre pulsar y dejar de compartir es tiempo en el que siguen viendo una
// pantalla que ya no autorizan. Medio segundo se percibe como inmediato; cinco
// se perciben como que el botón no funciona, y esa es justo la sensación que un
// control de privacidad no puede permitirse.
const REVOKE_POLL_MS = 500;

// Cuánto se espera a que la persona conteste al aviso de CONTROL.
//
// El plazo de esta segunda puerta vive con el de la primera en
// consent-prompt.ts: el presupuesto IPC de `rcp.consent.request` se calcula
// sobre el mayor de los dos, y separados era cuestión de tiempo que subir uno
// rompiera esa cuenta en silencio.

// Codes meaning "this endpoint will not produce a frame until something
// changes on it" (someone logs in, an MDM profile lands, the session moves
// off Wayland, the helper gets installed). We surface these to the operator
// on the FIRST occurrence — waiting for the transient tolerance below would
// just leave them staring at a spinner. Everything not listed here is treated
// as a transient blip. Vocabulary is shared by all three PrivSvc
// implementations: ScreenCaptureDxgi.cs (Windows), privsvc/macos and
// privsvc/linux src/screen-capture.ts + their native helpers.
const TERMINAL_CAPTURE_CODES = new Set([
  "no_interactive_desktop",         // all three OSes — nobody logged in
  "wayland_unsupported",            // Linux — X11-only helper
  "no_screen_recording_permission", // macOS — TCC denegado (agentes previos al bundle)
  // macOS — se acaba de PEDIR el permiso y hay un diálogo abierto en el Mac.
  // Es terminal para ESTA sesión a propósito: reintentar cada 5 s no acelera a
  // la persona que está mirando el diálogo, solo llena el log y mantiene viva
  // una sesión que no va a dar imagen. Que el operador reintente cuando le
  // confirmen que ya está aprobado.
  "screen_recording_permission_pending",
  "screen_capture_helper_missing",  // macOS/Linux — helper not deployed
  "screen_capture_init_failed",     // Windows — DXGI chain wouldn't come up
  "screen_capture_no_display",      // no display attached at all
  "screen_capture_unsupported_adapter", // Windows — adapter can't do Desktop Duplication
  "screen_capture_access_denied",   // Windows — secure desktop / session isolation
  "x11_connect_failed",             // Linux — helper can't reach the X server
  // Linux — el aviso en pantalla que le dice a la persona que la están viendo
  // se cayó a mitad de sesión (ADR-0012). Terminal a propósito: PrivSvc no lo
  // resucita solo, así que reintentar cada 200 ms no arregla nada y solo
  // mantiene viva una sesión que ya no puede dar imagen. El operador abre otra
  // y eso vuelve a pasar por la puerta de arranque.
  "indicator_gone"
]);

// Consecutive non-terminal failures absorbed before we bother the browser. A
// UAC prompt, a fast-user-switch, a secure-desktop transition or a GPU driver
// reset each produce one or two bad captures and then recover by themselves;
// reporting those as errors is what made screen share look broken on
// perfectly healthy machines.
const TRANSIENT_ERROR_TOLERANCE = 5;

// Once a terminal condition is reported we keep polling — the operator may
// well fix it live (log into the console, approve the PPPC profile) and we
// want the stream to resume on its own. But we back off hard so a headless
// server doesn't burn a DXGI init attempt every 200 ms for hours.
const TERMINAL_RETRY_INTERVAL_MS = 5_000;

// Dirty-rect streaming: most frames carry only the region DXGI reports as
// changed, which for typing or a moving cursor is a tiny fraction of the
// screen. The browser blits each region onto the canvas it already has.
//
// That makes frames INTERDEPENDENT, and this DataChannel is deliberately
// unreliable (ordered:false, maxRetransmits:0) — a dropped partial update
// would otherwise leave a stale rectangle on the operator's screen forever,
// with nothing to correct it. So we force a full frame on a fixed cadence:
// the worst case for a drop becomes "wrong for up to this long" instead of
// "wrong until the session ends".
//
// 4s is a compromise: at 5fps that's one full frame in twenty, so the
// bandwidth win survives, and a corrupted region self-heals fast enough
// that an operator is unlikely to act on stale pixels.
const KEYFRAME_INTERVAL_MS = 4_000;

// How often to emit the throttled stream-stats line. Per-frame logging would
// be spam at 5-15fps, but with NOTHING logged there is no way to tell from an
// endpoint whether dirty rects are actually engaging — "the screen looked
// smooth" is not evidence, and the DXGI path can only be exercised on real
// Windows. One line every 10s is cheap and makes a smoke test measurable.
const STATS_INTERVAL_MS = 10_000;

export class ScreenSession {
  private readonly dc: any;
  private readonly args: ScreenSessionArgs;
  private disposed = false;
  private revokeTimer: NodeJS.Timeout | null = null;
  private captureTimer: NodeJS.Timeout | null = null;
  private fps = DEFAULT_FPS;
  private quality = DEFAULT_QUALITY;
  private seq = 0;
  private lastWidth = 0;
  private lastHeight = 0;
  private auditStartedSent = false;

  /**
   * Si en esta sesión ha llegado a inyectarse entrada (ADR-0012).
   *
   * POR QUÉ SE DEDUCE Y NO SE PREGUNTA
   *
   *   El botón "Controlling" de la UI solo decide si el NAVEGADOR del operador
   *   envía eventos; al agente no le llega ninguna señal de modo. Podríamos
   *   añadir un mensaje de control al canal, y sería peor: el indicador
   *   dependería de que el lado del operador dijera la verdad sobre lo que
   *   está haciendo el lado del operador.
   *
   *   Deducirlo de que llegó un evento real es más difícil de eludir. Lo que
   *   se le enseña a la persona es lo que le ha pasado a su equipo, no lo que
   *   la otra parte declara.
   *
   * POR QUÉ NO VUELVE A false
   *
   *   Se queda encendido el resto de la sesión. Apagarlo tras unos segundos
   *   sin eventos convertiría cada pausa del técnico —leer la pantalla, mirar
   *   un ticket— en "solo está viendo", que es justo el minuto en que la
   *   persona podría bajar la guardia y escribir una contraseña. El error se
   *   comete hacia avisar de más.
   *
   *   Cuando exista la segunda puerta de consentimiento (paso 2 del ADR), el
   *   permiso explícito sustituirá a esta deducción.
   */
  private inputSeen = false;

  /** Ya se avisó de que la entrada está bloqueada. Una vez por sesión. */
  private inputBlockedReported = false;

  /** Grabación de esta sesión (ADR-0012). null si el tenant no la activó. */
  private recorder: ScreenRecorder | null = null;

  /** Estado de la segunda puerta (ADR-0012). Ver control-consent.ts. */
  private controlConsent: ControlConsentState = "not_asked";

  /**
   * Instante de arranque, fijado UNA vez.
   *
   * El indicador se republica cuando cambia algo (el primer evento de entrada,
   * mañana la grabación). Si cada republicación recalculara la fecha, el
   * "lleva conectado desde…" saltaría hacia adelante en cada cambio y la
   * sesión parecería recién empezada justo cuando acaba de escalar a control.
   */
  private readonly startedAtUtc = new Date().toISOString();
  // Failure bookkeeping — see reportCaptureFailure.
  private consecutiveFailures = 0;
  // Last code pushed to the browser, so a persistent condition reports once
  // instead of once per capture tick. Cleared on the next good frame.
  private lastReportedCode: string | null = null;
  // True while we're in the slow retry cadence after a terminal report.
  private terminalBackoff = false;
  // When the last FULL frame went out. Drives the keyframe cadence that keeps
  // dirty-rect streaming self-healing over an unreliable channel. Starts at 0
  // so the very first capture is a keyframe.
  private lastKeyframeAtMs = 0;
  // Throttled stream stats — see STATS_INTERVAL_MS. Reset on each emit so
  // every line describes one window rather than the whole session.
  private statsWindowStartMs = 0;
  private statFrames = 0;
  private statPartials = 0;
  private statBytes = 0;
  private statPartialBytes = 0;

  constructor(dc: any, args: ScreenSessionArgs) {
    this.dc = dc;
    this.args = args;

    dc.onMessage((raw: any) => {
      if (this.disposed) return;
      try {
        const msg = JSON.parse(
          typeof raw === "string" ? raw : raw.toString()
        );
        this.handleMessage(msg);
      } catch {
        /* malformed JSON — ignore */
      }
    });

    dc.onClosed(() => {
      args.ctx.logger?.info?.("[rcp.screen] data channel closed", {
        sessionId: args.sessionId
      });
      this.stopCapture("data_channel_closed");
    });

    // ADR-0012 — indicador permanente en el equipo del usuario. Se publica
    // ANTES del primer fotograma: nadie debe ver su pantalla sin que el
    // indicador ya esté encendido, ni siquiera durante un instante.
    this.publishIndicator();
    this.startRevokeWatch();
    this.startRecording();

    // Start the capture loop after a tick so the constructor returns
    // cleanly before the first async capture fires.
    setImmediate(() => {
      if (this.disposed) return;
      void this.startAfterIndicator();
    });
  }

  /**
   * En Linux, ENCIENDE el indicador antes de capturar y aborta si no aparece.
   *
   * POR QUÉ AQUÍ HAY UNA PUERTA Y EN WINDOWS/macOS NO
   *
   *   En Windows y macOS el indicador lo pinta un proceso que YA vive en la
   *   sesión del usuario (la bandeja) leyendo el fichero de estado. Publicar
   *   el estado no puede fallar de forma que deje a alguien mirando sin aviso:
   *   si la bandeja no corre, tampoco corre nada más del lado del usuario.
   *
   *   Linux no tiene nada nuestro en la sesión gráfica. El aviso lo lanza
   *   PrivSvc a propósito para esta sesión, y ESO sí puede fallar por su
   *   cuenta: sin fuente utilizable, sin cookie X, con el helper ausente en un
   *   paquete construido sin libX11. En ese caso la elección es real —
   *   compartir pantalla sin que nadie pueda saberlo, o no compartirla.
   *
   *   ADR-0012 dice que el valor por defecto pasa a ser el seguro. Así que no
   *   se comparte.
   *
   *   El alcance de esa negativa es pequeño: la captura en Linux ya rechaza
   *   headless (`no_interactive_desktop`) y Wayland (`wayland_unsupported`)
   *   antes de llegar aquí. Lo único nuevo que se rechaza es "hay escritorio
   *   X11 pero el aviso no arranca", que es exactamente el caso que no
   *   queremos dejar pasar.
   */
  private async startAfterIndicator(): Promise<void> {
    if (process.platform === "linux") {
      const who = this.args.operator?.trim() || "A remote operator";
      let res: any = null;
      try {
        res = await this.args.ctx.priv?.call?.({
          id: `rcp.indicator.show.${this.args.sessionId}`,
          method: "rcp.indicator.show",
          params: {
            sessionId: this.args.sessionId,
            text: `${who} is viewing this screen`,
            button: "Stop sharing"
          }
        });
      } catch (err: any) {
        res = { ok: false, code: "indicator_call_failed", message: err?.message };
      }

      if (!res || res.ok !== true) {
        const code = String(res?.code || res?.error?.code || "indicator_unavailable");
        this.args.ctx.logger?.warn?.(
          "[rcp.screen] sin indicador visible: no se comparte pantalla",
          { sessionId: this.args.sessionId, code }
        );
        this.args.sendScreenAudit({
          event: "error",
          width: 0,
          height: 0,
          fps: this.fps,
          errorMessage: `indicator_unavailable:${code}`
        });
        this.stopCapture("indicator_unavailable");
        return;
      }
    }

    if (!this.disposed) this.scheduleNext();
  }

  /** ¿Exige el tenant consentimiento del usuario? */
  private consentRequired(): boolean {
    return Boolean(
      this.args.ctx.policyRuntime?.isFeatureEnabled?.("remoteRequireConsent")
    );
  }

  /**
   * Pide permiso para CONTROLAR y aplica la respuesta.
   *
   * Reutiliza el mismo seam que la puerta de ver (consent-prompt.ts), con una
   * capacidad distinta para que cada plataforma pueda redactar su texto: "va a
   * ver tu pantalla" y "va a poder usar tu equipo" no son la misma frase, y
   * enseñar la primera cuando pasa la segunda sería mentir.
   *
   * No lanza nunca. Cualquier fallo cuenta como negativa — un aviso roto no
   * puede convertirse en un permiso concedido.
   */
  private async askForControlConsent(): Promise<void> {
    const { ctx, sessionId } = this.args;
    const prompter = ctx.consentPrompter ?? failClosedConsentPrompter;

    let decision: ConsentDecision;
    try {
      decision = await prompter.request({
        sessionId,
        capability: "rcp.screen.control",
        operator: this.args.operator || null,
        timeoutSeconds: CONTROL_CONSENT_TIMEOUT_S
      });
    } catch (err: any) {
      ctx.logger?.error?.("[rcp.screen] el aviso de control falló; se deniega", {
        sessionId,
        err: err?.message || String(err)
      });
      decision = "denied";
    }

    if (this.disposed) return;

    const prev = this.controlConsent;
    this.controlConsent = stateAfterDecision(decision);

    if (this.controlConsent === "granted") {
      ctx.logger?.info?.("[rcp.screen] control autorizado por el usuario", { sessionId });
      // El indicador pasa a "viendo y controlando" en cuanto hay permiso, no
      // al llegar el primer evento que sí se reenvía: la persona acaba de
      // decir que sí y la banda tiene que reflejar lo que aceptó.
      this.inputSeen = true;
      this.publishIndicator();
      return;
    }

    ctx.logger?.info?.("[rcp.screen] control denegado por el usuario", {
      sessionId,
      decision
    });

    if (shouldNotifyOperator(prev, this.controlConsent)) {
      // El operador tiene que saber POR QUÉ sus clics no hacen nada. Sin esto
      // vería una pantalla que se mueve sola —porque la persona sigue
      // trabajando— y sus propios eventos sin efecto, que se diagnostica como
      // "el control remoto está roto".
      //
      // terminal:false a propósito: la sesión sigue viva y viéndose. Solo el
      // control quedó fuera.
      //
      // Se envía con `send` directo y NO por el reportador de fallos de
      // captura: aquel deduplica con lastReportedCode, que es estado de la
      // salud de la captura. Mezclar ahí un mensaje de consentimiento haría
      // que un fallo de captura posterior con el mismo código se tragara, o
      // al revés. Aquí la deduplicación ya la hace shouldNotifyOperator.
      this.send({
        op: "error",
        code: decision === "timeout" ? "control_consent_timeout" : "control_consent_denied",
        message:
          decision === "timeout"
            ? "The person at the device did not respond to the request to control it. Viewing continues."
            : "The person at the device declined to let you control it. Viewing continues.",
        terminal: false
      });
    }
  }

  /**
   * Abre la grabación si el tenant la tiene activada.
   *
   * No arrancar NO es un error de la sesión: se sigue dando soporte, sin
   * grabar, y el motivo queda registrado. La alternativa —negarse a dar
   * soporte porque no cabe el vídeo— castigaría a quien pidió ayuda por un
   * problema de disco que no es suyo.
   */
  private startRecording(): void {
    if (!recordingEnabled(this.args.ctx)) return;
    try {
      const rec = new ScreenRecorder(this.args.sessionId, this.args.ctx.logger as any);
      if (rec.start()) {
        this.recorder = rec;
        this.args.ctx.logger?.info?.("[rcp.screen] grabando la sesión", {
          sessionId: this.args.sessionId
        });
      }
    } catch (err: any) {
      this.args.ctx.logger?.warn?.("[rcp.screen] no se pudo iniciar la grabación", {
        sessionId: this.args.sessionId,
        err: err?.message || String(err)
      });
    }
  }

  /**
   * Cierra la grabación y deja constancia de CÓMO acabó.
   *
   * La auditoría tiene que poder distinguir tres cosas que se parecen y no lo
   * son: "no se grabó", "se grabó entera" y "se grabó a medias". Meses
   * después, para quien revise un incidente, la diferencia entre la segunda y
   * la tercera es si puede fiarse de lo que ve.
   *
   * ⚠️ La clave se queda AQUÍ, en el resultado, sin persistir. Mandarla al
   * control plane es el siguiente trozo del paso 3; hasta entonces la
   * grabación es ilegible a propósito, que es mejor que legible por cualquiera
   * que abra el portátil.
   */
  private stopRecording(): void {
    const rec = this.recorder;
    this.recorder = null;
    if (!rec) return;

    try {
      const res = rec.stop();
      this.args.ctx.logger?.info?.("[rcp.screen] grabación cerrada", {
        sessionId: this.args.sessionId,
        frames: res.frames,
        bytes: res.bytes,
        stopReason: res.stopReason,
        truncated: res.truncated
      });

      this.handOffRecording(res);
      if (res.truncated) {
        // Que quede en la auditoría del backend, no solo en el log local: el
        // log local vive en el equipo del usuario y nadie lo mira.
        this.args.sendScreenAudit({
          event: "error",
          width: this.lastWidth,
          height: this.lastHeight,
          fps: this.fps,
          errorMessage: `recording_truncated:${res.stopReason}`
        });
      }
    } catch (err: any) {
      this.args.ctx.logger?.warn?.("[rcp.screen] fallo cerrando la grabación", {
        sessionId: this.args.sessionId,
        err: err?.message || String(err)
      });
    }
  }

  /**
   * Entrega la clave, o borra el fichero si no hay a quién entregársela.
   *
   * ⚠️ El borrado NO es limpieza opcional. La clave solo existe en memoria; si
   * no sale de aquí, ese fichero queda indescifrable para siempre y lo único
   * que hace es ocupar el disco de la persona a la que se grabó. Guardarlo
   * "por si acaso" no tiene caso: no hay ningún futuro en el que esa clave
   * reaparezca.
   *
   * Se envía y se marca en el mismo paso. La marca es lo que salva al fichero
   * del barrido de arranque; sin ella, el próximo inicio del agente lo tratará
   * —correctamente— como huérfano.
   */
  private handOffRecording(res: {
    path: string | null;
    bytes: number;
    frames: number;
    keyBase64: string;
    stopReason: string;
    truncated: boolean;
  }): void {
    if (!res.path) return; // no se grabó nada

    const send = this.args.sendRecordingReady;
    if (!send) {
      // Sin canal de entrega no hay grabación posible. Es el caso de una
      // versión del agente con grabación activada y un session-manager que no
      // la cablea — mejor borrarlo que dejarlo.
      this.args.ctx.logger?.warn?.(
        "[rcp.screen] no hay canal para entregar la clave; se descarta la grabación",
        { sessionId: this.args.sessionId }
      );
      removeRecording(res.path);
      return;
    }

    try {
      send({
        sessionId: this.args.sessionId,
        keyBase64: res.keyBase64,
        bytes: res.bytes,
        frames: res.frames,
        width: this.lastWidth,
        height: this.lastHeight,
        durationMs: Date.now() - Date.parse(this.startedAtUtc),
        truncated: res.truncated,
        stopReason: res.stopReason,
        sha256: fileSha256(res.path)
      });
      writeConfirmedMarker(res.path, { sessionId: this.args.sessionId });
    } catch (err: any) {
      this.args.ctx.logger?.warn?.(
        "[rcp.screen] falló la entrega de la clave; se descarta la grabación",
        { sessionId: this.args.sessionId, err: err?.message || String(err) }
      );
      removeRecording(res.path);
    }
  }

  /**
   * Explica el final de la sesión por el canal de datos, si hay algo que
   * explicar.
   *
   * Solo para los motivos que el operador NO puede deducir. Un cierre que
   * pidió él mismo, o un canal que se cae, ya se explican solos; anunciarlos
   * añadiría ruido a un cierre normal.
   */
  private sendStopReason(reason: string): void {
    const known: Record<string, string> = {
      revoked_by_user:
        "The person using this device ended the session from the on-screen " +
        "banner. This was their decision, not a connection problem — reopening " +
        "without asking them first is not appropriate.",
      indicator_unavailable:
        "The session was refused because the device could not show the " +
        "on-screen notice telling the user they are being viewed."
    };
    const message = known[reason];
    if (!message) return;

    try {
      this.send({ op: "error", code: reason, message, terminal: true });
    } catch {
      /* el canal ya se fue; el motivo queda en la auditoría igualmente */
    }
  }

  /** Retira el indicador nativo de Linux. No lanza: corre en el cierre. */
  private hideLinuxIndicator(): void {
    if (process.platform !== "linux") return;
    try {
      void this.args.ctx.priv?.call?.({
        id: `rcp.indicator.hide.${this.args.sessionId}`,
        method: "rcp.indicator.hide",
        params: {}
      });
    } catch {
      /* el proceso se está cerrando */
    }
  }

  /** Enciende el indicador de la bandeja para esta sesión. */
  private publishIndicator(): void {
    try {
      this.args.ctx.trayStatus?.setRemoteSession?.({
        active: true,
        sessionId: this.args.sessionId,
        capability: "rcp.screen",
        operator: this.args.operator || "",
        controlling: this.inputSeen,
        // El derecho a saber que te graban no se agota al aceptar: dura lo que
        // dure la grabación. Se lee de la política en cada publicación, no se
        // fija al abrir, porque el tenant puede cambiarlo con la sesión viva.
        recording: recordingEnabled(this.args.ctx),
        startedAtUtc: this.startedAtUtc
      });
    } catch (err: any) {
      // No tumbar la sesión porque el indicador no se pueda escribir, pero
      // dejarlo MUY visible en el log: significa que hay alguien viendo una
      // pantalla sin que su dueño tenga forma de saberlo.
      this.args.ctx.logger?.warn?.(
        "[rcp.screen] no se pudo publicar el indicador de sesión",
        { sessionId: this.args.sessionId, err: err?.message }
      );
    }
  }

  /** Apaga el indicador. Un indicador que se queda encendido tras cerrar la
   *  sesión enseña una alarma falsa y entrena a la gente a ignorarla. */
  private clearIndicator(): void {
    try {
      this.args.ctx.trayStatus?.setRemoteSession?.(null);
    } catch {
      /* el proceso se está cerrando; nada que hacer */
    }
  }

  private startRevokeWatch(): void {
    const poll = () => {
      if (this.disposed) return;
      let req = null;
      try {
        req = consumeRevokeRequest(this.args.sessionId);
      } catch {
        /* consumeRevokeRequest no lanza, pero el bucle de captura no es
           sitio para averiguarlo por las malas */
      }
      if (req) {
        this.args.ctx.logger?.info?.("[rcp.screen] sesión revocada en el endpoint", {
          sessionId: this.args.sessionId,
          by: req.by
        });
        // El motivo viaja al operador y al registro de auditoría: no fue un
        // fallo de red, fue una persona retirando su consentimiento. Que esos
        // dos casos se distingan es la mitad del valor de tener el control.
        this.stopCapture("revoked_by_user");
        return;
      }
      this.revokeTimer = setTimeout(poll, REVOKE_POLL_MS);
    };
    this.revokeTimer = setTimeout(poll, REVOKE_POLL_MS);
  }

  // ── Internal helpers ───────────────────────────────────────────────────────

  private send(obj: object): void {
    if (this.disposed) return;
    try {
      this.dc.sendMessage(JSON.stringify(obj));
    } catch (err: any) {
      this.args.ctx.logger?.warn?.("[rcp.screen] send failed", {
        sessionId: this.args.sessionId,
        err: err?.message
      });
    }
  }

  private handleMessage(msg: any): void {
    const op = String(msg?.op ?? "");
    switch (op) {
      case "setQuality": {
        const fps = Number(msg.fps);
        const quality = Number(msg.quality);
        const previousFps = this.fps;
        if (Number.isFinite(fps) && fps > 0)
          this.fps = Math.max(MIN_FPS, Math.min(MAX_FPS, Math.round(fps)));
        if (Number.isFinite(quality) && quality > 0)
          this.quality = Math.max(MIN_QUALITY, Math.min(MAX_QUALITY, Math.round(quality)));
        // Echo the APPLIED frame rate back when it changed. The browser's
        // slider can ask for anything; MIN_FPS/MAX_FPS clamp it here, and
        // without this echo the UI would keep displaying a value the agent
        // never honoured.
        if (this.fps !== previousFps && this.seq > 0) {
          this.send({
            op: "screenInfo",
            width: this.lastWidth,
            height: this.lastHeight,
            fps: this.fps
          });
        }
        // Reschedule with new interval.
        if (this.captureTimer) {
          clearTimeout(this.captureTimer);
          this.captureTimer = null;
        }
        if (!this.disposed) this.scheduleNext();
        break;
      }
      case "stop":
        this.stopCapture("operator_stopped");
        break;

      // M3.S4 — input forwarding. The browser sends mouse + keyboard
      // events as JSON; we forward them to PrivSvc.SendInject. Each
      // call is fire-and-forget — IPC errors are logged but never
      // tear down the session (a transient SendInput failure should
      // not kill the screen stream).
      case "mouseMove":
      case "mouseDown":
      case "mouseUp":
      case "wheel":
      case "keyDown":
      case "keyUp":
      case "releaseAll":
        this.forwardInput(op, msg);
        break;
    }
  }

  // M3.S4 — Forward an input op to PrivSvc.SendInput via IPC.
  // We strip the message down to the fields PrivSvc actually needs
  // and pass `op` explicitly so the C# router knows which branch
  // to take inside InputInjection.Inject.
  private forwardInput(op: string, msg: any): void {
    const { ctx, sessionId } = this.args;

    // ADR-0012, segunda puerta: CONTROLAR se consiente aparte de VER.
    //
    // Va aquí, en el reenvío de cada evento, porque es el único punto por el
    // que pasa todo lo que llega a actuar sobre el equipo. Ponerlo donde la UI
    // del operador pulsa "Controlling" no serviría: eso es un botón en el
    // navegador de la otra parte, y la puerta no puede depender de que quien
    // pide permiso se lo pida a sí mismo.
    const gate = controlGate(this.consentRequired(), this.controlConsent);
    if (gate.kind === "ask") {
      this.controlConsent = "pending";
      void this.askForControlConsent();
      return; // este evento se tira: aún no hay permiso
    }
    if (gate.kind === "drop") return;

    // Primer evento de entrada de la sesión: subir el indicador de "viendo" a
    // "viendo y controlando". Una sola vez — republicar en cada movimiento de
    // ratón escribiría el fichero de estado cientos de veces por minuto.
    if (!this.inputSeen) {
      this.inputSeen = true;
      this.publishIndicator();
    }
    const params: Record<string, any> = { op };
    // Mouse fields (coordinates + button)
    if ("x" in msg)      params.x      = Number(msg.x);
    if ("y" in msg)      params.y      = Number(msg.y);
    if ("button" in msg) params.button = Number(msg.button);
    // Wheel deltas
    if ("deltaX" in msg) params.deltaX = Number(msg.deltaX);
    if ("deltaY" in msg) params.deltaY = Number(msg.deltaY);
    // Keyboard
    if ("code" in msg)   params.code   = String(msg.code);

    (ctx.priv as any)
      .call({
        v: 1,
        id: `input.inject.${Date.now()}`,
        method: "input.inject",
        params
      })
      .then((res: any) => {
        // ⚠️ El IPC devuelve Success aunque SendInput haya sido BLOQUEADO: el
        // `ok` de la respuesta va DENTRO del resultado (ver InputInjection.cs,
        // que hace soft-fail a propósito para no reintentar en bucle). Si no
        // se mira aquí, el operador ve el cursor congelado y no hay ni una
        // línea en ningún log que lo explique — que es exactamente lo que
        // pasó en campo.
        const inner = res?.result ?? res;
        if (inner && inner.ok === false) {
          this.reportInputBlocked(String(inner.hint || ""));
        }
      })
      .catch((err: any) => {
        ctx.logger?.debug?.("[rcp.screen] input.inject failed", {
          sessionId,
          op,
          err: err?.message
        });
      });
  }

  /**
   * Avisa al operador de que su entrada NO está llegando al equipo.
   *
   * En Windows esto es casi siempre UIPI: un proceso de integridad media no
   * puede mandar entrada sintética a una ventana ELEVADA. Con la consola de
   * servicios, un cmd "como administrador" o cualquier ventana con escudo en
   * primer plano, SendInput se descarta y devuelve 0.
   *
   * Se avisa UNA vez por sesión: los eventos de ratón llegan a decenas por
   * segundo y repetirlo llenaría el canal. Y no es terminal — en cuanto la
   * ventana elevada pierde el foco, el control vuelve solo.
   */
  private reportInputBlocked(hint: string): void {
    if (this.inputBlockedReported) return;
    this.inputBlockedReported = true;

    this.args.ctx.logger?.warn?.("[rcp.screen] la entrada está siendo bloqueada", {
      sessionId: this.args.sessionId,
      hint
    });

    this.send({
      op: "error",
      code: "input_blocked_elevated",
      message:
        "Input is not reaching the device. On Windows this happens while an " +
        "elevated window has focus (Services, an administrator command prompt, " +
        "or a UAC prompt): the operating system blocks synthetic input to " +
        "windows running with higher privileges. Ask the user to close or " +
        "minimise it, and control resumes on its own.",
      terminal: false
    });
  }

  // M3.S2 — split a large base64 JPEG string into FRAME_CHUNK_MAX
  // slices and send them as frameStart / frameChunk[] / frameDone.
  // The browser reassembles before rendering; any chunk dropped by
  // the unreliable DataChannel causes the whole frame to be discarded
  // when the browser receives the next frameStart.
  //
  // M3.S3 — cursor pos rides on frameStart so the overlay updates in
  // lockstep with the frame, even if a chunk is dropped.
  private sendFrameChunked(
    seq: number,
    width: number,
    height: number,
    data: string,
    cursorX: number,
    cursorY: number,
    region: { full: boolean; x: number; y: number; rw: number; rh: number }
  ): void {
    const chunks: string[] = [];
    for (let i = 0; i < data.length; i += FRAME_CHUNK_MAX) {
      chunks.push(data.slice(i, i + FRAME_CHUNK_MAX));
    }
    this.send({
      op: "frameStart",
      seq,
      width,
      height,
      chunks: chunks.length,
      cursorX,
      cursorY,
      ...region
    });
    for (let idx = 0; idx < chunks.length; idx++) {
      this.send({ op: "frameChunk", seq, idx, data: chunks[idx] });
    }
    this.send({ op: "frameDone", seq });
  }

  // ── Capture loop ───────────────────────────────────────────────────────────

  private scheduleNext(): void {
    if (this.disposed) return;
    // In terminal backoff we poll slowly instead of at the requested frame
    // rate — the next successful capture clears the flag and we snap back to
    // the operator's fps.
    const intervalMs = this.terminalBackoff
      ? TERMINAL_RETRY_INTERVAL_MS
      : Math.round(1000 / this.fps);
    this.captureTimer = setTimeout(async () => {
      if (!this.disposed) await this.captureFrame();
      if (!this.disposed) this.scheduleNext();
    }, intervalMs);
    // Don't keep the Node.js event loop alive just for this timer.
    (this.captureTimer as any).unref?.();
  }

  private async captureFrame(): Promise<void> {
    if (this.disposed) return;
    const { ctx, sessionId, sendScreenAudit } = this.args;

    try {
      // Ask for a keyframe when the cadence is due. The capture side also
      // forces one after a duplication-chain re-init, where its dirty rects
      // have nothing to diff against.
      const now = Date.now();
      const wantKeyframe = now - this.lastKeyframeAtMs >= KEYFRAME_INTERVAL_MS;

      const result = await (ctx.priv as any).call({
        v: 1,
        id: `screen.capture.${now}`,
        method: "screen.capture",
        params: { quality: this.quality, forceFull: wantKeyframe }
      });

      if (!result?.ok) {
        // Forward PrivSvc's OWN code — see the error semantics note at the
        // top of this file for why collapsing it was a bug.
        const errCode =
          String(result?.error?.code ?? "").trim() || "screen_capture_failed";
        const errMsg = String(
          result?.error?.message ?? result?.error ?? "capture failed"
        );
        this.reportCaptureFailure(errCode, errMsg);
        return;
      }

      // Good capture — clear the failure state so a session that recovers
      // (user logs back in, UAC prompt dismissed) reports cleanly if it
      // fails again later, and drops out of the slow retry cadence.
      this.consecutiveFailures = 0;
      this.lastReportedCode = null;
      this.terminalBackoff = false;

      const data: string = String(result.result?.data ?? "");
      const width: number = Number(result.result?.width ?? 0);
      const height: number = Number(result.result?.height ?? 0);
      // M3.S3 — cursor pos comes from C# GetCursorPos. -1 means
      // PrivSvc couldn't read it (rare; lock screen, RDP detach).
      const cursorX: number = Number(result.result?.cursorX ?? -1);
      const cursorY: number = Number(result.result?.cursorY ?? -1);
      // Region metadata. macOS/Linux helpers only ever produce whole-screen
      // grabs and don't send these, so absent `full` means full — never
      // treat a legacy response as a partial update sitting at (0,0).
      const full: boolean = result.result?.full !== false;
      const rx: number = Number(result.result?.x ?? 0);
      const ry: number = Number(result.result?.y ?? 0);
      const rw: number = Number(result.result?.rw ?? width);
      const rh: number = Number(result.result?.rh ?? height);

      if (!data) return;
      if (full) this.lastKeyframeAtMs = Date.now();

      // Send screenInfo on the first frame or when screen resolution changes.
      if (this.seq === 0 || width !== this.lastWidth || height !== this.lastHeight) {
        this.send({ op: "screenInfo", width, height, fps: this.fps });

        if (!this.auditStartedSent) {
          this.auditStartedSent = true;
          sendScreenAudit({
            event: "started",
            width,
            height,
            fps: this.fps,
            errorMessage: ""
          });
        }

        this.lastWidth = width;
        this.lastHeight = height;
      }

      // M3.S2 — send as a single message when small enough; chunk
      // otherwise to stay under the SCTP DataChannel size limit.
      // M3.S3 — cursorX/Y travel on the frame (single message) or
      // frameStart (chunked) so the browser can overlay the cursor in
      // sync with the underlying frame.
      const frameSeq = this.seq++;
      const region = { full, x: rx, y: ry, rw, rh };
      this.recordFrameStats(full, data.length);

      // ADR-0012 — grabación. Se ofrece el MISMO fotograma que va al operador,
      // así que la grabación es exactamente lo que se vio, no una captura
      // aparte que podría diferir. El grabador decide solo si le toca
      // guardarlo, y nunca lanza: un fallo grabando no puede tumbar la sesión
      // de soporte que está grabando.
      this.recorder?.offer({
        payload: Buffer.from(data, "base64"),
        full,
        x: rx,
        y: ry,
        rw,
        rh,
        w: width,
        h: height
      });
      if (data.length <= FRAME_CHUNK_MAX) {
        this.send({ op: "frame", seq: frameSeq, width, height, data, cursorX, cursorY, ...region });
      } else {
        this.sendFrameChunked(frameSeq, width, height, data, cursorX, cursorY, region);
      }
    } catch (err: any) {
      // IPC itself threw (PrivSvc reconnecting, pipe closed mid-call). Same
      // treatment as a failed capture: transient until proven otherwise.
      this.reportCaptureFailure(
        "screen_capture_ipc_error",
        err?.message || String(err)
      );
    }
  }

  /**
   * Decide what a failed capture means and whether the browser needs to hear
   * about it.
   *
   * Three outcomes:
   *   - `screen_capture_no_frame`: not a failure at all. The desktop didn't
   *     change; the browser's canvas already holds the right pixels. Silent.
   *   - terminal code: report immediately (once), then keep retrying slowly
   *     in case the operator fixes the condition live.
   *   - anything else: absorb up to TRANSIENT_ERROR_TOLERANCE consecutive
   *     occurrences, then report as non-terminal so the browser can warn
   *     without tearing the viewer down.
   */
  /**
   * Accumulate per-frame counters and emit one summary line per window.
   *
   * This is the only observable evidence that dirty rects are engaging on a
   * real endpoint. `partial%` near 0 on an active desktop means the crop
   * decision never fires (bad dirty-rect metadata, or every change exceeding
   * DIRTY_MAX_AREA_PERCENT); `avgPartialKb` vs `avgKb` is the actual saving.
   */
  private recordFrameStats(full: boolean, payloadLen: number): void {
    const now = Date.now();
    if (this.statsWindowStartMs === 0) this.statsWindowStartMs = now;

    this.statFrames += 1;
    this.statBytes += payloadLen;
    if (!full) {
      this.statPartials += 1;
      this.statPartialBytes += payloadLen;
    }

    const elapsed = now - this.statsWindowStartMs;
    if (elapsed < STATS_INTERVAL_MS) return;

    const frames = this.statFrames;
    const partials = this.statPartials;
    const fulls = frames - partials;
    const kb = (n: number) => Math.round(n / 1024);
    this.args.ctx.logger?.info?.("[rcp.screen] stream stats", {
      sessionId: this.args.sessionId,
      windowSec: Math.round(elapsed / 1000),
      frames,
      partialPct: frames ? Math.round((partials / frames) * 100) : 0,
      keyframes: fulls,
      fps: this.fps,
      quality: this.quality,
      avgKb: frames ? kb(this.statBytes / frames) : 0,
      avgPartialKb: partials ? kb(this.statPartialBytes / partials) : 0,
      avgFullKb: fulls ? kb((this.statBytes - this.statPartialBytes) / fulls) : 0,
      totalKb: kb(this.statBytes)
    });

    this.statsWindowStartMs = now;
    this.statFrames = 0;
    this.statPartials = 0;
    this.statBytes = 0;
    this.statPartialBytes = 0;
  }

  private reportCaptureFailure(code: string, message: string): void {
    const { ctx, sessionId } = this.args;

    if (code === NO_FRAME_CODE) {
      // Deliberately not counted and not reported — an idle desktop is the
      // single most common state a monitored machine is in.
      ctx.logger?.debug?.("[rcp.screen] no new frame (idle desktop)", {
        sessionId
      });
      return;
    }

    const terminal = TERMINAL_CAPTURE_CODES.has(code);
    this.consecutiveFailures += 1;

    ctx.logger?.warn?.("[rcp.screen] capture failed", {
      sessionId,
      code,
      terminal,
      consecutive: this.consecutiveFailures,
      error: message
    });

    if (terminal) {
      // Slow the loop down; a headless server would otherwise re-init the
      // whole DXGI chain several times a second for the life of the session.
      this.terminalBackoff = true;
    } else if (this.consecutiveFailures < TRANSIENT_ERROR_TOLERANCE) {
      return;
    }

    // Report once per distinct condition. Without this a persistent failure
    // would emit an `error` message on every capture tick.
    if (this.lastReportedCode === code) return;
    this.lastReportedCode = code;
    this.send({ op: "error", code, message, terminal });
  }

  // ── Teardown ───────────────────────────────────────────────────────────────

  private stopCapture(reason: string): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.captureTimer) {
      clearTimeout(this.captureTimer);
      this.captureTimer = null;
    }
    if (this.revokeTimer) {
      clearTimeout(this.revokeTimer);
      this.revokeTimer = null;
    }
    this.clearIndicator();
    this.hideLinuxIndicator();
    this.stopRecording();

    // ⚠️ Decirle al operador POR QUÉ se acabó, mientras el canal sigue vivo.
    //
    // Sin esto, el navegador solo ve caerse el WebSocket de señalización y
    // muestra "Connection error: Signaling WebSocket closed unexpectedly."
    // Para el caso que más importa —la persona pulsó "detener" en su banda—
    // ese mensaje es directamente engañoso: sugiere una avería de red donde
    // hubo una decisión, y empuja al operador a reintentar contra alguien que
    // acaba de decir que no.
    //
    // Va AQUÍ y no antes: la captura ya está parada arriba, así que no se
    // envía ni un fotograma de más, y al teardown le queda un tick de
    // setImmediate para que el mensaje salga por el canal.
    this.sendStopReason(reason);

    if (this.auditStartedSent) {
      this.args.sendScreenAudit({
        event: "stopped",
        width: this.lastWidth,
        height: this.lastHeight,
        fps: this.fps,
        errorMessage: ""
      });
    }
    setImmediate(() => this.args.onTeardown(reason));
  }

  dispose(reason: string): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.captureTimer) {
      clearTimeout(this.captureTimer);
      this.captureTimer = null;
    }
    // ⚠️ Estas dos líneas faltaban, y este es el camino de salida MÁS común:
    // el operador cierra la pestaña, se cae el peer y el plugin llama aquí,
    // no a stopCapture. Sin ellas la banda de "te están viendo la pantalla" se
    // quedaba encendida para siempre después de cada sesión —peor que no
    // tenerla, porque una alarma que no se apaga enseña a ignorarla— y el
    // sondeo de revocación seguía leyendo disco dos veces por segundo durante
    // toda la vida del proceso. Lo encontró un test, no el campo.
    if (this.revokeTimer) {
      clearTimeout(this.revokeTimer);
      this.revokeTimer = null;
    }
    this.clearIndicator();
    this.hideLinuxIndicator();
    this.stopRecording();
    if (this.auditStartedSent) {
      this.args.sendScreenAudit({
        event: "stopped",
        width: this.lastWidth,
        height: this.lastHeight,
        fps: this.fps,
        errorMessage: ""
      });
    }
    this.args.ctx.logger?.info?.("[rcp.screen] session disposed", {
      sessionId: this.args.sessionId,
      reason
    });
  }
}
