// test/plugins/rcp-hard-cap-ice-restart.test.ts
//
// ⚠️ El tope duro de la sesión no se renueva con la red.
//
// El límite de 4 h vive en un `setTimeout` del `PeerSession`, y un reinicio
// de ICE construye un `PeerSession` NUEVO: con el temporizador naciendo con
// él, cada reconstrucción regalaba otras cuatro horas. Un portátil que
// cambia de punto de acceso cada media hora podía no alcanzar el tope
// nunca, y el tope es lo único que cierra una sesión que el operador se
// dejó abierta.
//
// Un límite que se renueva solo, sin que nadie lo decida, no es un límite.
//
// Es el mismo razonamiento que el de `consentGranted`: lo que pertenece a
// la SESIÓN no puede vivir en el peer, porque el peer se reconstruye y la
// sesión no.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/** Los argumentos con los que se construyó cada peer, en orden. */
const built: any[] = [];
const disposed: string[] = [];

vi.mock("../../src/plugins/rcp/peer-session", () => ({
  PeerSession: class {
    constructor(args: any) {
      built.push(args);
    }
    acceptOffer = vi.fn(async () => {});
    addRemoteIce = () => {};
    dispose = async (reason: string) => {
      disposed.push(reason);
    };
  }
}));

import { SessionManager } from "../../src/plugins/rcp/session-manager";

const CAP_S = 100;

function offer(ufrag: string, over: Record<string, unknown> = {}) {
  return {
    sessionId: "sess-1",
    capability: "rcp.screen",
    operatorUserId: "op@example.com",
    sessionTimeoutSeconds: CAP_S,
    sdp: `v=0\r\na=ice-ufrag:${ufrag}\r\na=ice-pwd:whatever\r\n`,
    ...over
  };
}

function makeManager() {
  built.length = 0;
  disposed.length = 0;
  const sent: any[] = [];
  const ctx: any = {
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    sendControl: (m: any) => sent.push(m),
    // Sin consentimiento: aquí se mide el reloj, no la puerta.
    policyRuntime: { isFeatureEnabled: (f: string) => f === "remoteScreen" }
  };
  return { mgr: new SessionManager(ctx), sent };
}

/** El motivo del último `remoteSessionClose` enviado, si lo hubo. */
const lastClose = (sent: any[]) =>
  sent.filter((m) => m.remoteSessionClose).pop()?.remoteSessionClose?.reason ?? null;

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-09-05T00:00:00Z"));
});
afterEach(() => vi.useRealTimers());

describe("⚠️ el tope duro sobrevive al reinicio de ICE", () => {
  it("el peer reconstruido recibe lo que QUEDA, no el plazo entero", async () => {
    const { mgr } = makeManager();
    await mgr.onOffer(offer("aaaa"));
    expect(built[0].sessionTimeoutSeconds).toBe(CAP_S);

    // Cuarenta segundos de sesión y se rompe la red: mismo id, ufrag nuevo.
    vi.setSystemTime(new Date("2026-09-05T00:00:40Z"));
    await mgr.onOffer(offer("bbbb"));

    expect(disposed).toContain("ice_restart_rebuild");
    expect(built).toHaveLength(2);
    expect(built[1].sessionTimeoutSeconds).toBe(60);
  });

  it("y varios reinicios seguidos siguen restando", async () => {
    // Un portátil que salta de punto de acceso lo hace más de una vez. Si el
    // descuento se calculara contra el peer anterior en vez de contra el
    // inicio de la sesión, cada salto devolvería casi todo el plazo.
    const { mgr } = makeManager();
    await mgr.onOffer(offer("aaaa"));
    vi.setSystemTime(new Date("2026-09-05T00:00:30Z"));
    await mgr.onOffer(offer("bbbb"));
    vi.setSystemTime(new Date("2026-09-05T00:01:00Z"));
    await mgr.onOffer(offer("cccc"));

    expect(built[2].sessionTimeoutSeconds).toBe(40);
  });

  it("⚠️ si el tope venció durante el corte, la sesión NO se reconstruye", async () => {
    // Devolver aquí una sesión viva sería resucitar una que ya debía haber
    // terminado, y encima sin que nadie lo pidiera.
    const { mgr, sent } = makeManager();
    await mgr.onOffer(offer("aaaa"));

    vi.setSystemTime(new Date("2026-09-05T00:02:00Z")); // 120 s > 100 s
    await mgr.onOffer(offer("bbbb"));

    expect(built).toHaveLength(1);
    expect(lastClose(sent)).toBe("hard_cap_timeout");
  });

  it("una sesión distinta empieza con el plazo entero", async () => {
    // El reloj es de la sesión, no del equipo ni del proceso.
    const { mgr } = makeManager();
    await mgr.onOffer(offer("aaaa"));
    vi.setSystemTime(new Date("2026-09-05T00:00:50Z"));
    await mgr.onOffer(offer("dddd", { sessionId: "sess-2" }));

    expect(built[1].sessionTimeoutSeconds).toBe(CAP_S);
  });

  it("cerrar la sesión olvida su reloj", async () => {
    // Si sobreviviera al cierre, reutilizar el id entraría con el plazo ya
    // consumido — o, peor, con uno vencido, y no abriría nunca.
    const { mgr } = makeManager();
    await mgr.onOffer(offer("aaaa"));
    vi.setSystemTime(new Date("2026-09-05T00:00:50Z"));
    await mgr.onClose({ sessionId: "sess-1", reason: "user_closed" });

    await mgr.onOffer(offer("eeee"));
    expect(built[1].sessionTimeoutSeconds).toBe(CAP_S);
  });

  it("el tope por defecto sigue siendo de cuatro horas", async () => {
    // Sin `sessionTimeoutSeconds` en la oferta —backend antiguo— el valor no
    // puede quedarse a cero: sería cerrar toda sesión al abrirla.
    const { mgr } = makeManager();
    await mgr.onOffer(offer("aaaa", { sessionTimeoutSeconds: undefined }));
    expect(built[0].sessionTimeoutSeconds).toBe(4 * 60 * 60);
  });
});
