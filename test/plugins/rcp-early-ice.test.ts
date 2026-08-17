// test/plugins/rcp-early-ice.test.ts
//
// El navegador empieza a trickle-ar candidatos en cuanto llama a
// setLocalDescription, así que sus primeros candidatos adelantan a la oferta
// por el bus de señalización con regularidad. Capturado en producción el
// 2026-08-17 (W11-JPR-Lab01):
//
//   14:03:30.0030  ICE (host) -> agente     <- la sesión aún no existe
//   14:03:30.1096  offer      -> agente
//
// Antes se descartaban en silencio, así que conectar o no dependía de qué
// mensaje ganaba la carrera: el MISMO equipo, red y servidores ICE conectaba
// en un intento y daba `ice_failed` en el siguiente. Además de romper
// sesiones, ese no-determinismo envenenaba cualquier medición.

import { describe, it, expect, vi } from "vitest";

const added: any[] = [];
const acceptOffer = vi.fn(async () => {});
vi.mock("../../src/plugins/rcp/peer-session", () => ({
  PeerSession: class {
    acceptOffer = acceptOffer;
    addRemoteIce = (ice: any) => { added.push(ice); };
    dispose = async () => {};
  }
}));

import { SessionManager } from "../../src/plugins/rcp/session-manager";

function makeManager() {
  added.length = 0;
  acceptOffer.mockClear();
  const logs: any[] = [];
  const sent: any[] = [];
  const ctx: any = {
    logger: {
      info: (m: string, d: any) => logs.push([m, d]),
      warn: (m: string, d: any) => logs.push([m, d]),
      error: () => {}, debug: () => {}
    },
    policyRuntime: { isFeatureEnabled: (f: string) => f === "remoteShell" },
    sendControl: (m: any) => sent.push(m)
  };
  return { mgr: new SessionManager(ctx), logs, sent };
}

const offer = (sessionId: string) => ({
  sessionId, sdp: "v=0\r\n", capability: "rcp.shell", sessionTimeoutSeconds: 60
});
const ice = (sessionId: string, candidate: string) => ({
  sessionId, candidate, sdpMid: "0", sdpMLineIndex: 0
});

describe("early ICE — candidatos que adelantan a su oferta", () => {
  it("entrega los candidatos que llegaron ANTES de la oferta", async () => {
    const { mgr } = makeManager();
    // El orden exacto observado en producción.
    mgr.onIce(ice("s1", "candidate:1 typ host"));
    mgr.onIce(ice("s1", "candidate:2 typ srflx"));
    await mgr.onOffer(offer("s1"));

    expect(added.map((i) => i.candidate)).toEqual([
      "candidate:1 typ host",
      "candidate:2 typ srflx"
    ]);
  });

  it("los entrega DESPUÉS de acceptOffer, no antes", async () => {
    // libdatachannel exige la descripción remota puesta antes de aceptar
    // candidatos; drenar antes los tiraría igual, con el buffer tapando el bug.
    const { mgr } = makeManager();
    const order: string[] = [];
    acceptOffer.mockImplementation(async () => { order.push("acceptOffer"); });
    mgr.onIce(ice("s1", "candidate:1 typ host"));
    const before = added.length;
    await mgr.onOffer(offer("s1"));
    expect(before).toBe(0);
    expect(order).toEqual(["acceptOffer"]);
    expect(added).toHaveLength(1);
  });

  it("sigue entregando en directo los que llegan tras la oferta", async () => {
    const { mgr } = makeManager();
    await mgr.onOffer(offer("s1"));
    mgr.onIce(ice("s1", "candidate:live typ relay"));
    expect(added.map((i) => i.candidate)).toEqual(["candidate:live typ relay"]);
  });

  it("no mezcla buffers entre sesiones", async () => {
    const { mgr } = makeManager();
    mgr.onIce(ice("s1", "para-s1"));
    mgr.onIce(ice("s2", "para-s2"));
    await mgr.onOffer(offer("s1"));
    expect(added.map((i) => i.candidate)).toEqual(["para-s1"]);
  });

  it("preserva sdpMid y sdpMLineIndex", async () => {
    const { mgr } = makeManager();
    mgr.onIce({ sessionId: "s1", candidate: "c", sdpMid: "data", sdpMLineIndex: 3 });
    await mgr.onOffer(offer("s1"));
    expect(added[0]).toEqual({ candidate: "c", sdpMid: "data", sdpMLineIndex: 3 });
  });
});

describe("early ICE — el buffer está acotado", () => {
  it("limita los candidatos por sesión", async () => {
    // Lo alimenta la red directamente: sin tope sería una primitiva de
    // crecimiento de memoria para cualquiera que alcance la señalización.
    const { mgr, logs } = makeManager();
    for (let i = 0; i < 50; i++) mgr.onIce(ice("s1", `c${i}`));
    await mgr.onOffer(offer("s1"));
    expect(added.length).toBeLessThanOrEqual(32);
    expect(logs.some(([m]) => /early-ice cap reached/.test(m))).toBe(true);
  });

  it("limita el número de sesiones en buffer", () => {
    const { mgr, logs } = makeManager();
    for (let i = 0; i < 40; i++) mgr.onIce(ice(`sess-${i}`, "c"));
    expect(logs.some(([m]) => /early-ice buffer full/.test(m))).toBe(true);
  });

  it("caduca los buffers cuya oferta nunca llegó", async () => {
    const { mgr } = makeManager();
    mgr.onIce(ice("huerfana", "c"));
    // Pasado el TTL, una llegada nueva barre lo viejo. Con fake timers
    // explícitos para no depender de que setSystemTime funcione sin ellos.
    vi.useFakeTimers();
    vi.setSystemTime(new Date(Date.now() + 61_000));
    mgr.onIce(ice("otra", "c"));
    vi.useRealTimers();
    await mgr.onOffer(offer("huerfana"));
    expect(added).toHaveLength(0);
  });

  it("ignora un sessionId vacío", () => {
    const { mgr } = makeManager();
    expect(() => mgr.onIce({ candidate: "c" })).not.toThrow();
  });
});

// ── Ofertas duplicadas ────────────────────────────────────────────────
//
// Una segunda oferta para una sesión viva son dos cosas MUY distintas, y
// antes se ignoraban las dos: el navegador se quedaba esperando una
// respuesta que nunca llegaba hasta agotar reintentos ("WebRTC connection
// lost — retries exhausted").
//
// Verificado contra node-datachannel antes de escribir esto:
//   - misma oferta reenviada        -> la acepta y emite respuesta nueva
//   - oferta con ice-ufrag distinto -> "Invalid ICE settings from remote SDP"
// Por eso el retransmit se re-responde y el ICE restart se cierra con un
// motivo explícito en vez de intentar una renegociación que la librería
// no soporta.
describe("ofertas duplicadas", () => {
  const withUfrag = (sessionId: string, ufrag: string) => ({
    sessionId,
    sdp: `v=0\r\na=ice-ufrag:${ufrag}\r\na=ice-pwd:xxxx\r\n`,
    capability: "rcp.shell",
    sessionTimeoutSeconds: 60
  });

  it("re-responde a una retransmisión (mismo ice-ufrag)", async () => {
    const { mgr } = makeManager();
    await mgr.onOffer(withUfrag("s1", "AAAA"));
    expect(acceptOffer).toHaveBeenCalledTimes(1);
    await mgr.onOffer(withUfrag("s1", "AAAA"));
    // Segunda aplicación => libdatachannel emite una respuesta nueva.
    expect(acceptOffer).toHaveBeenCalledTimes(2);
  });

  it("cierra con motivo explícito ante un ICE restart (ufrag distinto)", async () => {
    const { mgr, sent } = makeManager();
    await mgr.onOffer(withUfrag("s1", "AAAA"));
    await mgr.onOffer(withUfrag("s1", "BBBB"));
    // No se intenta renegociar: la librería lo rechazaría.
    expect(acceptOffer).toHaveBeenCalledTimes(1);
    const close = sent.find((m: any) => m.remoteSessionClose);
    expect(close?.remoteSessionClose?.reason).toBe("ice_restart_unsupported");
  });

  it("tras el cierre por ICE restart, la sesión deja de estar viva", async () => {
    const { mgr } = makeManager();
    await mgr.onOffer(withUfrag("s1", "AAAA"));
    await mgr.onOffer(withUfrag("s1", "BBBB"));
    // Una oferta posterior se trata como sesión nueva, no como duplicada.
    await mgr.onOffer(withUfrag("s1", "CCCC"));
    expect(acceptOffer).toHaveBeenCalledTimes(2);
  });
});
