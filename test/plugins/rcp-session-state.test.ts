// test/plugins/rcp-session-state.test.ts
//
// Sprint 2 (aditivo) — RCP: máquina de estados de la sesión remota y el
// protocolo de señalización (Answer / Ice / Close / Error) que el
// SessionManager empuja por `ctx.sendControl`.
//
// Alcance de esta suite (el SessionManager es el dueño del ciclo de vida;
// PeerSession sólo envuelve el handshake WebRTC nativo):
//   connecting → offer válido ⇒ construye PeerSession + acceptOffer(sdp)
//   running    → callbacks del peer:
//                  sendAnswer  ⇒ remoteSessionAnswer
//                  sendIce     ⇒ remoteSessionIce
//                ICE remota entrante ⇒ peer.addRemoteIce
//   error      → offer inválido / capability desconocida / policy off /
//                acceptOffer rechaza ⇒ remoteSessionError, sin sesión viva
//   ended      → onTeardown(reason) ⇒ remoteSessionClose;
//                onClose / onError del backend ⇒ peer.dispose
//
// ── Frontera de mock ────────────────────────────────────────────────────
// PeerSession (src/plugins/rcp/peer-session.ts) hace `require("node-
// datachannel")` a nivel de módulo: es un addon nativo que Vitest NO puede
// interceptar (queda externalizado) y cuya construcción real crashea el
// runtime en hosts sin prebuild. Por eso NO se testea PeerSession por
// dentro aquí; se mockea el MÓDULO `./peer-session` en su frontera natural
// (import relativo de src, misma estrategia que test/transport/
// grpc-stream.test.ts usa para sus dependencias). El fake captura los args
// (incluidos los callbacks sendAnswer/sendIce/onTeardown) para que el test
// dispare las transiciones a mano, y registra cada instancia + las llamadas
// a acceptOffer/addRemoteIce/dispose.
//
// No se toca ninguna suite existente. No se carga node-datachannel real.

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Fake PeerSession (frontera src, no nativo) ──────────────────────────
const H = vi.hoisted(() => {
  const instances: any[] = [];
  class FakePeerSession {
    args: any;
    accepted: string[] = [];
    ices: any[] = [];
    disposed: string | null = null;
    acceptShouldThrow: string | null = null;
    constructor(args: any) {
      this.args = args;
      instances.push(this);
    }
    async acceptOffer(sdp: string) {
      if (this.acceptShouldThrow) throw new Error(this.acceptShouldThrow);
      this.accepted.push(sdp);
    }
    addRemoteIce(ice: any) {
      this.ices.push(ice);
    }
    async dispose(reason: string) {
      this.disposed = reason;
    }
  }
  return { instances, FakePeerSession };
});

vi.mock("../../src/plugins/rcp/peer-session", () => ({
  PeerSession: H.FakePeerSession
}));

import { SessionManager } from "../../src/plugins/rcp/session-manager";

const peers = H.instances;

// ── Contexto de agente mínimo ──────────────────────────────────────────
function makeCtx(featureEnabled = true) {
  const sent: any[] = [];
  const ctx: any = {
    policyRuntime: { isFeatureEnabled: () => featureEnabled },
    sendControl: (m: any) => sent.push(m),
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} }
  };
  return { ctx, sent };
}

function lastPeer(): any {
  return peers[peers.length - 1];
}

function findMsg(sent: any[], key: string): any | undefined {
  const m = sent.find((x) => key in x);
  return m ? m[key] : undefined;
}

const OFFER = {
  sessionId: "sess-abc-12345678",
  sdp: "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\n",
  capability: "rcp.shell",
  sessionTimeoutSeconds: 3600
};

beforeEach(() => {
  peers.length = 0;
  vi.clearAllMocks();
});

describe("RCP máquina de estados — connecting / running", () => {
  it("connecting: offer válido construye PeerSession con args correctos y llama acceptOffer(sdp)", async () => {
    const { ctx } = makeCtx();
    const mgr = new SessionManager(ctx);

    await mgr.onOffer({ ...OFFER });

    expect(peers.length).toBe(1);
    const p = lastPeer();
    expect(p.args.sessionId).toBe(OFFER.sessionId);
    expect(p.args.capability).toBe("rcp.shell");
    expect(p.args.sessionTimeoutSeconds).toBe(3600);
    expect(p.accepted).toEqual([OFFER.sdp]);
  });

  it("connecting: parsea iceServersJson y lo pasa al PeerSession", async () => {
    const { ctx } = makeCtx();
    const mgr = new SessionManager(ctx);
    const iceServers = [{ urls: ["turn:host:3478"], username: "u", credential: "c" }];

    await mgr.onOffer({ ...OFFER, iceServersJson: JSON.stringify(iceServers) });

    expect(lastPeer().args.iceServers).toEqual(iceServers);
  });

  it("connecting: iceServersJson malformado cae a [] sin romper", async () => {
    const { ctx } = makeCtx();
    const mgr = new SessionManager(ctx);

    await mgr.onOffer({ ...OFFER, iceServersJson: "{not-json" });

    expect(peers.length).toBe(1);
    expect(lastPeer().args.iceServers).toEqual([]);
  });

  it("running: el callback sendAnswer del peer ⇒ remoteSessionAnswer(sessionId, sdp)", async () => {
    const { ctx, sent } = makeCtx();
    const mgr = new SessionManager(ctx);
    await mgr.onOffer({ ...OFFER });

    lastPeer().args.sendAnswer("answer-sdp-body");

    const answer = findMsg(sent, "remoteSessionAnswer");
    expect(answer).toBeDefined();
    expect(answer.sessionId).toBe(OFFER.sessionId);
    expect(answer.sdp).toBe("answer-sdp-body");
  });

  it("running: el callback sendIce del peer ⇒ remoteSessionIce con mLineIndex", async () => {
    const { ctx, sent } = makeCtx();
    const mgr = new SessionManager(ctx);
    await mgr.onOffer({ ...OFFER });

    lastPeer().args.sendIce("candidate:1 udp ...", "0", 0);

    const ice = findMsg(sent, "remoteSessionIce");
    expect(ice).toBeDefined();
    expect(ice.sessionId).toBe(OFFER.sessionId);
    expect(ice.candidate).toBe("candidate:1 udp ...");
    expect(ice.sdpMid).toBe("0");
    expect(ice.sdpMLineIndex).toBe(0);
  });

  it("running: ICE remota entrante se reenvía al peer correcto (addRemoteIce)", async () => {
    const { ctx } = makeCtx();
    const mgr = new SessionManager(ctx);
    await mgr.onOffer({ ...OFFER });

    mgr.onIce({
      sessionId: OFFER.sessionId,
      candidate: "candidate:remote 1",
      sdpMid: "0",
      sdpMLineIndex: 0
    });

    expect(lastPeer().ices).toEqual([
      { candidate: "candidate:remote 1", sdpMid: "0", sdpMLineIndex: 0 }
    ]);
  });

  it("ICE para sesión desconocida es no-op (no revienta, no construye peers)", async () => {
    const { ctx } = makeCtx();
    const mgr = new SessionManager(ctx);

    expect(() =>
      mgr.onIce({ sessionId: "nope", candidate: "x", sdpMid: "0" })
    ).not.toThrow();
    expect(peers.length).toBe(0);
  });
});

describe("RCP máquina de estados — error", () => {
  it("offer sin sessionId/sdp/capability se descarta sin peer ni señalización", async () => {
    const { ctx, sent } = makeCtx();
    const mgr = new SessionManager(ctx);

    await mgr.onOffer({ sessionId: "", sdp: "", capability: "" });

    expect(peers.length).toBe(0);
    expect(sent.length).toBe(0);
  });

  it("capability desconocida ⇒ remoteSessionError CAPABILITY_UNKNOWN, sin peer", async () => {
    const { ctx, sent } = makeCtx();
    const mgr = new SessionManager(ctx);

    await mgr.onOffer({ ...OFFER, capability: "rcp.bogus" });

    const err = findMsg(sent, "remoteSessionError");
    expect(err).toBeDefined();
    expect(err.code).toBe("CAPABILITY_UNKNOWN");
    expect(peers.length).toBe(0);
  });

  it("policy deshabilitada ⇒ remoteSessionError POLICY_DISABLED, sin peer", async () => {
    const { ctx, sent } = makeCtx(false); // feature off
    const mgr = new SessionManager(ctx);

    await mgr.onOffer({ ...OFFER });

    const err = findMsg(sent, "remoteSessionError");
    expect(err).toBeDefined();
    expect(err.code).toBe("POLICY_DISABLED");
    expect(peers.length).toBe(0);
  });

  it("acceptOffer rechaza ⇒ SDP_PARSE_ERROR y la sesión se elimina del mapa", async () => {
    const { ctx, sent } = makeCtx();
    const mgr = new SessionManager(ctx);

    // Hacemos que el PRÓXIMO PeerSession falle en acceptOffer. El ctor del
    // fake registra la instancia antes de acceptOffer, así que armamos el
    // fallo interceptando la construcción vía prototype.
    const origAccept = H.FakePeerSession.prototype.acceptOffer;
    H.FakePeerSession.prototype.acceptOffer = async function () {
      throw new Error("bad sdp");
    };
    try {
      await mgr.onOffer({ ...OFFER });
    } finally {
      H.FakePeerSession.prototype.acceptOffer = origAccept;
    }

    const err = findMsg(sent, "remoteSessionError");
    expect(err).toBeDefined();
    expect(err.code).toBe("SDP_PARSE_ERROR");
    // La sesión NO debe quedar registrada: un ICE posterior no llega al peer.
    const before = lastPeer().ices.length;
    mgr.onIce({ sessionId: OFFER.sessionId, candidate: "x", sdpMid: "0" });
    expect(lastPeer().ices.length).toBe(before);
  });

  it("rechaza el offer al alcanzar el tope local de peers ⇒ AGENT_AT_CAPACITY", async () => {
    const { ctx, sent } = makeCtx();
    const mgr = new SessionManager(ctx);

    // MAX_CONCURRENT_LOCAL_PEERS = 8 → el 9º se rechaza.
    for (let i = 0; i < 8; i++) {
      await mgr.onOffer({ ...OFFER, sessionId: `sess-${i}-abcdefgh` });
    }
    const peersBefore = peers.length;
    await mgr.onOffer({ ...OFFER, sessionId: "sess-overflow-xxxx" });

    expect(peers.length).toBe(peersBefore); // no construyó otro
    const err = findMsg(sent, "remoteSessionError");
    expect(err.code).toBe("AGENT_AT_CAPACITY");
  });

  it("offer duplicado para la misma sesión se ignora (no construye segundo peer)", async () => {
    const { ctx } = makeCtx();
    const mgr = new SessionManager(ctx);

    await mgr.onOffer({ ...OFFER });
    await mgr.onOffer({ ...OFFER });

    expect(peers.length).toBe(1);
  });
});

describe("RCP máquina de estados — ended (teardown)", () => {
  it("ended: onTeardown(reason) del peer ⇒ remoteSessionClose con ese reason", async () => {
    const { ctx, sent } = makeCtx();
    const mgr = new SessionManager(ctx);
    await mgr.onOffer({ ...OFFER });

    // El PeerSession real invoca onTeardown en ice_failed / peer_closed /
    // shell exit / hard_cap_timeout. Simulamos la señal.
    lastPeer().args.onTeardown("ice_failed");

    const close = findMsg(sent, "remoteSessionClose");
    expect(close).toBeDefined();
    expect(close.sessionId).toBe(OFFER.sessionId);
    expect(close.reason).toBe("ice_failed");
  });

  it("ended: tras onTeardown la sesión sale del mapa (ICE posterior no llega)", async () => {
    const { ctx } = makeCtx();
    const mgr = new SessionManager(ctx);
    await mgr.onOffer({ ...OFFER });
    const p = lastPeer();

    p.args.onTeardown("peer_closed");
    const before = p.ices.length;
    mgr.onIce({ sessionId: OFFER.sessionId, candidate: "x", sdpMid: "0" });

    expect(p.ices.length).toBe(before);
  });

  it("ended: onClose del backend ⇒ peer.dispose(reason) y saca del mapa", async () => {
    const { ctx } = makeCtx();
    const mgr = new SessionManager(ctx);
    await mgr.onOffer({ ...OFFER });
    const p = lastPeer();

    await mgr.onClose({ sessionId: OFFER.sessionId, reason: "operator_closed" });

    expect(p.disposed).toBe("operator_closed");
    // ya no está registrada
    mgr.onIce({ sessionId: OFFER.sessionId, candidate: "x", sdpMid: "0" });
    expect(p.ices.length).toBe(0);
  });

  it("ended: onError del backend ⇒ peer.dispose('remote_error:<code>')", async () => {
    const { ctx } = makeCtx();
    const mgr = new SessionManager(ctx);
    await mgr.onOffer({ ...OFFER });
    const p = lastPeer();

    await mgr.onError({ sessionId: OFFER.sessionId, code: "SIGNALING_LOST" });

    expect(p.disposed).toBe("remote_error:SIGNALING_LOST");
  });

  it("onClose de una sesión inexistente es no-op idempotente", async () => {
    const { ctx } = makeCtx();
    const mgr = new SessionManager(ctx);
    await expect(
      mgr.onClose({ sessionId: "ghost", reason: "x" })
    ).resolves.toBeUndefined();
  });
});
