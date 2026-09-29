// test/plugins/rcp-screen-logon-sas.test.ts
//
// TNS-OPER-SNOC04 (T1, 29-sep-2026), segunda ronda con 1.1.86. El operador
// abrió screen share contra el servidor sin nadie dentro, vio «Waiting for
// first frame…» y lo dio por roto — hasta que pulsó «Take control» y apareció
// «Presiona Ctrl+Alt+Supr para desbloquear». Y ahí se quedó: desde un Mac esa
// combinación no existe.
//
// Dos cosas de este fichero:
//
//   1. El agente le dice al visor que NO HAY NADIE DENTRO. Con eso el visor
//      arranca en control solo. Decisión del usuario: «tu acceso sin un
//      usuario logueado ya implica tomar el control de teclado y mouse».
//   2. Ctrl+Alt+Supr por su propio método de PrivSvc (SendInput no puede
//      sintetizarlo), y por la MISMA puerta de control que un clic.

import { describe, it, expect, vi, afterEach } from "vitest";
import { ScreenSession } from "../../src/plugins/rcp/screen-session";

class FakeDataChannel {
  private msgCb: ((raw: any) => void) | null = null;
  sent: string[] = [];
  onMessage(cb: (raw: any) => void) { this.msgCb = cb; }
  onClosed(_cb: () => void) {}
  sendMessage(text: string) { this.sent.push(text); }
  emit(obj: any) { this.msgCb?.(JSON.stringify(obj)); }
  ofOp(op: string): any[] { return this.sent.map((s) => JSON.parse(s)).filter((m) => m.op === op); }
}

async function waitFor(cond: () => boolean, timeoutMs = 3000) {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) return;
    await new Promise((r) => setTimeout(r, 10));
  }
}

const frame = (extra: Record<string, unknown> = {}) => ({
  ok: true,
  result: { data: "QUJD", width: 1024, height: 768, full: true, rw: 1024, rh: 768, ...extra }
});

function makeSession(opts: {
  capture?: () => any;
  sas?: () => any;
  consentRequired?: boolean;
  decision?: "approved" | "denied" | "timeout";
} = {}) {
  const dc = new FakeDataChannel();
  const calls: any[] = [];
  const asked: any[] = [];
  const ctx: any = {
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    trayStatus: { setRemoteSession: () => {} },
    policyRuntime: {
      isFeatureEnabled: (f: string) => f === "remoteRequireConsent" && Boolean(opts.consentRequired)
    },
    consentPrompter: {
      available: () => true,
      request: async (r: any) => { asked.push(r); return opts.decision ?? "approved"; }
    },
    priv: {
      call: vi.fn(async (req: any) => {
        calls.push(req);
        if (req.method === "input.sas") return (opts.sas ?? (() => ({ ok: true, result: { sent: true } })))();
        if (req.method === "screen.capture") return (opts.capture ?? (() => frame()))();
        return { ok: true, result: {} };
      })
    }
  };
  const session = new ScreenSession(dc as any, {
    sessionId: "sess-snoc04", ctx, operator: "Javier Pacheco",
    sendScreenAudit: () => {}, onTeardown: () => {}
  } as any);
  return { dc, calls, asked, session };
}

const realPlatform = process.platform;
function pretendPlatform(p: NodeJS.Platform) {
  Object.defineProperty(process, "platform", { value: p, configurable: true });
}
afterEach(() => {
  Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
});

describe("el visor sabe que no hay nadie dentro", () => {
  it("⭐ screenInfo lleva noUserSignedIn cuando PrivSvc lo dice", async () => {
    const { dc, session } = makeSession({ capture: () => frame({ noUserSignedIn: true }) });
    await waitFor(() => dc.ofOp("screenInfo").length >= 1);
    expect(dc.ofOp("screenInfo")[0]).toMatchObject({ width: 1024, height: 768, noUserSignedIn: true });
    session.dispose("test");
  });

  it("ausente es false — lo seguro: con alguien delante NO se toma el control solo", async () => {
    const { dc, session } = makeSession();
    await waitFor(() => dc.ofOp("screenInfo").length >= 1);
    expect(dc.ofOp("screenInfo")[0].noUserSignedIn).toBe(false);
    session.dispose("test");
  });

  it("vuelve a mandar screenInfo cuando alguien inicia sesión, aunque no cambie el tamaño", async () => {
    // Sin esto el visor seguiría creyendo que está ante la pantalla de login
    // después de que el operador entrara con las credenciales del servidor.
    let n = 0;
    const { dc, session } = makeSession({
      capture: () => frame({ noUserSignedIn: n++ < 2 })
    });
    await waitFor(() => dc.ofOp("screenInfo").length >= 2);
    const infos = dc.ofOp("screenInfo");
    expect(infos[0].noUserSignedIn).toBe(true);
    expect(infos[1].noUserSignedIn).toBe(false);
    session.dispose("test");
  });

  it("el eco de fps no lo pierde", async () => {
    const { dc, session } = makeSession({ capture: () => frame({ noUserSignedIn: true }) });
    await waitFor(() => dc.ofOp("screenInfo").length >= 1);
    dc.emit({ op: "setQuality", fps: 3 });
    await waitFor(() => dc.ofOp("screenInfo").length >= 2);
    const echo = dc.ofOp("screenInfo").at(-1);
    expect(echo.fps).toBe(3);
    expect(echo.noUserSignedIn, "undefined se leería como «ya hay alguien»").toBe(true);
    session.dispose("test");
  });
});

describe("Ctrl+Alt+Supr", () => {
  it("⭐ en Windows va por input.sas, no por input.inject", async () => {
    pretendPlatform("win32");
    const { dc, calls, session } = makeSession();
    dc.emit({ op: "sas" });
    await waitFor(() => calls.some((c) => c.method === "input.sas"));
    expect(calls.some((c) => c.method === "input.sas")).toBe(true);
    expect(
      calls.some((c) => c.method === "input.inject"),
      "SendInput no puede sintetizar la SAS: por ahí no haría nada",
    ).toBe(false);
    session.dispose("test");
  });

  it("🔴 pasa por la puerta de control: con consentimiento exigido, primero se pregunta", async () => {
    pretendPlatform("win32");
    const { dc, calls, asked, session } = makeSession({ consentRequired: true, decision: "approved" });
    dc.emit({ op: "sas" });
    await waitFor(() => asked.length >= 1);
    expect(asked[0].capability).toBe("rcp.screen.control");
    expect(
      calls.some((c) => c.method === "input.sas"),
      "el botón no puede ser un atajo para actuar sin control concedido",
    ).toBe(false);
    session.dispose("test");
  });

  it("⭐ si Windows no lo permite, el operador lee QUÉ directiva falta", async () => {
    pretendPlatform("win32");
    const why =
      "Windows on this device does not let services send Ctrl+Alt+Del "
      + "(SoftwareSASGeneration is not configured). Enable the policy …";
    const { dc, session } = makeSession({
      sas: () => ({ ok: false, error: { code: "sas_not_allowed", message: why } })
    });
    dc.emit({ op: "sas" });
    await waitFor(() => dc.ofOp("error").some((e) => e.code === "sas_not_allowed"));
    const err = dc.ofOp("error").find((e) => e.code === "sas_not_allowed");
    expect(err.message, "se reenvía tal cual, no se resume en «no se pudo»").toBe(why);
    expect(err.terminal).toBe(false);
    session.dispose("test");
  });

  it("screenInfo anuncia si el botón tiene sentido en este equipo", async () => {
    pretendPlatform("win32");
    const w = makeSession();
    await waitFor(() => w.dc.ofOp("screenInfo").length >= 1);
    expect(w.dc.ofOp("screenInfo")[0].canSendSas).toBe(true);
    w.session.dispose("test");

    pretendPlatform("darwin");
    const m = makeSession();
    await waitFor(() => m.dc.ofOp("screenInfo").length >= 1);
    expect(m.dc.ofOp("screenInfo")[0].canSendSas).toBe(false);
    m.session.dispose("test");
  });

  it("fuera de Windows lo dice y no llama a PrivSvc", async () => {
    pretendPlatform("darwin");
    const { dc, calls, session } = makeSession();
    dc.emit({ op: "sas" });
    await waitFor(() => dc.ofOp("error").length >= 1);
    expect(dc.ofOp("error")[0].code).toBe("sas_unsupported");
    expect(calls.some((c) => c.method === "input.sas")).toBe(false);
    session.dispose("test");
  });
});
