// test/plugins/rcp-screen-signin-flow.test.ts
//
// El recorrido ENTERO de entrar a un servidor por su pantalla de Windows,
// escrito antes del siguiente despliegue y no después.
//
// TNS-OPER-SNOC04 (29-sep-2026): cada despliegue destapaba el siguiente paso
// roto — primer fotograma, azul liso, «Take control», Ctrl+Alt+Supr, la
// directiva que lo bloquea. «No estamos viendo más allá de la corrección en
// turno.» Así que se recorrió el flujo completo y salieron tres pasos más que
// iban a fallar en campo:
//
//   · la contraseña: teclas físicas interpretadas con la distribución del
//     SERVIDOR (`@` desde un Mac español llegaba como Alt+2);
//   · la consola BLOQUEADA, muy común en servidores: se veía negro;
//   · al irse, la consola quedaba con una sesión de administrador abierta
//     — y el helper, SYSTEM sobre el escritorio seguro, no lo paraba nadie.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import {
  ScreenSession,
  __resetLiveScreenSessionsForTests
} from "../../src/plugins/rcp/screen-session";
import { redactInputEvent } from "../../src/plugins/rcp/recording-store";

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
  consentRequired?: boolean;
  server?: boolean;
} = {}) {
  const dc = new FakeDataChannel();
  const calls: any[] = [];
  const logged: any[] = [];
  const log = (...a: any[]) => { logged.push(a); };
  const ctx: any = {
    logger: { info: log, warn: log, error: log, debug: log },
    trayStatus: { setRemoteSession: () => {} },
    policyRuntime: {
      isFeatureEnabled: (f: string) =>
        (f === "remoteRequireConsent" && Boolean(opts.consentRequired)) ||
        (f === "remoteServerConsole" && Boolean(opts.server))
    },
    consentPrompter: { available: () => true, request: async () => "approved" },
    priv: {
      call: vi.fn(async (req: any) => {
        calls.push(req);
        if (req.method === "screen.capture") return (opts.capture ?? (() => frame()))();
        if (req.method === "screen.end") return { ok: true, result: { stopped: true, consoleLocked: true } };
        return { ok: true, result: { ok: true, injected: 2 } };
      })
    }
  };
  const session = new ScreenSession(dc as any, {
    sessionId: `sess-${Math.random().toString(36).slice(2, 8)}`, ctx,
    sendScreenAudit: () => {}, onTeardown: () => {}
  } as any);
  return { dc, calls, logged, session };
}

const realPlatform = process.platform;
function pretendPlatform(p: NodeJS.Platform) {
  Object.defineProperty(process, "platform", { value: p, configurable: true });
}
beforeEach(() => {
  __resetLiveScreenSessionsForTests();
});
afterEach(() => {
  Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
});

describe("consola BLOQUEADA de un servidor", () => {
  it("⭐ screenInfo lo dice, aparte de «sin nadie dentro»", async () => {
    const { dc, session } = makeSession({ capture: () => frame({ consoleLocked: true }) });
    await waitFor(() => dc.ofOp("screenInfo").length >= 1);
    expect(dc.ofOp("screenInfo")[0]).toMatchObject({ consoleLocked: true, noUserSignedIn: false });
    session.dispose("test");
  });

  it("al desbloquearla se vuelve a avisar al visor", async () => {
    let n = 0;
    const { dc, session } = makeSession({ capture: () => frame({ consoleLocked: n++ < 2 }) });
    await waitFor(() => dc.ofOp("screenInfo").length >= 2);
    const infos = dc.ofOp("screenInfo");
    expect(infos[0].consoleLocked).toBe(true);
    expect(infos[1].consoleLocked).toBe(false);
    session.dispose("test");
  });

  it("el eco de fps no lo pierde", async () => {
    const { dc, session } = makeSession({ capture: () => frame({ consoleLocked: true }) });
    await waitFor(() => dc.ofOp("screenInfo").length >= 1);
    dc.emit({ op: "setQuality", fps: 3 });
    await waitFor(() => dc.ofOp("screenInfo").length >= 2);
    expect(dc.ofOp("screenInfo").at(-1).consoleLocked).toBe(true);
    session.dispose("test");
  });
});

describe("Type text: la contraseña como caracteres", () => {
  it("⭐ en Windows va a input.inject como texto, no como teclas", async () => {
    pretendPlatform("win32");
    const { dc, calls, session } = makeSession();
    dc.emit({ op: "typeText", text: "admin@corp.local" });
    await waitFor(() => calls.some((c) => c.params?.op === "typeText"));
    const call = calls.find((c) => c.params?.op === "typeText");
    expect(call.method).toBe("input.inject");
    expect(call.params.text).toBe("admin@corp.local");
    session.dispose("test");
  });

  it("🔴 pasa por la puerta de control, como un clic", async () => {
    pretendPlatform("win32");
    const { dc, calls, session } = makeSession({ consentRequired: true });
    dc.emit({ op: "typeText", text: "hunter2" });
    await new Promise((r) => setTimeout(r, 100));
    expect(calls.some((c) => c.params?.op === "typeText")).toBe(false);
    session.dispose("test");
  });

  it("🔴 el texto NO aparece en ningún log", async () => {
    // Es casi siempre una credencial. Se fuerza el camino de error del IPC,
    // que es donde un «err: …» con el texto dentro se colaría.
    pretendPlatform("win32");
    const SECRET = "S3cr3t@Passw0rd!";
    const { dc, calls, logged, session } = makeSession();
    (session as any).args.ctx.priv.call = vi.fn(async (req: any) => {
      calls.push(req);
      if (req.method === "input.inject") throw new Error("pipe closed");
      return frame();
    });
    dc.emit({ op: "typeText", text: SECRET });
    await waitFor(() => calls.some((c) => c.params?.op === "typeText"));
    await new Promise((r) => setTimeout(r, 50));
    expect(JSON.stringify(logged)).not.toContain(SECRET);
    session.dispose("test");
  });

  it("🔴 la grabación guarda cuántos caracteres, nunca cuáles", () => {
    const rec = redactInputEvent("typeText", { text: "S3cr3t@" });
    expect(rec).toEqual({ op: "typeText", chars: 7 });
    expect(JSON.stringify(rec)).not.toContain("S3cr3t");
  });

  it("se anuncia sólo donde existe, y demasiado largo se rechaza aquí", async () => {
    pretendPlatform("win32");
    const w = makeSession();
    await waitFor(() => w.dc.ofOp("screenInfo").length >= 1);
    expect(w.dc.ofOp("screenInfo")[0].canTypeText).toBe(true);
    w.dc.emit({ op: "typeText", text: "x".repeat(1025) });
    await waitFor(() => w.dc.ofOp("error").length >= 1);
    expect(w.dc.ofOp("error")[0].code).toBe("type_text_too_long");
    expect(w.calls.some((c) => c.params?.op === "typeText")).toBe(false);
    w.session.dispose("test");

    pretendPlatform("darwin");
    const m = makeSession();
    await waitFor(() => m.dc.ofOp("screenInfo").length >= 1);
    expect(m.dc.ofOp("screenInfo")[0].canTypeText).toBe(false);
    m.session.dispose("test");
  });
});

describe("al terminar: parar el helper y bloquear la consola", () => {
  it("⭐ la última sesión que se cierra manda screen.end", async () => {
    pretendPlatform("win32");
    const { calls, session } = makeSession();
    await waitFor(() => calls.length >= 1);
    session.dispose("test");
    await waitFor(() => calls.some((c) => c.method === "screen.end"));
    expect(calls.some((c) => c.method === "screen.end")).toBe(true);
  });

  it("🔴 con otra sesión viva NO: le bloquearía la consola a quien sigue dentro", async () => {
    pretendPlatform("win32");
    const a = makeSession();
    const b = makeSession();
    a.session.dispose("test");
    await new Promise((r) => setTimeout(r, 50));
    expect(a.calls.some((c) => c.method === "screen.end")).toBe(false);

    b.session.dispose("test");
    await waitFor(() => b.calls.some((c) => c.method === "screen.end"));
    expect(b.calls.some((c) => c.method === "screen.end")).toBe(true);
  });

  it("una sola vez aunque se cierre por los dos caminos", async () => {
    pretendPlatform("win32");
    const { calls, session } = makeSession();
    (session as any).stopCapture("operator_stopped");
    session.dispose("test");
    await new Promise((r) => setTimeout(r, 50));
    expect(calls.filter((c) => c.method === "screen.end")).toHaveLength(1);
  });

  it("fuera de Windows no hay helper que parar", async () => {
    pretendPlatform("darwin");
    const { calls, session } = makeSession();
    session.dispose("test");
    await new Promise((r) => setTimeout(r, 50));
    expect(calls.some((c) => c.method === "screen.end")).toBe(false);
  });
});
