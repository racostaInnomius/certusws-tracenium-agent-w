// test/plugins/rcp-screen-indicator-ipc.test.ts
//
// ⚠️ El sobre de la llamada al PrivSvc, no sólo su contenido.
//
// En Linux la sesión de pantalla no arranca hasta que el PrivSvc confirma que
// el aviso «te están viendo» está en pantalla (ADR-0012), y si no puede, se
// niega. Esa puerta es correcta. Lo que estaba mal era la llamada: salía SIN
// el campo `v`, y lo primero que hace el router del PrivSvc —antes de mirar el
// método— es `if (req.v !== 1) return fail(…, "bad_version")`.
//
// Resultado: desde el 2026-08-30 (commit `05f64b2`, el que añadió la puerta)
// **ningún equipo Linux podía compartir pantalla**. Falla cerrado, así que no
// se veía como un error sino como una negativa razonable. Se descubrió el
// 23-sep cuando alguien lo intentó por primera vez en T118:
//
//     screen_error  indicator_unavailable:bad_version
//     closed        indicator_unavailable              (1 s)
//
// Por qué no lo cazó el compilador: `PrivSvcRequest` declara `v: 1` como
// obligatorio, pero `IPrivSvcClient.call(req: any)` lo borra. Y por qué no lo
// cazó el banco de pruebas: el doble de `priv.call` contestaba `ok: true` a
// cualquier cosa, con lo que aprobaba peticiones que el PrivSvc real rechaza.
//
// De ahí la forma de estos tests: el doble aplica **la misma primera regla que
// el router real** (`privsvc/linux/src/router.ts`, `routeRequest`). Un doble
// más amable que el original no prueba nada.

import { describe, it, expect, vi, afterEach } from "vitest";
import { ScreenSession } from "../../src/plugins/rcp/screen-session";

let prevPlatform: PropertyDescriptor | undefined;
function pretendLinux() {
  prevPlatform = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value: "linux" });
}
afterEach(() => {
  if (prevPlatform) Object.defineProperty(process, "platform", prevPlatform);
  prevPlatform = undefined;
  vi.restoreAllMocks();
});

class FakeDataChannel {
  private msgCb: ((raw: any) => void) | null = null;
  private closedCb: (() => void) | null = null;
  sent: string[] = [];
  onMessage(cb: (raw: any) => void) { this.msgCb = cb; }
  onClosed(cb: () => void) { this.closedCb = cb; }
  sendMessage(text: string) { this.sent.push(text); }
  emit(obj: any) { this.msgCb?.(JSON.stringify(obj)); }
}

const frame = () => ({
  ok: true,
  result: {
    data: "QUJD", width: 1920, height: 1080,
    cursorX: 0, cursorY: 0, full: true, x: 0, y: 0, rw: 1920, rh: 1080
  }
});

/**
 * Un PrivSvc que se comporta como el de verdad en lo único que aquí importa:
 * comprueba la versión del protocolo ANTES que el método.
 *
 * Espejo de `privsvc/linux/src/router.ts`:
 *     if (req.v !== 1) return fail(req.id, "bad_version", "Unsupported protocol version");
 */
function makeSession(opts: { indicatorOk?: boolean } = {}) {
  const dc = new FakeDataChannel();
  const requests: any[] = [];
  const audits: any[] = [];

  const ctx: any = {
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    trayStatus: { setRemoteSession: vi.fn() },
    priv: {
      call: vi.fn(async (req: any) => {
        requests.push(req);
        if (req?.v !== 1) {
          return { v: 1, id: req?.id, ok: false, result: null,
                   error: { code: "bad_version", message: "Unsupported protocol version" } };
        }
        if (req.method === "rcp.indicator.show") {
          return opts.indicatorOk === false
            ? { v: 1, id: req.id, ok: false, result: null,
                error: { code: "no_display", message: "sin sesión gráfica" } }
            : { v: 1, id: req.id, ok: true, result: { shown: true }, error: null };
        }
        if (req.method === "rcp.indicator.hide") {
          return { v: 1, id: req.id, ok: true, result: {}, error: null };
        }
        return frame();
      })
    }
  };

  const session = new ScreenSession(dc as any, {
    sessionId: "sess-ipc-1",
    ctx,
    sendScreenAudit: (a: any) => audits.push(a),
    onTeardown: () => {}
  } as any);

  return { dc, session, requests, audits, ctx };
}

const pedir = (requests: any[], method: string) =>
  requests.find((r) => r?.method === method);

async function waitFor(cond: () => boolean, timeoutMs = 3000) {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) return;
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("⚠️ la llamada al indicador tiene que ser aceptable para el PrivSvc real", () => {
  it("`rcp.indicator.show` viaja con la versión del protocolo", async () => {
    pretendLinux();
    const { requests, session } = makeSession();
    await waitFor(() => Boolean(pedir(requests, "rcp.indicator.show")));

    const show = pedir(requests, "rcp.indicator.show");
    expect(show).toBeDefined();
    // El router lo mira ANTES que el método: sin esto da igual lo demás.
    expect(show.v).toBe(1);
    session.dispose("test");
  });

  it("⚠️ con un PrivSvc que valida la versión, la pantalla LLEGA a capturarse", async () => {
    // Este es el test del fallo: antes, la respuesta era `bad_version`, la
    // sesión se negaba y no se capturaba ni un fotograma. En Linux, en todos
    // los equipos, desde el 30-ago.
    pretendLinux();
    const { requests, audits, session } = makeSession();

    await waitFor(() => requests.some((r) => r?.method === "screen.capture"));
    expect(requests.some((r) => r?.method === "screen.capture")).toBe(true);
    expect(audits.some((a) => String(a?.errorMessage || "").includes("bad_version"))).toBe(false);
    session.dispose("test");
  });

  it("el `hide` del cierre también, o el aviso se queda encendido para siempre", async () => {
    // Un indicador que no se puede apagar le dice a la persona que la siguen
    // mirando cuando ya no hay nadie. Se aprende a ignorarlo, y entonces deja
    // de servir para lo único que sirve.
    pretendLinux();
    const { requests, session } = makeSession();
    await waitFor(() => Boolean(pedir(requests, "rcp.indicator.show")));

    session.dispose("test");
    await waitFor(() => Boolean(pedir(requests, "rcp.indicator.hide")));

    const hide = pedir(requests, "rcp.indicator.hide");
    expect(hide).toBeDefined();
    expect(hide.v).toBe(1);
  });

  it("⚠️ y si el aviso NO se puede enseñar, se sigue negando", async () => {
    // El arreglo no puede convertirse en abrir la puerta. Sin aviso visible no
    // se comparte pantalla: es la razón de ser de la puerta.
    pretendLinux();
    const { requests, audits, session } = makeSession({ indicatorOk: false });

    await waitFor(() => audits.some((a) => a?.event === "error"));
    expect(audits.some((a) => String(a?.errorMessage || "").startsWith("indicator_unavailable"))).toBe(true);
    expect(requests.some((r) => r?.method === "screen.capture")).toBe(false);
    session.dispose("test");
  });
});
