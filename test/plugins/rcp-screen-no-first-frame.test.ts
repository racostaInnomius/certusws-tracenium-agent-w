// test/plugins/rcp-screen-no-first-frame.test.ts
//
// 🔴 TNS-OPER-SNOC04 (T1, 29-sep-2026): «Waiting for first frame…» para
// siempre, sin un solo error.
//
// Lo medido en producción antes de tocar código, porque el agente no contaba
// nada: la sesión quedó `active`, con `answered` y `connected setupMs:1021` —
// señalización, ICE y DataChannel perfectos— y CERO fotogramas.
//
// La causa: un servidor sin nadie dentro enseña su pantalla de inicio de
// sesión, y ese escritorio no cambia NUNCA. `AcquireNextFrame` agota su espera
// en cada llamada, DXGI contesta `screen_capture_no_frame`, y esa es
// justamente la única rama que el agente calla a propósito («escritorio
// quieto, el navegador ya tiene los píxeles buenos») — premisa falsa cuando no
// ha habido un primer fotograma. En un PC de usuario nunca se vio porque
// siempre se mueve algo.
//
// Se arreglan las dos mitades, y la segunda importa aunque la primera esté:
// cualquier otro motivo por el que no llegue el primer fotograma dejaba al
// operador ante un cartel que no caduca.

import { describe, it, expect, vi, afterEach } from "vitest";
import { ScreenSession } from "../../src/plugins/rcp/screen-session";
import { readFileSync } from "node:fs";
import path from "node:path";

class FakeDataChannel {
  private msgCb: ((raw: any) => void) | null = null;
  private closedCb: (() => void) | null = null;
  sent: string[] = [];
  onMessage(cb: (raw: any) => void) { this.msgCb = cb; }
  onClosed(cb: () => void) { this.closedCb = cb; }
  sendMessage(text: string) { this.sent.push(text); }
  triggerClosed() { this.closedCb?.(); }
  parsed(): any[] { return this.sent.map((s) => JSON.parse(s)); }
  ofOp(op: string): any[] { return this.parsed().filter((m) => m.op === op); }
}

function makeSession(results: (call: any) => any) {
  const dc = new FakeDataChannel();
  const calls: any[] = [];
  const ctx: any = {
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    priv: {
      // Igual que en rcp-screen-dirty-rects: sólo las capturas, porque en
      // Linux la sesión emite además `rcp.indicator.show` antes del primer
      // fotograma y las aserciones sobre `calls[n]` se volverían dependientes
      // de la plataforma del runner.
      //
      // ⚠️ Y el indicador se contesta AQUÍ, no con `results`. Este fichero es
      // el primero cuyas respuestas son `ok: false` (`noFrame`): en Linux la
      // sesión pide `rcp.indicator.show` antes de capturar, recibía ese
      // `ok: false`, se cortaba por `indicator_unavailable` y no capturaba
      // nunca. Y en el segundo test el indicador se comía la única respuesta
      // con imagen. Verde en macOS, rojo en el ubuntu-latest del CI desde
      // 1.1.86 — la misma trampa que ya documenta rcp-screen-dirty-rects.
      call: vi.fn(async (req: any) => {
        if (String(req?.method ?? "").startsWith("rcp.indicator.")) return { ok: true };
        if (req?.method === "screen.capture") calls.push(req);
        return results(req);
      })
    }
  };
  const session = new ScreenSession(dc as any, {
    sessionId: "sess-screen-snoc04",
    ctx,
    sendScreenAudit: () => {},
    onTeardown: () => {}
  });
  return { dc, calls, session };
}

// ⚠️ `performance.now()`, no `Date.now()`: estos tests congelan `Date`, y con
// él este tope no vencía nunca — una condición que no llegaba se convertía en
// un «Test timed out in 30000ms» que no dice cuál.
async function waitFor(cond: () => boolean, timeoutMs = 3000) {
  const start = performance.now();
  while (!cond()) {
    if (performance.now() - start > timeoutMs) return;
    await new Promise((r) => setTimeout(r, 10));
  }
}

const noFrame = () => ({
  ok: false,
  error: { code: "screen_capture_no_frame", message: "No new frame within timeout (idle desktop)" }
});

afterEach(() => {
  vi.useRealTimers();
});

describe("un escritorio quieto que nunca da el primer fotograma", () => {
  it("🔴 avisa al operador en vez de dejarlo esperando", async () => {
    // ⚠️ Sólo se falsea `Date`. El bucle de captura corre con temporizadores
    // REALES a 5 fps; falsear setTimeout aquí probaría el mock y no el código.
    // Con `Date` falso podemos saltar la espera de gracia sin congelar nada.
    vi.useFakeTimers({ toFake: ["Date"] });
    const t0 = new Date("2026-09-29T14:03:39Z");
    vi.setSystemTime(t0);

    const { dc, calls, session } = makeSession(noFrame);
    // El bucle usa Date.now() para su propio ritmo, así que esperamos por el
    // contador de llamadas, no por el reloj.
    await waitFor(() => calls.length >= 1);
    expect(dc.ofOp("error")).toHaveLength(0);

    // Pasada la gracia, el silencio deja de ser aceptable.
    vi.setSystemTime(new Date(t0.getTime() + 9_000));
    await waitFor(() => dc.ofOp("error").length >= 1);

    const err = dc.ofOp("error")[0];
    expect(err.code).toBe("screen_capture_no_first_frame");
    expect(
      err.terminal,
      "no es terminal: si el fotograma llega luego, el visor pinta y sigue",
    ).toBe(false);
    session.dispose("test");
  });

  it("no avisa si el primer fotograma llegó, por quieto que esté después", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const t0 = new Date("2026-09-29T14:03:39Z");
    vi.setSystemTime(t0);

    let first = true;
    const { dc, calls, session } = makeSession(() => {
      if (!first) return noFrame();
      first = false;
      return {
        ok: true,
        result: { data: "QUJD", width: 1920, height: 1080, full: true, rw: 1920, rh: 1080 }
      };
    });
    await waitFor(() => calls.length >= 2);
    vi.setSystemTime(new Date(t0.getTime() + 30_000));
    await waitFor(() => calls.length >= 4);

    expect(
      dc.ofOp("error"),
      "un escritorio quieto CON imagen entregada es el estado normal de la flota",
    ).toHaveLength(0);
    expect(dc.ofOp("frame").length).toBeGreaterThan(0);
    session.dispose("test");
  });

  /**
   * La otra mitad silenciosa del mismo camino: PrivSvc puede contestar `ok`
   * con `data` vacío —su ParseHelperLine rellena `["data"] = … ?? ""`— y el
   * agente hacía `if (!data) return`. Encima justo antes había puesto a cero
   * los contadores de fallo, así que ni siquiera entraba en el camino que
   * reporta. Un `ok` vacío en bucle no dejaba rastro en ningún sitio.
   */
  it("🔴 un `ok` con data vacío se reporta, no se descarta", async () => {
    const { dc, session } = makeSession(() => ({
      ok: true,
      result: { data: "", width: 1920, height: 1080, full: true }
    }));

    await waitFor(() => dc.ofOp("error").length >= 1, 5000);
    const err = dc.ofOp("error")[0];
    expect(err.code).toBe("screen_capture_empty");
    expect(dc.ofOp("frame"), "no se envía imagen vacía").toHaveLength(0);
    session.dispose("test");
  });
});

/**
 * La causa raíz vive en C# y este runner no lo compila (el `protoc` de
 * grpc.tools sólo viene x86_64 y este Mac es ARM), así que la guarda es
 * estática: que la condición siga en el fichero.
 */
describe("el helper de captura contesta a un keyframe aunque nada se mueva", () => {
  const PROGRAM = path.resolve(
    __dirname, "../../privsvc/windows/Tracenium.ScreenCap/Program.cs"
  );
  // ⚠️ Sin comentarios: este fichero y el propio Program.cs EXPLICAN el fallo
  // citando el código viejo, y un escáner ingenuo encuentra la explicación en
  // vez del código. Ya pasó dos veces en este repo.
  const code = readFileSync(PROGRAM, "utf8")
    .split("\n")
    .filter((l) => {
      const t = l.trimStart();
      return !t.startsWith("//") && !t.startsWith("*") && !t.startsWith("/*");
    })
    .join("\n");

  it("`no_frame` sólo corta en seco si NO se pidió fotograma completo", () => {
    expect(
      code,
      "sin el `!forceFull`, un escritorio que no cambia nunca —la pantalla de "
        + "login de un servidor— no entrega jamás el primer fotograma",
    ).toMatch(/code == "screen_capture_no_frame"\s*&&\s*!forceFull/);
  });

  it("y entonces lo lee GDI, que no depende de que algo cambie", () => {
    const guard = code.indexOf('code == "screen_capture_no_frame" && !forceFull');
    const gdi = code.indexOf('ScreenCapture.Capture("helper", quality)');
    expect(guard).toBeGreaterThan(-1);
    expect(
      gdi,
      "la reserva de GDI tiene que quedar DESPUÉS: es donde cae el keyframe",
    ).toBeGreaterThan(guard);
  });
});

/**
 * 🔴 Segunda vuelta (1-oct-2026, agente 1.1.88): con CAPTUREBLT y todo, la
 * pantalla de inicio de sesión de SNOC04 salió AZUL hasta que el operador movió
 * el cursor. El fotograma completo de un escritorio quieto no puede depender
 * de GDI. Dos piezas, y GDI queda como último recurso:
 *
 *   · DXGI conserva su textura de staging — siempre la última imagen real — y
 *     un fotograma completo sin cambios se re-codifica desde ahí;
 *   · si aún no hay ninguna imagen, en el escritorio de Windows el helper
 *     mueve el ratón un píxel y vuelta (lo mismo que arregló el operador) y
 *     reintenta DXGI.
 */
describe("un fotograma completo de un escritorio quieto NO sale de GDI", () => {
  const strip = (p: string) =>
    readFileSync(path.resolve(__dirname, p), "utf8")
      .split("\n")
      .filter((l) => {
        const t = l.trimStart();
        return !t.startsWith("//") && !t.startsWith("*") && !t.startsWith("/*") && !t.startsWith("///");
      })
      .join("\n");
  const DXGI = "../../privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/ScreenCaptureDxgi.cs";
  const HELPER = "../../privsvc/windows/Tracenium.ScreenCap/Program.cs";
  const SESSION = "../../privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/SessionScreenCapture.cs";

  it("⭐ sin cambios y con fotograma completo pedido, se re-codifica la última imagen de DXGI", () => {
    const d = strip(DXGI);
    const timeout = d.indexOf("if (hr == DXGI_ERROR_WAIT_TIMEOUT)");
    const staged = d.indexOf("TryEncodeStagedFull(reqId, quality)", timeout);
    const noFrame = d.indexOf('"screen_capture_no_frame"', timeout);
    expect(staged, "sin esto el keyframe de una pantalla quieta vuelve a GDI: azul").toBeGreaterThan(timeout);
    expect(noFrame, "no_frame sólo DESPUÉS de intentar la última imagen").toBeGreaterThan(staged);
  });

  it("la textura de staging sobrevive al fotograma (es la última imagen)", () => {
    const d = strip(DXGI);
    const capture = d.slice(d.indexOf("private static int TryCaptureFrame("), d.indexOf("private static PrivSvcResponse? TryEncodeStagedFull("));
    expect(capture).toContain("_stagingValid = true;");
    expect(capture, "liberarla en cada fotograma tira la última imagen").not.toMatch(/Release\(stagingTex\)/);
    const cleanup = d.slice(d.indexOf("private static void Cleanup()"));
    expect(cleanup, "al reiniciar la cadena la vieja ya no vale").toContain("Release(_staging);");
    expect(cleanup).toContain("_stagingValid = false;");
  });

  it("⭐ sin ninguna imagen, en el escritorio de Windows: despertar y reintentar DXGI ANTES que GDI", () => {
    const h = strip(HELPER);
    const nudge = h.indexOf("InputInjection.Nudge();");
    const gdi = h.indexOf('ScreenCapture.Capture("helper", quality)');
    expect(nudge, "lo que arregló el azul fue mover el cursor").toBeGreaterThan(-1);
    expect(gdi, "GDI va DESPUÉS, como último recurso").toBeGreaterThan(nudge);
    const gate = h.slice(h.lastIndexOf("if (", nudge), nudge);
    expect(gate, "sólo en el escritorio de Windows").toContain("HelperState.Logon");
    expect(gate, "una vez por helper, no en cada keyframe").toContain("!HelperState.Nudged");
  });

  it("PrivSvc pasa --logon sólo al arrancar el helper en el escritorio de Windows", () => {
    expect(strip(SESSION)).toContain('if (logonDesktop) cmdline.Append(" --logon");');
  });
});
