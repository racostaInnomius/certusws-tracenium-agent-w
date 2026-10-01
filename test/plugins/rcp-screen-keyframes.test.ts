// test/plugins/rcp-screen-keyframes.test.ts
//
// El fotograma completo periódico, sólo cuando hace falta.
//
// Medido en TNS-OPER-SNOC04 (1-oct-2026): ~44 KB/s entrando con la pantalla de
// login QUIETA. Era el keyframe de cada 4 s — un JPEG entero para repintar lo
// mismo. El keyframe existe para reparar un parcial perdido (el canal es
// deliberadamente no fiable), y sin parciales no hay nada que reparar.
//
// Lo que se fija:
//   · sin parciales desde el último completo, no hay completo a los 4 s;
//   · con parciales, sí (la reparación de siempre);
//   · a los 30 s hay completo pase lo que pase (red de seguridad);
//   · si el navegador pide uno (`keyframe`), sale en la siguiente captura.

import { describe, it, expect, vi, afterEach } from "vitest";
import { ScreenSession } from "../../src/plugins/rcp/screen-session";

class FakeDataChannel {
  private msgCb: ((raw: any) => void) | null = null;
  sent: string[] = [];
  onMessage(cb: (raw: any) => void) { this.msgCb = cb; }
  onClosed(_cb: () => void) {}
  sendMessage(text: string) { this.sent.push(text); }
  emit(obj: any) { this.msgCb?.(JSON.stringify(obj)); }
}

async function waitFor(cond: () => boolean, timeoutMs = 3000) {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) return;
    await new Promise((r) => setTimeout(r, 10));
  }
}

const full = { ok: true, result: { data: "QUJD", width: 1024, height: 768, full: true, rw: 1024, rh: 768 } };
const partial = { ok: true, result: { data: "QUJD", width: 1024, height: 768, full: false, x: 4, y: 4, rw: 16, rh: 16 } };
const noFrame = { ok: false, error: { code: "screen_capture_no_frame", message: "idle" } };

function makeSession(results: (call: any) => any) {
  const dc = new FakeDataChannel();
  const calls: any[] = [];
  const ctx: any = {
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    priv: {
      call: vi.fn(async (req: any) => {
        if (req?.method === "screen.capture") { calls.push(req); return results(req); }
        return { ok: true, result: {} };
      })
    }
  };
  const session = new ScreenSession(dc as any, {
    sessionId: "sess-kf", ctx, sendScreenAudit: () => {}, onTeardown: () => {}
  } as any);
  return { dc, calls, session };
}

afterEach(() => { vi.useRealTimers(); });

// ⚠️ Sólo se falsea `Date`: el bucle de captura corre con temporizadores
// reales y lee Date.now() para decidir el keyframe.
function clockAt(iso: string) {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date(iso));
}
const T0 = "2026-10-01T15:41:33Z";
const plus = (s: number) => new Date(new Date(T0).getTime() + s * 1000);

describe("keyframes", () => {
  it("⭐ pantalla quieta: NO hay completo a los 4 s", async () => {
    clockAt(T0);
    const { calls, session } = makeSession((req) => (req.params.forceFull ? full : noFrame));
    await waitFor(() => calls.length >= 2);
    expect(calls[0].params.forceFull, "el primero siempre").toBe(true);

    vi.setSystemTime(plus(5));
    const n = calls.length;
    await waitFor(() => calls.length >= n + 2);
    expect(
      calls.slice(n).some((c) => c.params.forceFull),
      "sin parciales que reparar, era un JPEG entero para pintar lo mismo",
    ).toBe(false);
    session.dispose("test");
  });

  it("con parciales SÍ hay completo a los 4 s: es la reparación", async () => {
    clockAt(T0);
    let first = true;
    const { calls, session } = makeSession(() => { if (first) { first = false; return full; } return partial; });
    await waitFor(() => calls.length >= 3);
    vi.setSystemTime(plus(5));
    const n = calls.length;
    await waitFor(() => calls.slice(n).some((c) => c.params.forceFull));
    expect(calls.slice(n).some((c) => c.params.forceFull)).toBe(true);
    session.dispose("test");
  });

  it("a los 30 s, completo aunque la pantalla esté quieta (red de seguridad)", async () => {
    clockAt(T0);
    const { calls, session } = makeSession((req) => (req.params.forceFull ? full : noFrame));
    await waitFor(() => calls.length >= 2);
    vi.setSystemTime(plus(31));
    const n = calls.length;
    await waitFor(() => calls.slice(n).some((c) => c.params.forceFull));
    expect(calls.slice(n).some((c) => c.params.forceFull)).toBe(true);
    session.dispose("test");
  });

  it("⭐ si el navegador pide uno, sale en la siguiente captura", async () => {
    clockAt(T0);
    const { dc, calls, session } = makeSession((req) => (req.params.forceFull ? full : noFrame));
    await waitFor(() => calls.length >= 2);
    const n = calls.length;
    dc.emit({ op: "keyframe" });
    await waitFor(() => calls.slice(n).some((c) => c.params.forceFull));
    expect(calls.slice(n).some((c) => c.params.forceFull)).toBe(true);
    // …y una vez entregado, deja de pedirse.
    const m = calls.length;
    await waitFor(() => calls.length >= m + 2);
    expect(calls.slice(m).some((c) => c.params.forceFull)).toBe(false);
    session.dispose("test");
  });
});
