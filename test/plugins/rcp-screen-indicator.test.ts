// test/plugins/rcp-screen-indicator.test.ts
//
// El indicador de la bandeja (ADR-0012) es lo que le permite a una persona
// enterarse de que le están viendo la pantalla y cortarlo. Sus fallos son
// silenciosos por naturaleza: si no se enciende, no hay error en ningún log —
// simplemente alguien mira sin que se note, que es exactamente el estado que
// teníamos antes de este trabajo y del que nadie se quejó porque nadie podía
// saberlo.
//
// De ahí que lo que se fija aquí no sea "la función se llama", sino el
// CONTRATO temporal: encendido antes del primer fotograma, apagado al
// terminar, y escalado a "controlando" en cuanto entra el primer evento.

import { describe, it, expect, vi } from "vitest";
import { ScreenSession } from "../../src/plugins/rcp/screen-session";

class FakeDataChannel {
  private msgCb: ((raw: any) => void) | null = null;
  private closedCb: (() => void) | null = null;
  sent: string[] = [];
  onMessage(cb: (raw: any) => void) { this.msgCb = cb; }
  onClosed(cb: () => void) { this.closedCb = cb; }
  sendMessage(text: string) { this.sent.push(text); }
  emit(obj: any) { this.msgCb?.(JSON.stringify(obj)); }
  triggerClosed() { this.closedCb?.(); }
}

const okFrame = () => ({
  ok: true,
  result: {
    data: "QUJD",
    width: 1920, height: 1080,
    cursorX: 0, cursorY: 0,
    full: true, x: 0, y: 0, rw: 1920, rh: 1080
  }
});

/**
 * Sesión con la bandeja instrumentada. `published` guarda TODAS las
 * publicaciones en orden: el orden es justo lo que hay que comprobar.
 */
function makeSession(over: Record<string, unknown> = {}) {
  const dc = new FakeDataChannel();
  const published: any[] = [];
  const captures: any[] = [];

  const ctx: any = {
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    trayStatus: {
      setRemoteSession: vi.fn((s: any) => published.push(s))
    },
    priv: {
      call: vi.fn(async (req: any) => {
        if (req.method === "screen.capture") captures.push(req);
        return okFrame();
      })
    }
  };

  const session = new ScreenSession(dc as any, {
    sessionId: "sess-indicator-1",
    ctx,
    sendScreenAudit: () => {},
    onTeardown: () => {},
    ...over
  } as any);

  return { dc, session, published, captures, ctx };
}

async function waitFor(cond: () => boolean, timeoutMs = 3000) {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) return;
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("indicador de sesión de pantalla", () => {
  it("se enciende ANTES del primer fotograma capturado", async () => {
    // El orden importa más que el hecho. Si el indicador se publicara después
    // del primer AcquireNextFrame, habría una ventana —corta, pero real— en la
    // que la pantalla de alguien ya salió del equipo sin aviso encendido.
    const { published, captures, session } = makeSession();

    expect(published.length).toBeGreaterThanOrEqual(1);
    expect(published[0].active).toBe(true);
    expect(captures.length).toBe(0);

    await waitFor(() => captures.length >= 1);
    expect(captures.length).toBeGreaterThanOrEqual(1);
    session.dispose("test");
  });

  it("lleva el nombre del operador cuando el backend lo manda", async () => {
    const { published, session } = makeSession({ operator: "Javier Pacheco" });
    expect(published[0].operator).toBe("Javier Pacheco");
    session.dispose("test");
  });

  it("manda operador vacío —no undefined— con backends antiguos", async () => {
    // La bandeja decide entre el nombre y "un operador" mirando si la cadena
    // está vacía. Un undefined viajando por JSON borra el campo y la bandeja
    // lo trata igual, pero dejarlo explícito evita depender de eso.
    const { published, session } = makeSession();
    expect(published[0].operator).toBe("");
    session.dispose("test");
  });

  it("arranca como 'viendo', no como 'controlando'", async () => {
    const { published, session } = makeSession();
    expect(published[0].controlling).toBe(false);
    session.dispose("test");
  });

  it("escala a 'controlando' con el primer evento de entrada", async () => {
    // Se deduce del evento real, no del botón de la UI del operador: el
    // indicador enseña lo que le pasó al equipo, no lo que declara quien mira.
    const { dc, published, session } = makeSession();
    dc.emit({ op: "mouseDown", button: 0, x: 5, y: 5 });
    await waitFor(() => published.length >= 2);

    const last = published[published.length - 1];
    expect(last.active).toBe(true);
    expect(last.controlling).toBe(true);
    session.dispose("test");
  });

  it("no republica en cada evento de entrada", async () => {
    // Un mouseMove por píxel reescribiría el fichero de estado cientos de
    // veces por minuto, y el watcher de la bandeja repintaría con cada uno.
    const { dc, published, session } = makeSession();
    for (let i = 0; i < 25; i++) dc.emit({ op: "mouseMove", x: i, y: i });
    await waitFor(() => published.length >= 2);
    await new Promise((r) => setTimeout(r, 50));

    // Encendido inicial + una sola escalada.
    expect(published.length).toBe(2);
    session.dispose("test");
  });

  it("mantiene el instante de arranque al escalar a control", async () => {
    // Recalcular la fecha en cada republicación haría que la sesión pareciera
    // recién empezada justo cuando acaba de escalar a control.
    const { dc, published, session } = makeSession();
    const started = published[0].startedAtUtc;

    await new Promise((r) => setTimeout(r, 20));
    dc.emit({ op: "keyDown", key: "a" });
    await waitFor(() => published.length >= 2);

    expect(published[published.length - 1].startedAtUtc).toBe(started);
    session.dispose("test");
  });

  it("se apaga al terminar la sesión", async () => {
    // Un indicador que se queda encendido sin sesión enseña una alarma falsa,
    // y una alarma falsa entrena a la gente a ignorar la siguiente.
    const { published, session } = makeSession();
    session.dispose("test");
    await waitFor(() => published[published.length - 1] === null);
    expect(published[published.length - 1]).toBeNull();
  });

  it("no tumba la sesión si la bandeja no se puede escribir", async () => {
    // El disco lleno o una ACL rara no pueden costar la sesión de soporte;
    // pero el log tiene que gritarlo, porque significa que hay alguien viendo
    // una pantalla sin que su dueño pueda saberlo.
    const dc = new FakeDataChannel();
    const warns: any[] = [];
    const ctx: any = {
      logger: {
        info: () => {}, error: () => {}, debug: () => {},
        warn: (...a: any[]) => warns.push(a)
      },
      trayStatus: {
        setRemoteSession: () => { throw new Error("EACCES"); }
      },
      priv: { call: vi.fn(async () => okFrame()) }
    };

    const session = new ScreenSession(dc as any, {
      sessionId: "sess-indicator-2",
      ctx,
      sendScreenAudit: () => {},
      onTeardown: () => {}
    } as any);

    expect(warns.length).toBeGreaterThanOrEqual(1);
    expect(String(warns[0][0])).toContain("indicador");
    session.dispose("test");
  });

  it("funciona con un ctx sin bandeja", async () => {
    // Linux headless y los tests de otros módulos construyen sesiones sin
    // trayStatus. El optional-chaining está ahí a propósito.
    const dc = new FakeDataChannel();
    const ctx: any = {
      logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
      priv: { call: vi.fn(async () => okFrame()) }
    };
    expect(() => new ScreenSession(dc as any, {
      sessionId: "sess-indicator-3",
      ctx,
      sendScreenAudit: () => {},
      onTeardown: () => {}
    } as any).dispose("test")).not.toThrow();
  });
});
