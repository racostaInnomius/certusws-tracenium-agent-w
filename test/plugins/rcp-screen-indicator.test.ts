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
});

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

  it("en Windows/macOS NO llama al indicador nativo de Linux", async () => {
    // La bandeja ya vive en la sesión del usuario en esas dos plataformas;
    // este IPC no existe en sus PrivSvc y llamarlo sería un error por método
    // desconocido en cada sesión.
    const { ctx, session, captures } = makeSession();
    await waitFor(() => captures.length >= 1);

    const methods = ctx.priv.call.mock.calls.map((c: any[]) => c[0].method);
    expect(methods).not.toContain("rcp.indicator.show");
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

// ── La puerta de Linux ──────────────────────────────────────────────
//
// En Windows y macOS el aviso lo pinta la bandeja, que ya vive en la sesión
// del usuario. Linux no tiene nada nuestro ahí, así que PrivSvc lanza el aviso
// a propósito para cada sesión — y eso puede fallar por su cuenta. Cuando
// falla, la elección es real: compartir pantalla sin que nadie pueda saberlo,
// o no compartirla. ADR-0012 dice que no se comparte.
describe("indicador en Linux — puerta fail-closed", () => {
  /** Sesión en Linux cuyo PrivSvc responde `indicator` según `indicatorReply`. */
  function makeLinuxSession(indicatorReply: any) {
    pretendLinux();
    const dc = new FakeDataChannel();
    const captures: any[] = [];
    const methods: string[] = [];
    const audits: any[] = [];

    const ctx: any = {
      logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
      trayStatus: { setRemoteSession: () => {} },
      priv: {
        call: vi.fn(async (req: any) => {
          methods.push(req.method);
          if (req.method === "rcp.indicator.show") return indicatorReply;
          if (req.method === "rcp.indicator.hide") return { ok: true };
          // Contar SOLO screen.capture: cualquier método futuro que se añada
          // al cierre se colaría aquí como si fuera un fotograma capturado.
          if (req.method === "screen.capture") captures.push(req);
          return okFrame();
        })
      }
    };

    const session = new ScreenSession(dc as any, {
      sessionId: "sess-linux-1",
      ctx,
      operator: "Javier Pacheco",
      sendScreenAudit: (a: any) => audits.push(a),
      onTeardown: () => {}
    } as any);

    return { dc, session, captures, methods, audits, ctx };
  }

  it("enciende el indicador ANTES de capturar el primer fotograma", async () => {
    const { methods, captures, session } = makeLinuxSession({ ok: true });
    await waitFor(() => captures.length >= 1);

    expect(methods[0]).toBe("rcp.indicator.show");
    session.dispose("test");
  });

  it("le pasa al helper el nombre del operador", async () => {
    const { ctx, captures, session } = makeLinuxSession({ ok: true });
    await waitFor(() => captures.length >= 1);

    const show = ctx.priv.call.mock.calls
      .map((c: any[]) => c[0])
      .find((r: any) => r.method === "rcp.indicator.show");
    expect(show.params.text).toContain("Javier Pacheco");
    expect(show.params.sessionId).toBe("sess-linux-1");
    session.dispose("test");
  });

  it("NO captura ni un fotograma si el indicador no arranca", async () => {
    // El caso que carga toda la garantía. Sin esto, un paquete construido sin
    // libX11 compartiría pantalla en silencio.
    const { captures, methods, session } = makeLinuxSession({
      ok: false, code: "indicator_no_font", message: "no font"
    });
    await waitFor(() => methods.length >= 1);
    await new Promise((r) => setTimeout(r, 250));

    expect(captures.length).toBe(0);
    session.dispose("test");
  });

  it("deja el motivo en la auditoría, no solo en el log", async () => {
    // "La sesión no arrancó" sin causa manda a quien lo investigue a mirar
    // WebRTC, que es donde no está el problema.
    const { audits, session } = makeLinuxSession({
      ok: false, code: "indicator_no_font", message: "no font"
    });
    await waitFor(() => audits.some((a) => a.event === "error"));

    const err = audits.find((a) => a.event === "error");
    expect(err.errorMessage).toContain("indicator_unavailable");
    expect(err.errorMessage).toContain("indicator_no_font");
    session.dispose("test");
  });

  it("tampoco captura si la llamada al indicador LANZA", async () => {
    // PrivSvc caído o IPC roto. Un throw no puede ser más permisivo que un
    // `ok:false`: sería la puerta abriéndose justo cuando algo va mal.
    pretendLinux();
    const dc = new FakeDataChannel();
    const captures: any[] = [];
    const ctx: any = {
      logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
      priv: {
        call: vi.fn(async (req: any) => {
          if (req.method === "rcp.indicator.show") throw new Error("IPC caído");
          // ⚠️ Filtrar por screen.capture, no "todo lo que no sea show". El
          // cierre manda un rcp.indicator.hide, y contarlo como captura hacía
          // fallar este test con la pantalla NUNCA capturada — un rojo que
          // acusaba al código de lo que hacía mal el doble.
          if (req.method === "screen.capture") captures.push(req);
          return okFrame();
        })
      }
    };
    const session = new ScreenSession(dc as any, {
      sessionId: "sess-linux-2", ctx,
      sendScreenAudit: () => {}, onTeardown: () => {}
    } as any);

    await new Promise((r) => setTimeout(r, 250));
    expect(captures.length).toBe(0);
    session.dispose("test");
  });

  it("retira el indicador al cerrar la sesión", async () => {
    // Un aviso huérfano diciendo "te están viendo" cuando ya nadie mira es una
    // alarma falsa, y entrena a ignorar la siguiente.
    const { methods, captures, session } = makeLinuxSession({ ok: true });
    await waitFor(() => captures.length >= 1);
    session.dispose("test");
    await waitFor(() => methods.includes("rcp.indicator.hide"));

    expect(methods).toContain("rcp.indicator.hide");
  });
});

// ── Segunda puerta: CONTROLAR (ADR-0012) ────────────────────────────
describe("puerta de control en la sesión", () => {
  function makeConsentSession(opts: {
    required: boolean;
    decision?: "approved" | "denied" | "timeout";
    throws?: boolean;
  }) {
    const dc = new FakeDataChannel();
    const injected: any[] = [];
    const asked: any[] = [];

    const ctx: any = {
      logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
      trayStatus: { setRemoteSession: () => {} },
      policyRuntime: { isFeatureEnabled: (f: string) => f === "remoteRequireConsent" && opts.required },
      consentPrompter: {
        available: () => true,
        request: async (r: any) => {
          asked.push(r);
          if (opts.throws) throw new Error("prompter roto");
          return opts.decision ?? "approved";
        }
      },
      priv: {
        call: vi.fn(async (req: any) => {
          if (req.method === "input.inject") injected.push(req.params);
          return okFrame();
        })
      }
    };

    const session = new ScreenSession(dc as any, {
      sessionId: "sess-consent", ctx, operator: "Javier Pacheco",
      sendScreenAudit: () => {}, onTeardown: () => {}
    } as any);

    return { dc, session, injected, asked };
  }

  it("sin política de consentimiento, la entrada pasa como siempre", async () => {
    const { dc, injected, session } = makeConsentSession({ required: false });
    dc.emit({ op: "mouseDown", button: 0, x: 5, y: 5 });
    await waitFor(() => injected.length >= 1);
    expect(injected.length).toBe(1);
    session.dispose("test");
  });

  it("el primer evento pide permiso y NO se inyecta", async () => {
    // Regalar "solo el primero" sería regalar justo el clic que puede pulsar
    // Aceptar en un diálogo del sistema.
    const { dc, injected, asked, session } = makeConsentSession({
      required: true, decision: "approved"
    });
    dc.emit({ op: "mouseDown", button: 0, x: 5, y: 5 });
    await waitFor(() => asked.length >= 1);

    expect(asked[0].capability).toBe("rcp.screen.control");
    expect(asked[0].operator).toBe("Javier Pacheco");
    expect(injected.length).toBe(0);
    session.dispose("test");
  });

  it("tras el sí, la entrada fluye", async () => {
    const { dc, injected, asked, session } = makeConsentSession({
      required: true, decision: "approved"
    });

    // Primer evento: dispara el aviso y se tira.
    dc.emit({ op: "mouseMove", x: 1, y: 1 });
    await waitFor(() => asked.length >= 1);
    expect(injected.length).toBe(0);

    // El permiso se resuelve de forma asíncrona; esperamos a que la puerta
    // esté abierta antes de mandar el siguiente. Sin esta espera el test
    // pasaría por accidente o fallaría por carrera, según el día.
    dc.emit({ op: "mouseDown", button: 0, x: 5, y: 5 });
    await waitFor(() => injected.length >= 1);

    expect(injected.length).toBe(1);
    expect(injected[0].op).toBe("mouseDown");
    session.dispose("test");
  });

  it("una ráfaga de ratón lanza UN solo aviso, no uno por evento", async () => {
    // 60 eventos por segundo ⇒ 60 diálogos. La persona vería su pantalla
    // sepultada y no podría ni contestar al primero.
    const { dc, asked, session } = makeConsentSession({
      required: true, decision: "approved"
    });
    for (let i = 0; i < 40; i++) dc.emit({ op: "mouseMove", x: i, y: i });
    await waitFor(() => asked.length >= 1);
    await new Promise((r) => setTimeout(r, 80));

    expect(asked.length).toBe(1);
    session.dispose("test");
  });

  it("tras el NO, la entrada no pasa y la sesión SIGUE VIVA", async () => {
    // Lo importante es la segunda mitad: la persona consintió que la vieran.
    // Tumbar la sesión por rechazar el control castigaría un "no" razonable y
    // empujaría a decir que sí a todo para que el técnico pueda seguir.
    const { dc, injected, session } = makeConsentSession({
      required: true, decision: "denied"
    });
    dc.emit({ op: "mouseDown", button: 0, x: 5, y: 5 });
    await waitFor(() => dc.sent.some((s) => s.includes("control_consent_denied")));

    for (let i = 0; i < 5; i++) dc.emit({ op: "mouseMove", x: i, y: i });
    await new Promise((r) => setTimeout(r, 60));

    expect(injected.length).toBe(0);
    const err = dc.sent.map((s) => JSON.parse(s)).find((m) => m.op === "error");
    expect(err.code).toBe("control_consent_denied");
    expect(err.terminal).toBe(false);   // ← la sesión sigue viéndose
    session.dispose("test");
  });

  it("al operador se le explica UNA vez, no con cada clic", async () => {
    const { dc, session } = makeConsentSession({ required: true, decision: "denied" });
    dc.emit({ op: "mouseDown", button: 0, x: 5, y: 5 });
    await waitFor(() => dc.sent.some((s) => s.includes("control_consent_denied")));
    for (let i = 0; i < 10; i++) dc.emit({ op: "mouseMove", x: i, y: i });
    await new Promise((r) => setTimeout(r, 60));

    const errs = dc.sent.map((s) => JSON.parse(s))
      .filter((m) => m.op === "error" && m.code === "control_consent_denied");
    expect(errs.length).toBe(1);
    session.dispose("test");
  });

  it("el timeout se trata como negativa", async () => {
    const { dc, injected, session } = makeConsentSession({
      required: true, decision: "timeout"
    });
    dc.emit({ op: "mouseDown", button: 0, x: 5, y: 5 });
    await waitFor(() => dc.sent.some((s) => s.includes("control_consent_timeout")));
    expect(injected.length).toBe(0);
    session.dispose("test");
  });

  it("un prompter que LANZA deniega, no concede", async () => {
    // Un aviso roto no puede convertirse en un permiso concedido.
    const { dc, injected, session } = makeConsentSession({ required: true, throws: true });
    dc.emit({ op: "mouseDown", button: 0, x: 5, y: 5 });
    await waitFor(() => dc.sent.some((s) => s.includes("control_consent_denied")));
    expect(injected.length).toBe(0);
    session.dispose("test");
  });

  it("sin prompter registrado, deniega (fail-closed)", async () => {
    // El default de consent-prompt.ts. Una plataforma sin diálogo nativo no
    // puede conceder control por omisión.
    const dc = new FakeDataChannel();
    const injected: any[] = [];
    const ctx: any = {
      logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
      policyRuntime: { isFeatureEnabled: (f: string) => f === "remoteRequireConsent" },
      priv: {
        call: vi.fn(async (req: any) => {
          if (req.method === "input.inject") injected.push(req.params);
          return okFrame();
        })
      }
    };
    const session = new ScreenSession(dc as any, {
      sessionId: "sess-noprompter", ctx,
      sendScreenAudit: () => {}, onTeardown: () => {}
    } as any);

    dc.emit({ op: "mouseDown", button: 0, x: 5, y: 5 });
    await waitFor(() => dc.sent.some((s) => s.includes("control_consent_denied")));
    expect(injected.length).toBe(0);
    session.dispose("test");
  });
});
