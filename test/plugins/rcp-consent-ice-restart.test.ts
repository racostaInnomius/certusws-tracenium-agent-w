// test/plugins/rcp-consent-ice-restart.test.ts
//
// ⚠️ Un reinicio de ICE no vuelve a pedir consentimiento.
//
// Cuando el Wi-Fi de un portátil salta de punto de acceso, el navegador
// manda una oferta nueva con credenciales ICE distintas. Para `rcp.screen`
// el agente reconstruye el peer desde cero, y el resto de `onOffer` se
// ejecuta otra vez — incluida la puerta del consentimiento. A la persona le
// volvía a saltar el diálogo a mitad de sesión sin que nada hubiera
// cambiado salvo su router.
//
// Volver a preguntar ahí no es "más seguro", es peor: enseña que el diálogo
// aparece solo y se acepta sin leer, que es exactamente cómo se anula un
// consentimiento en la práctica.
//
// La sesión es LA MISMA —mismo id, mismo operador, y el indicador de la
// pantalla nunca se apagó—, así que la decisión que ya tomó sigue valiendo.

import { describe, it, expect, vi } from "vitest";

const disposed: string[] = [];
vi.mock("../../src/plugins/rcp/peer-session", () => ({
  PeerSession: class {
    acceptOffer = vi.fn(async () => {});
    addRemoteIce = () => {};
    dispose = async (reason: string) => {
      disposed.push(reason);
    };
  }
}));

import { SessionManager } from "../../src/plugins/rcp/session-manager";

/** Oferta de pantalla, que es la única capacidad que se reconstruye. */
function offer(ufrag: string) {
  return {
    sessionId: "sess-1",
    capability: "rcp.screen",
    operatorUserId: "op@example.com",
    sdp: `v=0\r\na=ice-ufrag:${ufrag}\r\na=ice-pwd:whatever\r\n`
  };
}

function makeManager(request: ReturnType<typeof vi.fn>) {
  disposed.length = 0;
  const sent: any[] = [];
  const ctx: any = {
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    sendControl: (m: any) => sent.push(m),
    consentPrompter: { available: () => true, request },
    policyRuntime: {
      isFeatureEnabled: (f: string) =>
        f === "remoteScreen" || f === "remoteRequireConsent"
    }
  };
  return { mgr: new SessionManager(ctx), sent };
}

describe("consentimiento y reinicio de ICE", () => {
  it("⚠️ no se vuelve a preguntar al reconstruir el peer", async () => {
    const request = vi.fn(async () => "approved" as const);
    const { mgr } = makeManager(request);

    await mgr.onOffer(offer("aaaa"));
    expect(request).toHaveBeenCalledTimes(1);

    // Mismo sessionId, ufrag distinto: el navegador reinició ICE porque la
    // red se rompió. El peer se reconstruye…
    await mgr.onOffer(offer("bbbb"));
    expect(disposed).toContain("ice_restart_rebuild");

    // …y a la persona NO se le vuelve a preguntar.
    expect(request).toHaveBeenCalledTimes(1);
  });

  it("una sesión distinta sí pregunta, aunque sea el mismo equipo", async () => {
    // El permiso es de la sesión, no del equipo ni del día. Un operador que
    // abre una segunda sesión pide permiso otra vez.
    const request = vi.fn(async () => "approved" as const);
    const { mgr } = makeManager(request);

    await mgr.onOffer(offer("aaaa"));
    await mgr.onOffer({ ...offer("cccc"), sessionId: "sess-2" });

    expect(request).toHaveBeenCalledTimes(2);
  });

  it("⚠️ el permiso muere con la sesión", async () => {
    // Si sobreviviera al cierre, reabrir con el mismo id —o reutilizarlo—
    // entraría sin preguntar. Se limpia en los tres caminos de cierre.
    const request = vi.fn(async () => "approved" as const);
    const { mgr } = makeManager(request);

    await mgr.onOffer(offer("aaaa"));
    expect(request).toHaveBeenCalledTimes(1);

    await mgr.onClose({ sessionId: "sess-1", reason: "user_closed" });

    await mgr.onOffer(offer("dddd"));
    expect(request).toHaveBeenCalledTimes(2);
  });

  it("una negativa sigue cerrando la sesión", async () => {
    // El camino que no cambia: quien dice que no, cierra.
    const request = vi.fn(async () => "denied" as const);
    const { mgr, sent } = makeManager(request);

    await mgr.onOffer(offer("aaaa"));
    expect(sent).toContainEqual({
      remoteSessionClose: { sessionId: "sess-1", reason: "consent_denied" }
    });
  });

  it("⚠️ una negativa NO deja el permiso puesto para el siguiente intento", async () => {
    // El error que este mecanismo podría introducir: marcar la sesión como
    // consentida antes de mirar la respuesta. Entonces bastaría con decir
    // que no una vez para que la siguiente oferta entrara sola.
    const request = vi.fn(async () => "denied" as const);
    const { mgr } = makeManager(request);

    await mgr.onOffer(offer("aaaa"));
    await mgr.onOffer(offer("bbbb"));

    expect(request).toHaveBeenCalledTimes(2);
  });
});
