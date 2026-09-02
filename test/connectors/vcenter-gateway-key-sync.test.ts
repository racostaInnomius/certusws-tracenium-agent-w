// test/connectors/vcenter-gateway-key-sync.test.ts
//
// ADR-0013 — el ciclo de vida de la clave que abre la credencial de vCenter.
//
// Lo que se defiende aquí tiene dos modos de fallo caros y opuestos:
//
//   Crear de más — una clave capaz de descifrar en un equipo que no es
//   gateway. Es el error que hizo descartar la forma obvia del diseño:
//   provisionarla en el enrolamiento la habría puesto en toda la flota.
//
//   Recordar de más — dar por publicado un certificado que el control plane
//   nunca recibió. El agente dejaría de reintentarlo y el admin vería para
//   siempre un gateway que no acepta credenciales.

import { describe, it, expect, vi } from "vitest";
import {
  decideGatewayKeyAction,
  shouldPublish,
  reconcileGatewayKey,
  formatFingerprint,
  type GatewayKeySyncDeps,
} from "../../src/connectors/vcenter/gateway-key-sync";

const MATERIAL = { certPem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----", fingerprintSha256: "aa11" };

function deps(over: Partial<GatewayKeySyncDeps> = {}): GatewayKeySyncDeps {
  return {
    isGateway: () => true,
    deviceId: () => "dev-1",
    ensureKey: vi.fn(async () => MATERIAL),
    destroyKey: vi.fn(async () => {}),
    publish: vi.fn(async () => {}),
    announce: vi.fn(),
    ...over,
  };
}

describe("qué hacer con la clave", () => {
  it("no toca nada en un equipo que nunca fue gateway", () => {
    // El caso que cubre a la inmensa mayoría de la flota, y la razón de que
    // la clave no se cree en el enrolamiento.
    expect(decideGatewayKeyAction({ isGateway: false, publishedFingerprint: null })).toBe("none");
  });

  it("la destruye cuando se retira el rol", () => {
    expect(decideGatewayKeyAction({ isGateway: false, publishedFingerprint: "aa11" })).toBe("destroy");
  });

  it("sigue asegurándola aunque ya se publicara", () => {
    // `ensure` es idempotente y es la única forma de notar que el material
    // desapareció por debajo — una reinstalación, un /etc restaurado. Un
    // reconciliador que se fía de su memoria deja de reconciliar.
    expect(decideGatewayKeyAction({ isGateway: true, publishedFingerprint: "aa11" })).toBe("ensure");
  });
});

describe("cuándo publicar", () => {
  it("publica lo que aún no se publicó", () => {
    expect(shouldPublish({ fingerprintSha256: "aa11" }, null)).toBe(true);
  });

  it("calla cuando la huella no ha cambiado", () => {
    // Si no, cada sincronización de política sería ruido contra un valor que
    // casi nunca se mueve.
    expect(shouldPublish({ fingerprintSha256: "aa11" }, "aa11")).toBe(false);
  });

  it("republica cuando el material es otro", () => {
    expect(shouldPublish({ fingerprintSha256: "bb22" }, "aa11")).toBe(true);
  });

  it("no publica material sin huella", () => {
    expect(shouldPublish({ fingerprintSha256: "" }, null)).toBe(false);
  });
});

describe("un paso de reconciliación", () => {
  it("crea y publica al designar el gateway", async () => {
    const d = deps();
    const next = await reconcileGatewayKey(d, { publishedFingerprint: null });

    expect(d.ensureKey).toHaveBeenCalledWith("dev-1");
    expect(d.publish).toHaveBeenCalledWith(MATERIAL);
    expect(next.publishedFingerprint).toBe("aa11");
  });

  it("⭐ no recuerda la publicación si la publicación falló", async () => {
    // El modo de fallo silencioso: dar por entregado lo que no salió deja al
    // agente sin reintentar nunca, y al gateway sin poder aceptar
    // credenciales para siempre.
    const d = deps({ publish: vi.fn(async () => { throw new Error("red caída"); }) });
    const next = await reconcileGatewayKey(d, { publishedFingerprint: null });

    expect(next.publishedFingerprint).toBeNull();
  });

  it("olvida la huella al destruir, para volver a publicar si vuelve el rol", async () => {
    const d = deps({ isGateway: () => false });
    const next = await reconcileGatewayKey(d, { publishedFingerprint: "aa11" });

    expect(d.destroyKey).toHaveBeenCalledWith("dev-1");
    expect(d.ensureKey).not.toHaveBeenCalled();
    expect(next.publishedFingerprint).toBeNull();
  });

  it("nunca crea la clave en un equipo que no es gateway", async () => {
    const d = deps({ isGateway: () => false });
    await reconcileGatewayKey(d, { publishedFingerprint: null });

    expect(d.ensureKey).not.toHaveBeenCalled();
    expect(d.destroyKey).not.toHaveBeenCalled();
  });

  it("no lanza cuando privsvc falla", async () => {
    // Cuelga del camino que aplica políticas: una excepción aquí tumbaría la
    // aplicación de una política que trae otras diez cosas.
    const d = deps({ ensureKey: vi.fn(async () => { throw new Error("privsvc caído"); }) });
    const next = await reconcileGatewayKey(d, { publishedFingerprint: null });

    expect(next.publishedFingerprint).toBeNull();
  });

  it("crea la clave aunque todavía no haya transporte para publicarla", async () => {
    // El backend llega después. La clave se crea igual; lo que no ocurre es
    // que el navegador pueda sellar contra ella todavía.
    const d = deps({ publish: undefined });
    const next = await reconcileGatewayKey(d, { publishedFingerprint: null });

    expect(d.ensureKey).toHaveBeenCalled();
    expect(next.publishedFingerprint).toBeNull();
  });

  it("se queda quieto sin deviceId en vez de inventarse uno", async () => {
    const d = deps({ deviceId: () => "" });
    await reconcileGatewayKey(d, { publishedFingerprint: null });

    expect(d.ensureKey).not.toHaveBeenCalled();
  });
});

describe("ADR-0013 (A) — que haya dónde mirar en el propio equipo", () => {
  it("⭐ anuncia la huella aunque no haya nada que publicar", async () => {
    // El caso que se escapa si se anuncia dentro del camino de publicación:
    // tras un reinicio el fichero de estado se reconstruye vacío y la huella
    // NO cambió, así que no se republica. Anunciar después dejaría sin huella
    // visible justo a los gateways estables — los que llevan meses
    // funcionando, que son para los que alguien querrá comprobarla.
    const d = deps();
    await reconcileGatewayKey(d, { publishedFingerprint: MATERIAL.fingerprintSha256 });

    expect(d.publish).not.toHaveBeenCalled();
    expect(d.announce).toHaveBeenCalledWith(MATERIAL);
  });

  it("la retira al perder el rol", async () => {
    // Una huella de una clave ya destruida es algo que comparar que no
    // corresponde a nada.
    const d = deps({ isGateway: () => false });
    await reconcileGatewayKey(d, { publishedFingerprint: "aa11" });

    expect(d.announce).toHaveBeenCalledWith(null);
  });

  it("no anuncia nada en un equipo que no es gateway", async () => {
    const d = deps({ isGateway: () => false });
    await reconcileGatewayKey(d, { publishedFingerprint: null });

    expect(d.announce).not.toHaveBeenCalled();
  });
});

describe("⭐ el formato tiene que coincidir con el del portal", () => {
  // Todo el mecanismo consiste en que una persona compare dos cadenas de 64
  // caracteres en dos pantallas. Si una sale en minúsculas y de corrido y la
  // otra en mayúsculas por pares, la comparación se abandona a la mitad y la
  // casilla vuelve a ser un trámite. Copiado literal de `formatFingerprint`
  // del portal (sealCredential.js): si divergen, esto lo caza.
  const portal = (hex) =>
    String(hex || "").toUpperCase().replace(/[^0-9A-F]/g, "").match(/../g)?.join(":") ?? "";

  it("produce exactamente lo mismo", () => {
    for (const hex of [
      "a".repeat(64),
      "0123456789abcdef".repeat(4),
      "AA:BB:cc:dd" + "0".repeat(56),
      "",
    ]) {
      expect(formatFingerprint(hex)).toBe(portal(hex));
    }
  });

  it("sale en mayúsculas y por pares", () => {
    expect(formatFingerprint("aabbcc")).toBe("AA:BB:CC");
  });

  it("no revienta con una huella ausente", () => {
    expect(formatFingerprint("")).toBe("");
  });
});
