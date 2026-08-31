// test/privsvc/linux-consent-parse.test.ts
//
// parseDecision decide si alguien puede usar el equipo de otra persona a
// partir de una línea de texto. Todos sus caminos de error tienen que caer
// del mismo lado: un diálogo que no funcionó NO puede convertirse en un
// permiso concedido.

import { describe, it, expect } from "vitest";
import { parseDecision } from "../../privsvc/linux/src/consent-dialog";

describe("parseDecision", () => {
  it("lee las tres decisiones legítimas", () => {
    expect(parseDecision('{"ok":true,"decision":"approved"}')).toBe("approved");
    expect(parseDecision('{"ok":true,"decision":"denied"}')).toBe("denied");
    expect(parseDecision('{"ok":true,"decision":"timeout"}')).toBe("timeout");
  });

  it("una línea vacía deniega", () => {
    // El helper murió antes de contestar.
    expect(parseDecision("")).toBe("denied");
  });

  it("JSON corrupto deniega", () => {
    expect(parseDecision("{esto no es json")).toBe("denied");
  });

  it("un error del helper deniega", () => {
    expect(parseDecision('{"ok":false,"code":"consent_window_failed"}')).toBe("denied");
  });

  it("una decisión desconocida deniega", () => {
    // Un helper más nuevo que invente un valor no puede conceder acceso por
    // el mero hecho de que esta versión no lo entienda.
    expect(parseDecision('{"ok":true,"decision":"maybe"}')).toBe("denied");
  });

  it("un 'true' suelto no cuela como aprobación", () => {
    expect(parseDecision('{"ok":true}')).toBe("denied");
    expect(parseDecision("true")).toBe("denied");
  });
});
