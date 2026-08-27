// test/security/effective-mode-entitlement.test.ts
//
// F2 del plan de gates por tier — el cinturón del agente.
//
// El enforcer hace DOS cosas y sólo una depende del plan: leer estado y
// reportar drift es compliance (SCP / professional), pero ESCRIBIR en el
// endpoint vía `pmp.remediate` cuando el modo es `auto` es remediación, y eso
// lo habilita PMP (enterprise).
//
// Por eso el corte está en el resolutor de modo y no en el pase: degradar
// `auto` → `report-only` deja viva la detección. Bajarlo a `off`, o apagar
// `runSecurityEnforce`, le quitaría al tenant algo que sí ha pagado.
//
// Es defensa en profundidad: el backend ya degrada el modo al proyectar la
// política (policies.service::applyEntitlements), así que en condiciones
// normales aquí nunca llega un `auto` sin derecho. Si llega, es que aquel
// cierre falló — y el enforcer lo registra.

import { describe, it, expect } from "vitest";
import { effectiveMode } from "../../src/security/enforcer";

const NO_DEFAULT = {} as any;

describe("effectiveMode — cascada original (sin tocar)", () => {
  it("el modo de la capacidad gana al defaultMode", () => {
    expect(effectiveMode({ mode: "off" }, { defaultMode: "auto" } as any, true)).toBe("off");
    expect(effectiveMode({ mode: "auto" }, { defaultMode: "off" } as any, true)).toBe("auto");
  });

  it("sin modo propio hereda defaultMode", () => {
    expect(effectiveMode({}, { defaultMode: "auto" } as any, true)).toBe("auto");
  });

  it("sin nada, el suelo es report-only", () => {
    expect(effectiveMode({}, NO_DEFAULT, true)).toBe("report-only");
    expect(effectiveMode(null, NO_DEFAULT, true)).toBe("report-only");
  });

  it("un modo inválido no se propaga: cae al suelo", () => {
    expect(effectiveMode({ mode: "AUTO" }, NO_DEFAULT, true)).toBe("report-only");
    expect(effectiveMode({ mode: "sí" }, NO_DEFAULT, true)).toBe("report-only");
  });
});

describe("effectiveMode — gate de PMP", () => {
  it("sin derecho, `auto` cae a report-only y NO a off", () => {
    // El matiz que sostiene la decisión de producto: professional conserva la
    // detección de drift, sólo pierde la escritura.
    expect(effectiveMode({ mode: "auto" }, NO_DEFAULT, false)).toBe("report-only");
    expect(effectiveMode({ mode: "auto" }, NO_DEFAULT, false)).not.toBe("off");
  });

  it("sin derecho, un defaultMode auto también se degrada", () => {
    expect(effectiveMode({}, { defaultMode: "auto" } as any, false)).toBe("report-only");
  });

  it("sin derecho, `off` sigue siendo `off`", () => {
    // Degradar sólo aplica a auto; apagar es una decisión del operador que el
    // plan no tiene por qué revertir.
    expect(effectiveMode({ mode: "off" }, NO_DEFAULT, false)).toBe("off");
  });

  it("sin derecho, report-only no cambia", () => {
    expect(effectiveMode({ mode: "report-only" }, NO_DEFAULT, false)).toBe("report-only");
  });

  it("con derecho, `auto` se respeta", () => {
    expect(effectiveMode({ mode: "auto" }, NO_DEFAULT, true)).toBe("auto");
  });

  it("por defecto permite remediar — el parámetro es opt-in", () => {
    // Si alguien añade un llamador y olvida el tercer argumento, el
    // comportamiento no cambia respecto a antes de F2. El cierre que de verdad
    // protege el parque es el del backend, no éste.
    expect(effectiveMode({ mode: "auto" }, NO_DEFAULT)).toBe("auto");
  });
});
