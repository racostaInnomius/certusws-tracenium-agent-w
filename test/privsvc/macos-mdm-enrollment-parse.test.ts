// test/privsvc/macos-mdm-enrollment-parse.test.ts
//
// Cobertura del parser de `profiles status -type enrollment`.
//
// Por qué importa más de lo que parece: este parser alimenta la DETECCIÓN
// DE TAMPER. En el segmento no supervisado el usuario puede eliminar el
// perfil MDM y llevarse la política con él; enterarse depende de leer
// bien esta salida. Y el texto exacto ha cambiado entre versiones de
// macOS, así que el parser es tolerante a propósito — y por eso se fija
// aquí: "no lo pude determinar" NUNCA debe colapsar a "no enrolado", que
// produciría alertas de tamper falsas.

import { describe, it, expect } from "vitest";
import { parseEnrollmentStatus } from "../../privsvc/macos/src/mdm-state";

describe("parseEnrollmentStatus", () => {
  it("detecta enrolamiento aprobado por el usuario (UAMDM, sin DEP)", () => {
    const out = parseEnrollmentStatus(
      ["Enrolled via DEP: No", "MDM enrollment: Yes (User Approved)"].join("\n")
    );
    expect(out).toEqual({
      enrolled: true,
      userApproved: true,
      supervised: false,
      determined: true,
    });
  });

  it("detecta enrolamiento por DEP (supervisado)", () => {
    const out = parseEnrollmentStatus(
      ["Enrolled via DEP: Yes", "MDM enrollment: Yes"].join("\n")
    );
    expect(out.enrolled).toBe(true);
    expect(out.supervised).toBe(true);
    // Enrolado por DEP pero la línea no dice "User Approved".
    expect(out.userApproved).toBe(false);
    expect(out.determined).toBe(true);
  });

  it("detecta equipo NO enrolado", () => {
    const out = parseEnrollmentStatus(
      ["Enrolled via DEP: No", "MDM enrollment: No"].join("\n")
    );
    expect(out.enrolled).toBe(false);
    expect(out.userApproved).toBeNull();
    expect(out.determined).toBe(true);
  });

  it("salida vacía ⇒ INDETERMINADO, no 'no enrolado'", () => {
    // La distinción es la que evita alertas de tamper falsas.
    for (const input of ["", "   ", "\n"]) {
      const out = parseEnrollmentStatus(input);
      expect(out.determined).toBe(false);
      expect(out.enrolled).toBe(false);
    }
  });

  it("formato irreconocible ⇒ INDETERMINADO", () => {
    const out = parseEnrollmentStatus("algo totalmente distinto\nsin las claves esperadas");
    expect(out.determined).toBe(false);
  });

  it("es tolerante a mayúsculas y espaciado variable", () => {
    const out = parseEnrollmentStatus("mdm enrollment:   YES (user approved)");
    expect(out.enrolled).toBe(true);
    expect(out.userApproved).toBe(true);
    // Sin línea DEP no se puede afirmar la supervisión.
    expect(out.supervised).toBeNull();
  });

  it("no confunde 'No' dentro de otras palabras", () => {
    const out = parseEnrollmentStatus("MDM enrollment: Yes (User Approved)");
    expect(out.enrolled).toBe(true);
  });
});
