// La decisión de tocar (o no tocar) el consentimiento de ubicación de la cuenta
// de servicio es lo que no puede regresionar: es una escritura al registro de
// una máquina ajena, disparada por una policy remota. Está extraída como
// función pura para poder fijar toda la tabla de decisión sin registro.

import { describe, it, expect } from "vitest";
import {
  parseRegValue,
  planConsent,
  applyWindowsLocationConsent,
} from "../../src/plugins/amp/providers/windows-location-consent";

describe("parseRegValue", () => {
  it("extrae el valor de la salida real de reg query", () => {
    const out = [
      "",
      "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location",
      "    Value    REG_SZ    Allow",
      "",
    ].join("\r\n");
    expect(parseRegValue(out)).toBe("Allow");
  });

  it("distingue Deny de Allow", () => {
    expect(parseRegValue("    Value    REG_SZ    Deny")).toBe("Deny");
  });

  it("devuelve null cuando la clave o el valor no existen", () => {
    // Ausente NO es lo mismo que Deny: nadie expresó preferencia, y eso cambia
    // qué restauramos después.
    expect(parseRegValue("")).toBeNull();
    expect(parseRegValue("ERROR: El sistema no puede encontrar la clave")).toBeNull();
    expect(parseRegValue(undefined)).toBeNull();
  });

  it("no confunde un valor de nombre parecido", () => {
    expect(parseRegValue("    ValueOtra    REG_SZ    Allow")).toBeNull();
  });
});

describe("planConsent — encender", () => {
  it("no hace nada si ya está concedido", () => {
    expect(planConsent(true, "Allow", undefined)).toEqual({ action: "none", reason: "already allowed" });
  });

  it("concede y recuerda el Deny que había", () => {
    expect(planConsent(true, "Deny", undefined)).toEqual({
      action: "set", value: "Allow", remember: "Deny",
    });
  });

  it("concede y recuerda que NO había valor", () => {
    // Recordar `null` es lo que después permite borrarlo en vez de escribir un
    // Deny que nadie había puesto.
    expect(planConsent(true, null, undefined)).toEqual({
      action: "set", value: "Allow", remember: null,
    });
  });
});

describe("planConsent — apagar", () => {
  it("devuelve el valor previo que nosotros pisamos", () => {
    expect(planConsent(false, "Allow", "Deny")).toEqual({ action: "restore", value: "Deny" });
  });

  it("borra el valor si antes no existía", () => {
    expect(planConsent(false, "Allow", null)).toEqual({ action: "clear" });
  });

  it("NO toca nada que no hayamos puesto nosotros", () => {
    // El caso que importa: un admin con Allow deliberado no puede quedar en
    // Deny porque alguien apagó nuestra feature. Apagar no es licencia para
    // reescribir la máquina.
    expect(planConsent(false, "Allow", undefined)).toEqual({ action: "none", reason: "not set by us" });
    expect(planConsent(false, "Deny", undefined)).toEqual({ action: "none", reason: "not set by us" });
  });
});

describe("applyWindowsLocationConsent", () => {
  it("es no-op fuera de Windows", async () => {
    // macOS y Linux no tienen esta compuerta; tocar el registro ahí no existe.
    expect(await applyWindowsLocationConsent(true, "darwin")).toBeNull();
    expect(await applyWindowsLocationConsent(true, "linux")).toBeNull();
  });
});
