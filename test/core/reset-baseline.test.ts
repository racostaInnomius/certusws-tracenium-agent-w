import { describe, it, expect } from "vitest";
import { AMP_BASELINE_SCOPES, planResetBaseline } from "../../src/core/reset-baseline";

// Qué limpia un `reset_baseline`. El caso que importa es el segundo: el
// autorreparador de extensiones pedía la foto de extensiones y el agente tiraba
// también la de software e impresoras (14-sep, 34 equipos de T111).

describe("planResetBaseline", () => {
  it("sin scopes (backend anterior) limpia las tres, como siempre", () => {
    for (const payload of [{ namespace: "amp" }, { namespace: "AMP", scopes: null }]) {
      expect(planResetBaseline(payload)).toEqual({ ok: true, namespace: "amp", scopes: [...AMP_BASELINE_SCOPES] });
    }
  });

  it("⭐ con scopes limpia SÓLO lo pedido", () => {
    expect(planResetBaseline({ namespace: "amp", scopes: ["browserExtensions"] })).toEqual({
      ok: true,
      namespace: "amp",
      scopes: ["browserExtensions"],
    });
    expect(planResetBaseline({ namespace: "amp", scopes: ["software"] })).toMatchObject({ scopes: ["software"] });
  });

  it("orden canónico y sin repetidos", () => {
    expect(planResetBaseline({ namespace: "amp", scopes: ["browserExtensions", "software", "software"] })).toMatchObject({
      scopes: ["software", "browserExtensions"],
    });
  });

  it("⚠️ scopes vacío o no-array se rechaza: ni «todas» ni «ninguna»", () => {
    for (const scopes of [[], "software", { software: true }]) {
      const plan = planResetBaseline({ namespace: "amp", scopes });
      expect(plan.ok, JSON.stringify(scopes)).toBe(false);
    }
  });

  it("⚠️ un alcance desconocido rechaza el job entero y lo nombra", () => {
    const plan = planResetBaseline({ namespace: "amp", scopes: ["software", "certificates"] });
    expect(plan).toEqual({ ok: false, message: 'reset_baseline rejected: unsupported scopes "certificates"' });
  });

  it("un namespace que no es amp se rechaza como antes", () => {
    expect(planResetBaseline({ namespace: "scp" })).toEqual({
      ok: false,
      message: 'reset_baseline rejected: unsupported namespace "scp"',
    });
    expect(planResetBaseline(undefined).ok).toBe(false);
  });
});

describe("el handler de reset_baseline usa el plan", () => {
  // Lectura del FUENTE, como cdp-job-routing.test.ts: montar el stream para un
  // job de tres líneas es desproporcionado, y el fallo a evitar es concreto —
  // volver a llamar a los tres `clear*` sin mirar `scopes`.
  const fs = require("fs");
  const path = require("path");
  const fuente: string = fs.readFileSync(path.join(__dirname, "../../src/transport/grpc-stream.ts"), "utf8");
  const inicio = fuente.indexOf('case "reset_baseline"');
  const fin = fuente.indexOf("\n    case ", inicio + 10);
  const cuerpo = fuente.slice(inicio, fin);

  it("limpia recorriendo plan.scopes y rechaza lo que el plan rechaza", () => {
    expect(inicio).toBeGreaterThan(0);
    expect(cuerpo).toContain("planResetBaseline(payload)");
    expect(cuerpo).toMatch(/if \(!plan\.ok\)[\s\S]*status: 2/);
    expect(cuerpo).toMatch(/for \(const scope of plan\.scopes\) clearers\[scope\]\(\)/);
  });

  it("⚠️ ningún clear* se llama suelto, fuera del recorrido", () => {
    for (const fn of ["clearSoftwareBaseline", "clearPrinterBaseline", "clearBrowserExtensionBaseline"]) {
      expect(cuerpo, fn).not.toMatch(new RegExp(`\\b${fn}\\(\\)`));
    }
  });
});
