// test/plugins/rcp-recording-policy.test.ts
//
// El flag de grabación lo leen DOS sitios que no pueden discrepar: el texto
// del consentimiento y el indicador permanente. Discrepar significa enseñar un
// diálogo que no menciona la grabación y grabar igualmente — o al revés.
//
// Y su valor por defecto es lo único que separa "un tenant decidió grabar" de
// "hay vídeo de las pantallas de sus usuarios porque nadie miró el ajuste".

import { describe, it, expect } from "vitest";
import { recordingEnabled } from "../../src/plugins/rcp/recording-policy";
import { consentLines } from "../../src/plugins/rcp/consent-text";

const ctxWith = (value: unknown): any => ({
  policyRuntime: { isFeatureEnabled: (f: string) => (f === "remoteRecordScreen" ? value : false) }
});

describe("recordingEnabled", () => {
  it("true cuando el tenant lo activó", () => {
    expect(recordingEnabled(ctxWith(true))).toBe(true);
  });

  it("false cuando está apagado", () => {
    expect(recordingEnabled(ctxWith(false))).toBe(false);
  });

  it("sin policyRuntime, NO se graba", () => {
    // La dirección segura: la alternativa sería guardar vídeo de la pantalla
    // de alguien por no haber podido leer un fichero.
    expect(recordingEnabled({} as any)).toBe(false);
  });

  it("si isFeatureEnabled LANZA, no se graba", () => {
    const ctx: any = { policyRuntime: { isFeatureEnabled: () => { throw new Error("boom"); } } };
    expect(recordingEnabled(ctx)).toBe(false);
  });

  it("un valor no booleano no enciende la grabación por accidente", () => {
    expect(recordingEnabled(ctxWith(undefined))).toBe(false);
    expect(recordingEnabled(ctxWith(null))).toBe(false);
  });
});

describe("el diálogo y la grabación van juntos", () => {
  it("con grabación activa, el texto la menciona", () => {
    const t = consentLines({ kind: "view", recording: recordingEnabled(ctxWith(true)) }).join(" ");
    expect(t).toContain("recorded");
  });

  it("con grabación apagada, el texto NO la menciona", () => {
    const t = consentLines({ kind: "view", recording: recordingEnabled(ctxWith(false)) }).join(" ");
    expect(t).not.toContain("recorded");
  });
});
