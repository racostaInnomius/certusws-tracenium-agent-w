// test/plugins/patch-selection.test.ts
//
// Una lista vacía de parches, para el script de Windows Update de un privsvc
// viejo, es «instala TODO». El 8-sep-2026 así se instalaron 3 actualizaciones
// que nadie había elegido. El agente se actualiza antes que el MSI, así que
// esta barrera es la que protege a los equipos con el privsvc viejo.

import { describe, expect, it } from "vitest";
import fs from "fs";
import path from "path";
import { selectedPatchIds } from "../../src/plugins/pmp/patch-selection";

describe("selectedPatchIds", () => {
  it("devuelve la lista limpia", () => {
    expect(selectedPatchIds({ kbArticleIds: [" KB5122882 ", "KB5126149"] })).toEqual(["KB5122882", "KB5126149"]);
  });

  it("🔴 vacía, ausente, nula, no-lista, o sólo huecos → null, NUNCA []", () => {
    for (const p of [{ kbArticleIds: [] }, {}, null, undefined, { kbArticleIds: "KB1" }, { kbArticleIds: ["", "  ", null] }]) {
      // `[]` es exactamente el valor que el script viejo convierte en «todo».
      expect(selectedPatchIds(p)).toBeNull();
    }
  });

  it("acepta nombres de paquete (Linux, macOS)", () => {
    expect(selectedPatchIds({ kbArticleIds: ["openssl"] })).toEqual(["openssl"]);
  });
});

describe("⚠️ el manejador de patch_install rechaza antes de llamar al privsvc", () => {
  // Guarda de regresión barata sobre grpc-stream.ts, que no tiene test de
  // manejador: el rechazo tiene que ir ANTES de `patch.install`.
  it("el rechazo aparece antes que la llamada al privsvc", () => {
    const src = fs.readFileSync(path.join(__dirname, "../../src/transport/grpc-stream.ts"), "utf8");
    const rechazo = src.indexOf("patch_install rejected: no_patches_selected");
    const llamada = src.indexOf('method: "patch.install"');
    expect(rechazo).toBeGreaterThan(0);
    expect(llamada).toBeGreaterThan(rechazo);
  });
});
