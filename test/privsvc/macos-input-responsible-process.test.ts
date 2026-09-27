// test/privsvc/macos-input-responsible-process.test.ts
//
// 🔴 «"node" would like to control this Mac and access your data».
//
// Reporte del usuario (27-sep-2026): al tomar el control de un Mac, el diálogo
// del sistema pedía Accesibilidad para **node**, y en Ajustes › Control del
// dispositivo aparecía `node` en la lista.
//
// ── La asimetría que lo explica ──────────────────────────────────────
//
// Grabación de Pantalla y Accesibilidad NO se atribuyen igual en macOS:
//
//   · Grabación de Pantalla → identidad del BINARIO. Por eso la captura sale
//     correctamente como «Tracenium Screen Helper».
//   · Accesibilidad       → **responsible process**, o sea quien te lanzó. Y a
//     este helper lo lanza el PrivSvc de macOS, que es Node.
//
// Mismo binario, misma ruta, el mismo `launchctl asuser sudo` para los dos
// modos — y aun así uno sale bien y el otro no. Sin esta nota, la siguiente
// persona que lo mire buscará la diferencia en el lanzador, que no la tiene.
//
// ── Por qué el arreglo vive en el helper ─────────────────────────────
//
// A la responsabilidad heredada sólo se puede renunciar EN EL MOMENTO DE
// NACER, así que no basta con cambiar cómo nos llaman: hace falta un proceso
// nuevo. El helper se relanza a sí mismo una vez con
// `responsibility_spawnattrs_setdisclaim`. `posix_spawn` hereda 0/1/2, así que
// el canal de stdin/stdout que el PrivSvc ya tiene abierto sigue siendo el
// mismo y el lado Node no se entera de nada.
//
// Se comprueba por escáner de fuentes: la atribución sólo se puede confirmar
// mirando Ajustes en un Mac después de una sesión de control, y eso no cabe en
// una prueba.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";

const SRC = path.resolve(__dirname, "../../privsvc/macos/helpers/screencap/main.swift");
const text = readFileSync(SRC, "utf8");

function codeOnly(s: string): string {
  return s
    .split("\n")
    .filter((l) => {
      const x = l.trimStart();
      return !x.startsWith("//") && !x.startsWith("///") && !x.startsWith("*");
    })
    .join("\n");
}

describe("la renuncia de responsabilidad vale para TODOS los modos", () => {
  const lines = text.split("\n");
  const at = (pred: (l: string) => boolean) => lines.findIndex(pred);

  const fnAt = at((l) => l.startsWith("private func reexecDisclaimed() {"));
  const callAt = at((l) => l.trim() === "reexecDisclaimed()");
  const tccAt = at((l) => l.startsWith('if CommandLine.arguments.contains("--tcc-status")'));
  const serveAt = at((l) => l.startsWith('if CommandLine.arguments.contains("--input-serve")'));

  it("la función existe, se llama, y los modos vienen DESPUÉS", () => {
    expect(fnAt, "ya no existe reexecDisclaimed").toBeGreaterThan(-1);
    expect(callAt, "nadie la llama").toBeGreaterThan(-1);
    expect(
      callAt,
      "los modos se atienden antes de renunciar: los que salen con exit() "
        + "—TCC e --input-serve— nunca llegarían a hacerlo, que es exactamente "
        + "el bug que pedía Accesibilidad a nombre de node",
    ).toBeLessThan(tccAt);
    expect(callAt).toBeLessThan(serveAt);
  });

  it("⚠️ y los modos NO están dentro del cuerpo de la función", () => {
    // Así estaba: la llave se cerraba 190 líneas más abajo y se tragaba los
    // dos modos. Compila igual, y sólo la captura —el único camino que llega
    // al final— acababa renunciando.
    expect(
      tccAt,
      "el modo TCC volvió a caer dentro de reexecDisclaimed()",
    ).toBeGreaterThan(callAt);
    expect(serveAt).toBeGreaterThan(callAt);
  });

  it("se relanza UNA vez, con marca de entorno", () => {
    expect(text).toContain('TRACENIUM_SCREENCAP_DISCLAIMED');
  });

  it("⚠️ hereda los descriptores: el canal con el PrivSvc no se rompe", () => {
    // Sin file_actions, posix_spawn hereda 0/1/2. Pasarlos cerraría el stdin
    // que el PrivSvc ya tiene abierto y el control dejaría de responder — un
    // fallo peor que el de atribución.
    const fn = text.slice(text.indexOf("private func reexecDisclaimed"));
    expect(fn.slice(0, 3000)).toContain("posix_spawn(&pid, exePath, nil, &attrs");
  });

  it("⚠️ si no se puede renunciar, el helper SIGUE funcionando", () => {
    // Una atribución fea es mejor que un helper que no arranca: sin él no hay
    // ni captura ni control.
    const fn = text.slice(text.indexOf("private func reexecDisclaimed"));
    const upTo = fn.slice(0, fn.indexOf("reexecDisclaimed()", 40));
    expect(upTo).toContain("dlsym");
    expect(upTo).not.toContain("fatalError");
    expect((upTo.match(/return$/gm) ?? []).length).toBeGreaterThanOrEqual(3);
  });
});
