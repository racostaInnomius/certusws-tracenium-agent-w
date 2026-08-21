// Fusión entre fuentes del inventario de software de macOS.
//
// La misma app la ven varios colectores: el bundle de /Applications, el recibo
// de pkgutil, y a veces Homebrew. Colapsarlas en una fila es el trabajo, y el
// riesgo va en las dos direcciones: dejar filas duplicadas infla el inventario,
// y fusionar de más borra datos que alimentan PMP third-party y la detección
// de CVE, que cruzan por nombre + versión.

import { describe, it, expect } from "vitest";
import { mergeMacAppsBySource } from "../../src/plugins/amp/providers/macos";
import type { SoftwareApplication } from "../../src/domain/normalize-app";

const app = (o: Partial<SoftwareApplication>): SoftwareApplication =>
  ({
    installId: `${o.source}:${o.name}`,
    name: "App",
    version: null,
    publisher: null,
    installLocation: null,
    packageFamilyName: null,
    source: "pkgutil",
    ...o,
  } as SoftwareApplication);

describe("mergeMacAppsBySource", () => {
  it("colapsa el bundle y el recibo de la misma app en una fila", () => {
    const out = mergeMacAppsBySource([
      app({
        name: "Microsoft OneNote",
        source: "macos-app-bundle",
        packageFamilyName: "com.microsoft.onenote.mac",
        installLocation: "/Applications/Microsoft OneNote.app",
      }),
      app({
        name: "com.microsoft.onenote.mac",
        source: "pkgutil",
        packageFamilyName: "com.microsoft.onenote.mac",
        version: "16.83",
      }),
    ]);

    expect(out).toHaveLength(1);
    // El bundle manda en la identidad: su nombre es el que una persona
    // reconoce, y el recibo solo repite el identificador.
    expect(out[0].name).toBe("Microsoft OneNote");
    expect(out[0].source).toBe("macos-app-bundle");
  });

  it("⚠️ CONSERVA la versión del perdedor cuando el ganador no la tiene", () => {
    // Este era el daño. La fusión hacía `set(pfn, ganador)` y el bundle gana
    // sobre pkgutil, así que la fila que sobrevivía era justo la que no traía
    // versión: las 253 filas de esta fuente en producción tenían version NULL.
    // PMP y CVE cruzan por nombre + versión, de modo que la fusión les quitaba
    // el dato con el que trabajan.
    const out = mergeMacAppsBySource([
      app({
        name: "Citrix Workspace",
        source: "macos-app-bundle",
        packageFamilyName: "com.citrix.receiver.nomas",
        version: null,
      }),
      app({
        name: "com.citrix.receiver.nomas",
        source: "pkgutil",
        packageFamilyName: "com.citrix.receiver.nomas",
        version: "24.11.0",
      }),
    ]);

    expect(out).toHaveLength(1);
    expect(out[0].name).toBe("Citrix Workspace");
    expect(out[0].version).toBe("24.11.0");
  });

  it("la versión del ganador no se pisa con la del perdedor", () => {
    // Ahora que el bundle lee su Info.plist, suele traer la suya, y es la
    // buena: el recibo puede ser de una instalación anterior.
    const out = mergeMacAppsBySource([
      app({
        name: "Citrix Workspace",
        source: "macos-app-bundle",
        packageFamilyName: "com.citrix.receiver.nomas",
        version: "25.3.0",
      }),
      app({
        name: "com.citrix.receiver.nomas",
        source: "pkgutil",
        packageFamilyName: "com.citrix.receiver.nomas",
        version: "24.11.0",
      }),
    ]);

    expect(out[0].version).toBe("25.3.0");
  });

  it("respeta la prioridad sin importar el orden de llegada", () => {
    const orden1 = mergeMacAppsBySource([
      app({ name: "brew", source: "homebrew", packageFamilyName: "x", version: "1.0" }),
      app({ name: "Bundle", source: "macos-app-bundle", packageFamilyName: "x" }),
    ]);
    const orden2 = mergeMacAppsBySource([
      app({ name: "Bundle", source: "macos-app-bundle", packageFamilyName: "x" }),
      app({ name: "brew", source: "homebrew", packageFamilyName: "x", version: "1.0" }),
    ]);

    expect(orden1[0].name).toBe("Bundle");
    expect(orden2[0].name).toBe("Bundle");
    // Y en los dos casos la versión sobrevive.
    expect(orden1[0].version).toBe("1.0");
    expect(orden2[0].version).toBe("1.0");
  });

  it("una app sin identificador NO se fusiona con nadie", () => {
    // ⚠️ Sin llave, unir por nombre juntaría cosas distintas. Una fila suelta
    // de más es mucho menos dañina que dos apps colapsadas en una.
    const out = mergeMacAppsBySource([
      app({ name: "FoxOneMX", source: "macos-app-bundle", packageFamilyName: null }),
      app({ name: "FoxOneMX", source: "pkgutil", packageFamilyName: null }),
    ]);

    expect(out).toHaveLength(2);
  });

  it("no colapsa apps distintas que comparten fuente", () => {
    const out = mergeMacAppsBySource([
      app({ name: "Pages", source: "macos-app-bundle", packageFamilyName: "com.apple.pages" }),
      app({ name: "Keynote", source: "macos-app-bundle", packageFamilyName: "com.apple.keynote" }),
    ]);

    expect(out).toHaveLength(2);
  });

  it("ignora las entradas sin installId, que no son inventario", () => {
    const out = mergeMacAppsBySource([
      app({ name: "Sin id", installId: undefined as any, packageFamilyName: "y" }),
      app({ name: "Con id", packageFamilyName: "z" }),
    ]);

    expect(out).toHaveLength(1);
    expect(out[0].name).toBe("Con id");
  });

  it("no pierde apps cuando no hay nada que fusionar", () => {
    const entrada = [
      app({ name: "A", packageFamilyName: "a" }),
      app({ name: "B", packageFamilyName: "b" }),
      app({ name: "C", packageFamilyName: null }),
    ];
    expect(mergeMacAppsBySource(entrada)).toHaveLength(3);
    expect(mergeMacAppsBySource([])).toEqual([]);
  });
});
