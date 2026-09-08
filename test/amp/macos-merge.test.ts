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

  it("dos apps DE VERDAD con el mismo nombre siguen siendo dos filas", () => {
    // ⚠️ La mitad que sigue en pie de la regla original: sin llave, unir por
    // nombre juntaría cosas distintas, y una fila suelta de más es mucho menos
    // dañina que dos apps colapsadas en una. Ninguna de estas dos es un
    // recibo, así que nada las toca.
    const out = mergeMacAppsBySource([
      app({ name: "FoxOneMX", source: "macos-app-bundle", packageFamilyName: null }),
      app({ name: "FoxOneMX", source: "homebrew", packageFamilyName: null }),
    ]);

    expect(out).toHaveLength(2);
  });

  it("⚠️ pero una app y su RECIBO con el mismo nombre sí se colapsan", () => {
    // Aquí la regla anterior decía 2, y el campo demostró que se equivocaba:
    // `pkgutil` no lista lo instalado, lista recibos de instalación, y macOS
    // los guarda para siempre. Medido en el tenant 1 el 08-sep, 8 Macs daban
    // 24 filas de "Numbers" con 15 versiones. Que uno de los dos lados sea un
    // recibo es lo que hace segura la unión por nombre; sin esa condición,
    // el test de arriba sigue mandando.
    const out = mergeMacAppsBySource([
      app({ name: "FoxOneMX", source: "macos-app-bundle", packageFamilyName: null }),
      app({ name: "FoxOneMX", source: "pkgutil", packageFamilyName: null }),
    ]);

    expect(out).toHaveLength(1);
    expect(out[0].source).toBe("macos-app-bundle");
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

  // ─────────────────────────────────────────────────────────────────────
  // Los tres casos reales de producción (tenant 1, 08-sep).
  // ─────────────────────────────────────────────────────────────────────
  it("⚠️ Numbers: un bundle y seis recibos de Apple quedan en UNA fila", () => {
    // Apple versiona el identificador del recibo —Numbers10…Numbers15—, así
    // que la fusión por packageFamilyName no podía unir absolutamente nada:
    // los seis ids son distintos entre sí y distintos del bundle.
    const out = mergeMacAppsBySource([
      app({ name: "Numbers", source: "macos-app-bundle", packageFamilyName: "com.apple.iWork.Numbers", version: "14.5" }),
      app({ name: "Numbers", source: "pkgutil", packageFamilyName: "com.apple.pkg.Numbers10", version: "10.3.9.0.1.1610096085" }),
      app({ name: "Numbers", source: "pkgutil", packageFamilyName: "com.apple.pkg.Numbers11", version: "11.2.1.1631719887" }),
      app({ name: "Numbers", source: "pkgutil", packageFamilyName: "com.apple.pkg.Numbers12", version: "12.1.1.1667669062" }),
      app({ name: "Numbers", source: "pkgutil", packageFamilyName: "com.apple.pkg.Numbers13", version: "13.2.1.1694639406" }),
      app({ name: "Numbers", source: "pkgutil", packageFamilyName: "com.apple.pkg.Numbers14", version: "14.5.1.1761239430" }),
      app({ name: "Numbers", source: "pkgutil", packageFamilyName: "com.apple.pkg.Numbers15", version: "15.3.1.1.1785016684" }),
    ]);

    expect(out).toHaveLength(1);
    expect(out[0].source).toBe("macos-app-bundle");
    // La versión de la app real gana sobre la del recibo: 14.5 es lo que
    // ejecuta el usuario, 14.5.1.1761239430 es la versión del paquete.
    expect(out[0].version).toBe("14.5");
  });

  it("Microsoft PowerPoint: el recibo tiene otro id y aun así se une", () => {
    const out = mergeMacAppsBySource([
      app({ name: "Microsoft PowerPoint", source: "macos-app-bundle", packageFamilyName: "com.microsoft.Powerpoint", version: "16.112.2" }),
      app({ name: "Microsoft PowerPoint", source: "pkgutil", packageFamilyName: "com.microsoft.package.Microsoft_PowerPoint.app", version: "16.112.26083020" }),
    ]);

    expect(out).toHaveLength(1);
    expect(out[0].version).toBe("16.112.2");
  });

  it("Epson: nueve subpaquetes de un mismo driver quedan en uno, el más nuevo", () => {
    // Sin app de verdad detrás: sobrevive el recibo, y el que sobrevive es el
    // de versión más alta.
    const out = mergeMacAppsBySource([
      app({ name: "Epson Inkjet Printer Driver", source: "pkgutil", packageFamilyName: "com.epson.pkg.ijpdrv.remoteprint.w.Machine_106_and_later", version: "12.64" }),
      app({ name: "Epson Inkjet Printer Driver", source: "pkgutil", packageFamilyName: "com.epson.pkg.ijpdrv.et-1110series.w.Module_110_and_later", version: "13.26" }),
      app({ name: "Epson Inkjet Printer Driver", source: "pkgutil", packageFamilyName: "com.epson.pkg.ijpdrv.sc-p5000series.a.Machine_106_and_later", version: "13.26" }),
    ]);

    expect(out).toHaveLength(1);
    expect(out[0].version).toBe("13.26");
  });

  it("⚠️ un recibo SIN app detrás no se pierde: es software real", () => {
    // 259 de las 329 filas de pkgutil del tenant 1 son lo único que se sabe
    // de ese software —drivers, kexts, herramientas sin .app—. Colapsar no
    // puede convertirse en descartar.
    const out = mergeMacAppsBySource([
      app({ name: "Rosetta", source: "pkgutil", packageFamilyName: "com.apple.pkg.RosettaUpdateAuto", version: "2.0" }),
    ]);

    expect(out).toHaveLength(1);
    expect(out[0].name).toBe("Rosetta");
  });

  it("el resultado no depende del orden de entrada, tampoco con recibos", () => {
    const entrada = [
      app({ name: "Numbers", source: "pkgutil", packageFamilyName: "com.apple.pkg.Numbers13", version: "13.2.1.1694639406" }),
      app({ name: "Numbers", source: "pkgutil", packageFamilyName: "com.apple.pkg.Numbers14", version: "14.5.1.1761239430" }),
      app({ name: "Numbers", source: "macos-app-bundle", packageFamilyName: "com.apple.iWork.Numbers", version: "14.5" }),
    ];

    const a = mergeMacAppsBySource([...entrada]);
    const b = mergeMacAppsBySource([...entrada].reverse());

    expect(a).toHaveLength(1);
    expect(a[0].installId).toBe(b[0].installId);
    expect(a[0].version).toBe(b[0].version);
  });
});
