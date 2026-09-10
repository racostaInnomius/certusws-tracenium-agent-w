import { describe, it, expect } from "vitest";
import { normalizeApp } from "../../src/domain/normalize-app";
import { computeSoftwareDelta } from "../../src/domain/software-inventory-delta";

// ADR-0019 F0 — el CUARTO caso del mismo patrón, después de `uptimeSeconds`
// (ver boot-time.test.ts), `antivirus.products` y las impresoras de Windows.
//
// El colector de Windows emitía `uninstallString`, `quietUninstallString`,
// `productCode` y `uninstallKeyPath` desde 1.1.65. Con 52 equipos ya corriendo
// esa versión, las cuatro columnas del backend seguían en CERO ABSOLUTO: 0 de
// las 2.088 filas win32 de T111.
//
// El dato se caía en TRES listas explícitas del lado TypeScript —el tipo
// `RawApp`, el objeto que se le pasa a `normalizeApp`, y el que `normalizeApp`
// devuelve— y ninguna de las tres da error al olvidarse de un campo. Estos
// tests son el detector que no existía.

const CHROME = {
  name: "Google Chrome",
  version: "129.0.6668.71",
  publisher: "Google LLC",
  source: "win32-registry",
  uninstallString: '"C:\\Program Files\\Google\\Chrome\\Application\\setup.exe" --uninstall',
  quietUninstallString: '"C:\\Program Files\\Google\\Chrome\\Application\\setup.exe" --uninstall --force-uninstall',
  productCode: "{D73883EB-7167-37B2-A69C-06A4744F64D2}",
  uninstallKeyPath: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome"
};

describe("la identidad sobrevive al normalizador", () => {
  it("los cuatro campos llegan a la salida", () => {
    const app = normalizeApp(CHROME)!;
    expect(app.productCode).toBe("{D73883EB-7167-37B2-A69C-06A4744F64D2}");
    expect(app.uninstallKeyPath).toContain("HKLM\\SOFTWARE");
    expect(app.uninstallString).toContain("--uninstall");
    expect(app.quietUninstallString).toContain("--force-uninstall");
  });

  it("⚠️ NO se limpian ni se normalizan: se ejecutan literalmente", () => {
    // Un `UninstallString` lleva comillas y rutas con espacios que hay que
    // pasar EXACTAMENTE como el instalador las registró, y un ProductCode es
    // un GUID que sólo vale entero. Recortarlo o pasarlo a minúsculas para
    // «limpiarlo» rompería el comando sin que nada avise.
    const app = normalizeApp(CHROME)!;
    expect(app.uninstallString).toBe(CHROME.uninstallString);
    expect(app.productCode).toBe(CHROME.productCode);
  });

  it("los orígenes que no son de Windows los dejan sin poner", () => {
    // Ausencia es la respuesta correcta, no un hueco: «no sabemos cómo
    // quitarlo». Y `undefined`, no `null`, para no plantar nulos en campos
    // opcionales.
    const app = normalizeApp({ name: "GarageBand", source: "macos-app-bundle" })!;
    expect(app.productCode).toBeUndefined();
    expect(app.uninstallString).toBeUndefined();
  });
});

describe("⚠️ y sobrevive al delta, que es donde el arreglo se volvía inerte", () => {
  const sinIdentidad = normalizeApp({
    name: "Google Chrome",
    version: "129.0.6668.71",
    publisher: "Google LLC",
    source: "win32-registry"
  })!;
  const conIdentidad = normalizeApp(CHROME)!;

  it("estrenar identidad cuenta como cambio, aunque no cambie nada más", () => {
    // ESTE es el test que hace que publicar el agente sirva de algo.
    //
    // El baseline vive en SQLite en el equipo y sólo se manda entero en la
    // PRIMERA ejecución; después siempre delta. En la primera corrida tras
    // actualizar, la app tiene la MISMA versión, editor, ruta y package family
    // que antes — lo único que cambia es que ahora trae identidad.
    //
    // Si el delta no mira esos campos, `hasChanges` es false, no se manda
    // nada, y las columnas del backend se quedan vacías hasta que alguna app
    // cambie de versión por su cuenta. Es decir: indefinidamente.
    const r = computeSoftwareDelta([conIdentidad], [sinIdentidad]);
    expect(r.hasChanges).toBe(true);
    expect(r.delta?.updated?.map((a) => a.name)).toEqual(["Google Chrome"]);
    // Y viaja con la identidad puesta, que es lo que el backend va a escribir.
    expect(r.delta?.updated?.[0]?.productCode).toBe(CHROME.productCode);
  });

  it("un ProductCode distinto tras un upgrade también es un cambio", () => {
    // No es sólo cosa de la migración: un upgrade de producto cambia el
    // ProductCode sin tocar nada de lo que el delta miraba antes. Sin esto la
    // identidad guardada se queda obsoleta en silencio — y `msiexec /x` con un
    // GUID viejo no falla: quita otra cosa, o nada.
    const nuevo = normalizeApp({ ...CHROME, productCode: "{11111111-2222-3333-4444-555555555555}" })!;
    expect(computeSoftwareDelta([nuevo], [conIdentidad]).hasChanges).toBe(true);
  });

  it("pero dos inventarios idénticos siguen sin producir delta", () => {
    // El contrapeso: si cualquier diferencia contase, cada ciclo mandaría la
    // flota entera. La comparación se añadió para destapar un cambio real, no
    // para desactivar el filtro.
    const otro = normalizeApp(CHROME)!;
    expect(computeSoftwareDelta([otro], [conIdentidad]).hasChanges).toBe(false);
  });

  it("y una app de macOS, sin identidad en ninguno de los dos lados, tampoco", () => {
    const mac = normalizeApp({ name: "GarageBand", version: "10.4", source: "macos-app-bundle" })!;
    const mac2 = normalizeApp({ name: "GarageBand", version: "10.4", source: "macos-app-bundle" })!;
    expect(computeSoftwareDelta([mac2], [mac]).hasChanges).toBe(false);
  });
});
