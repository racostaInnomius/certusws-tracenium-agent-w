// Identidad y versión de un .app, leídas del bundle y no de Spotlight.
//
// El colector no se puede ejercitar sin una Mac, pero la decisión de qué campo
// gana sí — y es donde estaba el daño: la fuente de mayor prioridad entregaba
// las 253 filas de producción con version NULL, y sin bundle id en los equipos
// donde Spotlight no resolvía.

import { describe, it, expect } from "vitest";
import { parseBundleInfo } from "../../src/domain/macos-bundle-info";

const plist = (o: Record<string, unknown>) => JSON.stringify(o);

describe("parseBundleInfo", () => {
  it("saca identidad y versión de una sola lectura", () => {
    // Medido en Firefox 129.0.2 sobre una Mac donde mdls fallaba al 98%.
    expect(
      parseBundleInfo(
        plist({
          CFBundleIdentifier: "org.mozilla.firefox",
          CFBundleShortVersionString: "129.0.2",
          CFBundleVersion: "12924.8.19",
          CFBundleName: "Firefox",
        })
      )
    ).toEqual({
      bundleId: "org.mozilla.firefox",
      version: "129.0.2",
      displayName: "Firefox",
    });
  });

  it("prefiere la versión que el vendor publica sobre el número de build", () => {
    // ⚠️ PMP third-party y la detección de CVE cruzan por nombre + versión.
    // CFBundleVersion ("12924.8.19") no cruza con ningún catálogo; la corta sí.
    const info = parseBundleInfo(
      plist({ CFBundleShortVersionString: "129.0.2", CFBundleVersion: "12924.8.19" })
    );
    expect(info.version).toBe("129.0.2");
  });

  it("cae al build number antes que quedarse sin versión", () => {
    const info = parseBundleInfo(plist({ CFBundleVersion: "12924.8.19" }));
    expect(info.version).toBe("12924.8.19");
  });

  it("acepta una versión numérica, que en plist es legal", () => {
    // CFBundleShortVersionString viene a veces como número, no como cadena.
    expect(parseBundleInfo(plist({ CFBundleShortVersionString: 2 })).version).toBe("2");
  });

  it("rechaza valores que no son texto en vez de escribir '[object Object]'", () => {
    const info = parseBundleInfo(
      plist({ CFBundleIdentifier: { nope: 1 }, CFBundleShortVersionString: ["1.0"] })
    );
    expect(info.bundleId).toBeNull();
    expect(info.version).toBeNull();
  });

  it("prefiere el nombre de display sobre el interno", () => {
    const info = parseBundleInfo(
      plist({ CFBundleDisplayName: "Visual Studio Code", CFBundleName: "Code" })
    );
    expect(info.displayName).toBe("Visual Studio Code");
  });

  it("no confunde un mensaje de error con un identificador", () => {
    // ⚠️ Esta es la trampa que tenía el colector anterior. `mdls` escribe sus
    // errores en STDOUT ("/Applications/Firefox.app: could not find …") y sale
    // con código 1. Si algún día un fallo no propagara el código, esa cadena
    // se habría guardado en el lugar del bundle id — que es la llave de fusión.
    expect(parseBundleInfo("/Applications/Firefox.app: could not find it.")).toEqual({
      bundleId: null,
      version: null,
      displayName: null,
    });
  });

  it("aguanta entradas vacías, nulas y no textuales", () => {
    const vacio = { bundleId: null, version: null, displayName: null };
    expect(parseBundleInfo("")).toEqual(vacio);
    expect(parseBundleInfo("   ")).toEqual(vacio);
    expect(parseBundleInfo(null)).toEqual(vacio);
    expect(parseBundleInfo(undefined)).toEqual(vacio);
    expect(parseBundleInfo(42)).toEqual(vacio);
    // Un plist que es un arreglo en la raíz no es un bundle.
    expect(parseBundleInfo("[1,2,3]")).toEqual(vacio);
  });

  it("un bundle sin identidad no inventa una", () => {
    // Existe en el disco y se sigue reportando por su nombre de archivo, pero
    // sin llave de fusión: es mejor una fila suelta que una fusionada con la
    // app equivocada.
    expect(parseBundleInfo(plist({ CFBundleName: "FoxOneMX" }))).toEqual({
      bundleId: null,
      version: null,
      displayName: "FoxOneMX",
    });
  });
});
