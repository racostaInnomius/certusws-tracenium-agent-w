// test/privsvc/macos-dmg-min-os.test.ts
//
// 🔴 EL CASO DE CAMPO (30-sep, T1). Un deploy de Chrome 154 (DMG) llegó a
// `iMac-de-iMac-2`, que corre macOS 12.7.6. Chrome 154 exige 13.0. El agente
// hizo lo de siempre con un DMG —montar, `rm -rf /Applications/<App>.app`,
// `ditto` el nuevo, exit 0— y el resultado fue un navegador que no abre y un
// deploy en verde. El Chrome 150 que funcionaba ya no estaba.
//
// Un DMG no tiene instalador que compruebe nada: es una copia, y copiar nunca
// falla por la versión del SO. La guarda la pone el agente, con la clave que la
// propia app declara (`LSMinimumSystemVersion`).

import { readFileSync } from "fs";
import path from "path";
import { describe, expect, it } from "vitest";

import { compareSemver, osTooOld } from "../../privsvc/macos/src/mac-version";

describe("osTooOld", () => {
  it("🔴 el caso de campo: 12.7.6 no abre una app que exige 13.0", () => {
    expect(osTooOld("13.0", "12.7.6")).toBe(true);
  });

  it("un Mac igual o más nuevo que el mínimo pasa", () => {
    expect(osTooOld("13.0", "13.0")).toBe(false);
    expect(osTooOld("13.0", "13.0.1")).toBe(false);
    expect(osTooOld("13.0", "15.6.1")).toBe(false);
  });

  it("⚠️ atraviesa el salto de numeración de macOS: 26 es más nuevo que 15", () => {
    // Apple pasó de 15 (Sequoia) a 26 (Tahoe). Cinco Macs de T1 van en 26-27.
    expect(osTooOld("15.0", "26.6.2")).toBe(false);
    expect(osTooOld("26.0", "15.6.1")).toBe(true);
  });

  it("⚠️ compara número a número, no como texto", () => {
    // Como texto, "9" > "13" y "10.9" > "10.15". Las dos son falsas.
    expect(osTooOld("10.15", "10.9")).toBe(true);
    expect(osTooOld("13", "9.0")).toBe(true);
  });

  it("los ceros que faltan no cuentan: 13 == 13.0 == 13.0.0", () => {
    expect(osTooOld("13", "13.0.0")).toBe(false);
    expect(osTooOld("13.0.0", "13")).toBe(false);
  });

  it("⚠️ sin clave o sin versión legible, DEJA PASAR", () => {
    // Muchas apps no declaran LSMinimumSystemVersion. Bloquear por un dato
    // ausente pararía todas las instalaciones de Mac, que es peor que el caso
    // que esto evita — y es el comportamiento de antes.
    expect(osTooOld(null, "12.7.6")).toBe(false);
    expect(osTooOld(undefined, "12.7.6")).toBe(false);
    expect(osTooOld("", "12.7.6")).toBe(false);
    expect(osTooOld("13.0", null)).toBe(false);
    expect(osTooOld("no-es-version", "12.7.6")).toBe(false);
  });

  it("tolera espacios y saltos de línea de `defaults read` / `sw_vers`", () => {
    expect(osTooOld(" 13.0\n", "12.7.6\n")).toBe(true);
  });
});

describe("compareSemver (movido desde sdp.ts, sin cambios)", () => {
  // Lo usaba ya la regla de detección `bundle_version`. Estas pruebas fijan que
  // al moverlo no cambió de comportamiento.
  it("ordena como antes", () => {
    expect(compareSemver("154.0.8037.58", "150.0.7871.125")).toBe(1);
    expect(compareSemver("150.0.7871.125", "154.0.8037.58")).toBe(-1);
    expect(compareSemver("1.2", "1.2.0")).toBe(0);
    expect(compareSemver("2.0-beta", "2.0")).toBe(0);
  });
});

// ── Lo que no se puede ejecutar en CI, se fija en el fuente ────────────────
//
// `runDmgInstaller` monta imágenes con hdiutil y escribe en /Applications: no
// corre fuera de un Mac con root. Pero la propiedad que importa es de ORDEN y
// de CABLEADO, y esa se lee en el fuente — como hace
// test/grpc/agent-job-result.test.ts con controlplane.ts.

const SDP = readFileSync(
  path.join(__dirname, "..", "..", "privsvc", "macos", "src", "sdp.ts"),
  "utf8"
);

function body(fnName: string): string {
  const start = SDP.indexOf(`async function ${fnName}(`);
  expect(start, `no encuentro ${fnName}`).toBeGreaterThan(-1);
  const next = SDP.indexOf("\nasync function ", start + 1);
  return SDP.slice(start, next === -1 ? undefined : next);
}

describe("runDmgInstaller — dónde va la guarda", () => {
  const dmg = body("runDmgInstaller");

  it("🔴 comprueba el SO ANTES de borrar la app que ya está instalada", () => {
    // Es la propiedad que importa. Si la guarda fuera después del `rm -rf`, el
    // fallo seguiría siendo «navegador roto» — sólo que ahora con motivo.
    const guard = dmg.indexOf("osTooOld(");
    const remove = dmg.indexOf('"/bin/rm"');
    expect(guard).toBeGreaterThan(-1);
    expect(remove).toBeGreaterThan(-1);
    expect(guard).toBeLessThan(remove);
  });

  it("⚠️ lee la versión mínima del bundle MONTADO, no del instalado", () => {
    // El instalado es el viejo: su mínimo no dice nada de lo que se va a copiar.
    expect(dmg).toMatch(/readPlistKey\(\s*path\.join\(sourceApp,/);
    expect(dmg).toMatch(/"LSMinimumSystemVersion"/);
  });

  it("⚠️ la negativa sube con su código: el catch no la convierte en exit 1", () => {
    // Sin esto la guarda llegaría al portal como un `failed` genérico sin
    // motivo — el misterio que quiere evitar.
    expect(dmg).toMatch(/if \(err\?\.code === "os_too_old"\) throw err;/);
  });
});

describe("el handler de sdp.install", () => {
  it("🔴 devuelve `os_too_old`, no `install_failed`", () => {
    expect(SDP).toMatch(/return fail\(req\.id, "os_too_old",/);
  });

  it("el código está en la cabecera del contrato con el agente", () => {
    // La cabecera es la lista que el agente usa para decidir permanente o no.
    expect(SDP).toMatch(/\/\/\s+os_too_old\s+permanent \(mapped to outcome=rejected\)/);
  });
});
