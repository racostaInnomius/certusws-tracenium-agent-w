// test/privsvc/exec-bounded.test.ts
//
// ⚠️ UN `exec` SIN TOPE EN EL PRIVSVC NO CUELGA UNA OPERACIÓN: SACA AL
// EQUIPO DEL PORTAL.
//
// El IPC del privsvc es un carril SERIE —atiende una petición a la vez— y
// por ese mismo carril viaja el heartbeat. Un proceso hijo que no vuelve
// retiene el carril, y el equipo aparece caído en el portal estando
// encendido, con su agente sano. Medido el 2026-09-08 sobre una Mac
// durante el primer anillo de ADR-0015: 57 minutos fuera por un
// `crypto.cert.renew` cuyo handler no volvía. Y al reintentarse el job,
// otra vez.
//
// El arreglo no fue poner `timeout` en las once llamadas de macOS y las
// cinco de Linux —la que se olvida es exactamente el fallo— sino envolver
// `execFileAsync` una vez por fichero. Este test fija ESO: que el
// `promisify(execFile)` crudo se use UNA sola vez, para construir la
// envoltura, y que la envoltura ponga tope y mate de verdad.
//
// Es un test sobre el código fuente, como `test/priv/ipc-timeouts.test.ts`,
// y por el mismo motivo: la propiedad que hay que sostener es estructural
// —"no existe una ruta sin tope"— y eso no se demuestra ejecutando una
// ruta, se demuestra mirándolas todas.

import { describe, it, expect } from "vitest";
import { execFile } from "child_process";
import { promisify } from "util";
import fs from "fs";
import path from "path";
import os from "os";

const PLATAFORMAS = ["macos", "linux"] as const;

function fuente(plataforma: string): string {
  return fs.readFileSync(
    path.join(__dirname, "..", "..", "privsvc", plataforma, "src", "crypto-store.ts"),
    "utf8"
  );
}

describe.each(PLATAFORMAS)("crypto-store de %s — todo exec acotado", (plataforma) => {
  const src = fuente(plataforma);

  it("⚠️ el promisify(execFile) crudo se usa UNA vez: para envolverlo", () => {
    // Si alguien vuelve a escribir `const execFileAsync = promisify(execFile)`
    // y llama directo, este número sube y el test cae. Ése es el punto.
    const crudos = src.match(/promisify\(execFile\)/g) || [];
    expect(crudos.length, "hay más de un promisify(execFile) suelto").toBe(1);
    expect(src).toContain("const execFileRaw = promisify(execFile);");
  });

  it("⚠️ la envoltura pone tope y mata con SIGKILL", () => {
    const envoltura = src.slice(
      src.indexOf("function execFileAsync("),
      src.indexOf("const OPENSSL_BIN")
    );
    expect(envoltura).toContain("timeout: EXEC_TIMEOUT_MS");
    // SIGTERM no basta: `security` puede quedarse esperando una
    // interacción de UI que en un demonio headless no llega nunca.
    expect(envoltura).toContain('killSignal: "SIGKILL"');
    // El tope tiene que ser un número real, no `undefined` heredado.
    const m = src.match(/const EXEC_TIMEOUT_MS = ([0-9_]+);/);
    expect(m, "EXEC_TIMEOUT_MS no está declarado").not.toBeNull();
    expect(Number(m![1].replace(/_/g, ""))).toBeGreaterThan(1000);
  });

  it("⚠️ nadie llama a execFileRaw fuera de la envoltura", () => {
    const usos = src.match(/execFileRaw\(/g) || [];
    expect(usos.length, "execFileRaw sólo debe invocarse dentro de execFileAsync").toBe(1);
  });
});

describe("el mecanismo del tope, comprobado de verdad", () => {
  it("⚠️ un hijo que no termina SÍ muere y la promesa se resuelve", async () => {
    // Lo anterior fija que el código pide tope; esto comprueba que el
    // tope de Node hace lo que creemos en esta plataforma. Sin esta
    // comprobación estaríamos confiando en una opción por su nombre.
    const script = path.join(os.tmpdir(), `colgado-${process.pid}.sh`);
    fs.writeFileSync(script, "#!/bin/sh\nwhile true; do sleep 1; done\n", { mode: 0o755 });

    const bounded = promisify(execFile);
    const inicio = Date.now();
    await expect(
      bounded(script, [], { timeout: 700, killSignal: "SIGKILL" } as any)
    ).rejects.toThrow();
    const tardo = Date.now() - inicio;

    // Vuelve pronto: lo que importa es que VUELVE, no el número exacto.
    expect(tardo).toBeLessThan(10_000);
    fs.unlinkSync(script);
  });
});
