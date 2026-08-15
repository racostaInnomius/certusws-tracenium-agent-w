import { describe, it, expect } from "vitest";
import { spawn } from "node:child_process";

/**
 * Por qué un try/catch alrededor de `spawn` no protege de nada.
 *
 * Incidente del 2026-08-15: un perfil de AppArmor sin regla para
 * `/usr/bin/systemd-run` hacía que el spawn del instalador fallara con EACCES.
 * El código lo envolvía en try/catch, pero `spawn` NO lanza de forma síncrona:
 * emite un evento 'error' asíncrono. Sin listener, Node lo trata como
 * excepción no capturada y MATA el proceso.
 *
 * Resultado: privsvc —el broker privilegiado que además atiende compliance,
 * inventario y CDP— moría en cada intento de actualización. 364 reinicios
 * acumulados, y el agente sin actualizarse desde 1.1.21.
 *
 * Estos tests fijan las dos propiedades del arreglo: que el fallo llegue por
 * 'error' y no por throw, y que se pueda distinguir un arranque real de uno
 * fallido antes de responder.
 */

/** Réplica de la espera que hace agent-install antes de responder. */
function awaitSpawn(
  child: ReturnType<typeof spawn>,
  timeoutMs = 2000
): Promise<{ ok: true } | { ok: false; error: string }> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (r: { ok: true } | { ok: false; error: string }) => {
      if (settled) return;
      settled = true;
      resolve(r);
    };
    child.on("error", (err: any) => done({ ok: false, error: err?.message || String(err) }));
    child.on("spawn", () => done({ ok: true }));
    setTimeout(() => done({ ok: true }), timeoutMs).unref();
  });
}

describe("spawn: por qué el try/catch no bastaba", () => {
  it("NO lanza de forma síncrona cuando el binario no existe", () => {
    // Ésta es la premisa del incidente. Si algún día Node cambiara y lanzara
    // aquí, este test lo diría.
    let threw = false;
    let child: ReturnType<typeof spawn> | null = null;
    try {
      child = spawn("/ruta/que/no/existe/jamas", [], { stdio: "ignore" });
    } catch {
      threw = true;
    }
    expect(threw, "spawn lanzó síncronamente; la premisa del fix cambió").toBe(false);

    // Hay que consumir el 'error' o Node lo escala a excepción no capturada.
    child?.on("error", () => {});
  });

  it("el fallo llega por el evento 'error', que es lo que hay que escuchar", async () => {
    const child = spawn("/ruta/que/no/existe/jamas", [], { stdio: "ignore" });
    const result = await awaitSpawn(child, 3000);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/ENOENT|no such file/i);
  });

  it("un binario válido resuelve como arrancado", async () => {
    const child = spawn(process.execPath, ["-e", "0"], {
      stdio: "ignore",
      detached: true,
    });
    const result = await awaitSpawn(child, 3000);

    expect(result.ok).toBe(true);
    child.unref();
  });

  it("distingue arranque real de fallo, para no reportar started:true en falso", async () => {
    // Antes se respondía `started: true` en cuanto spawn retornaba, así que el
    // agente creía que la instalación iba en marcha aunque el proceso no
    // hubiese llegado a existir.
    const bad = spawn("/ruta/que/no/existe/jamas", [], { stdio: "ignore" });
    const good = spawn(process.execPath, ["-e", "0"], { stdio: "ignore", detached: true });

    const [rBad, rGood] = await Promise.all([awaitSpawn(bad, 3000), awaitSpawn(good, 3000)]);

    expect(rBad.ok).toBe(false);
    expect(rGood.ok).toBe(true);
    good.unref();
  });

  it("registrar el listener evita que el fallo tumbe el proceso", async () => {
    // Con listener, el 'error' se consume y el proceso sobrevive; sin él,
    // Node lo escalaría a uncaughtException. Que este test termine es la
    // prueba: el runner sigue vivo después.
    const child = spawn("/ruta/que/no/existe/jamas", [], { stdio: "ignore" });
    const result = await awaitSpawn(child, 3000);

    expect(result.ok).toBe(false);
    expect(process.exitCode ?? 0).toBe(0);
  });
});
