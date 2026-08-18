import { describe, it, expect } from "vitest";
import { trySpawnDetached } from "../../privsvc/linux/src/agent-install";

/**
 * El fallback del instalador de Linux.
 *
 * Incidente 2026-08-14/18, SRVOC-MainAgent: el perfil de AppArmor que instala
 * NUESTRO PROPIO .deb es un allowlist, y en 1.1.35 le faltaba la regla para
 * `/usr/bin/systemd-run`. privsvc lo usa para lanzar dpkg en un scope fuera de
 * su cgroup, así que el spawn moría con EACCES y la instalación no arrancaba
 * nunca.
 *
 * Lo grave no fue el hueco en el allowlist sino el DEADLOCK: el arreglo del
 * perfil viajaba dentro del update que el propio perfil bloqueaba. El host
 * estuvo cuatro días bajando nueve versiones (1.1.36→1.1.42, 730 MB) sin
 * instalar ninguna, y sólo salió con un `dpkg -i` manual por SSH.
 *
 * De ahí el fallback: si systemd-run no se puede ejecutar, se lanza el
 * instalador directamente. Es peor —queda dentro del cgroup y el postinst
 * puede morir al reiniciar el servicio— pero un hueco en el perfil deja de
 * poder inutilizar el mecanismo que entrega su propia corrección.
 *
 * Estos tests fijan el contrato del que depende ese encadenamiento: que un
 * fallo de exec sea DISTINGUIBLE de un arranque real *antes* de responder.
 * Sin esa distinción no hay forma de saber que hay que intentar el segundo
 * camino, y era justo lo que faltaba cuando el bug se manifestó.
 */
describe("trySpawnDetached", () => {
  it("reporta ok:false cuando el binario no se puede ejecutar", async () => {
    // Sustituto de EACCES: lo que importa es que un exec fallido vuelva por
    // el canal de error en vez de tumbar el proceso o pasar por bueno.
    const r = await trySpawnDetached("/nonexistent/systemd-run", ["--scope"]);

    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/ENOENT|EACCES|spawn/i);
  });

  it("un exec fallido NO tumba el proceso", async () => {
    // La regresión que costó 364 reinicios de privsvc: sin listener de
    // 'error', Node trata el fallo como excepción no capturada. Si esto
    // volviera a romperse, el runner de tests moriría aquí.
    await trySpawnDetached("/nonexistent/a", []);
    await trySpawnDetached("/nonexistent/b", []);

    expect(true).toBe(true);
  });

  it("reporta ok:true con pid cuando el binario sí arranca", async () => {
    const r = await trySpawnDetached("/bin/echo", ["ok"]);

    expect(r.ok).toBe(true);
    if (r.ok) expect(typeof r.pid).toBe("number");
  });

  it("permite encadenar: falla el primero, arranca el segundo", async () => {
    // La forma exacta del fallback en handleAgentInstall.
    const scope = await trySpawnDetached("/nonexistent/systemd-run", ["--scope"]);
    expect(scope.ok).toBe(false);

    const direct = await trySpawnDetached("/bin/echo", ["dpkg"]);
    expect(direct.ok).toBe(true);
  });

  it("si fallan ambos caminos, ambos errores quedan disponibles", async () => {
    const scope = await trySpawnDetached("/nonexistent/systemd-run", []);
    const direct = await trySpawnDetached("/nonexistent/dpkg", []);

    expect(scope.ok).toBe(false);
    expect(direct.ok).toBe(false);
    // El handler reporta los dos: "falló systemd-run" a secas mandaría a
    // revisar el binario equivocado.
    if (!scope.ok && !direct.ok) {
      expect(scope.error).not.toBe("");
      expect(direct.error).not.toBe("");
    }
  });
});
