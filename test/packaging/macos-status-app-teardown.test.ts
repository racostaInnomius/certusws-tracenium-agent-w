import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";

/**
 * 🔴 Dos iconos de Tracenium en la barra de menús, y una actualización que no
 * los quitaba.
 *
 * El `postinstall` arranca la bandeja dos veces sin querer: `launchctl
 * kickstart` para el LaunchAgent y `open --args --setup` para la ventana de
 * permisos. El arbitraje por `flock` que lleva el binario nuevo evita que
 * vuelva a pasar, pero NO limpia un equipo que ya arrastre el duplicado: la
 * instancia vieja ya está corriendo, no sabe arbitrar, y nadie la para.
 *
 * Por qué no bastaba el `bootout` que ya había: alcanza solo al trabajo
 * gestionado por launchd. Comprobado en el Mac afectado (25-sep-2026):
 *
 *   launchctl print gui/501/com.certusws.tracenium.agentstatus → pid = 66228
 *   ps                                                          → 66228 y 66235
 *
 * El 66235 —el del `open`— es un proceso suelto. `bootout` no lo ve, no se
 * reinicia solo y no se para solo. Sin un `pkill` explícito, el equipo se
 * actualizaba y seguía con dos iconos hasta cerrar sesión.
 */

const POSTINSTALL = path.resolve(
  __dirname,
  "../../privsvc/macos/pkg-scripts/postinstall",
);

const STATUS_APP_BINARY =
  "Tracenium Agent Status.app/Contents/MacOS/TraceniumAgentStatus";

describe("postinstall de macOS: no deja bandejas huérfanas", () => {
  const text = readFileSync(POSTINSTALL, "utf8");

  it("mata las instancias que launchd no controla", () => {
    expect(
      text,
      "sin esto, un Mac que ya tenga el icono duplicado se actualiza y sigue "
        + "con dos: el binario nuevo arbitra, pero el proceso viejo ya estaba",
    ).toContain(`pkill -f "${STATUS_APP_BINARY}"`);
  });

  it("y lo hace DESPUÉS del bootout, no antes", () => {
    const bootout = text.indexOf("bootout \"gui/$console_uid/com.certusws.tracenium.agentstatus\"");
    const kill = text.indexOf(`pkill -f "${STATUS_APP_BINARY}"`);
    expect(bootout, "el postinstall ya no hace bootout per-user").toBeGreaterThan(-1);
    expect(
      kill,
      "matar antes del bootout es inútil: KeepAlive relanza lo que acabas de matar",
    ).toBeGreaterThan(bootout);
  });

  /**
   * La otra mitad: el `--setup` tiene que llegar SIEMPRE a un proceso. Sin
   * `-n`, cuando LaunchServices ya tiene registrada la instancia del
   * `kickstart`, `open` se limita a activarla y los `--args` se tiran — la
   * ventana de permisos no se abriría nunca en una reinstalación.
   */
  it("pide instancia nueva para que el --setup no se pierda", () => {
    // ⚠️ Sin comentarios: este mismo fichero EXPLICA el fallo citando el
    // `open --args --setup` de antes, y la primera versión de esta prueba
    // encontró la explicación en vez del comando.
    const line = text
      .split("\n")
      .filter((l) => !l.trimStart().startsWith("#"))
      .find((l) => l.includes("/usr/bin/open") && l.includes("--setup"));
    expect(line, "el postinstall ya no lanza la ventana de permisos").toBeDefined();
    expect(
      line,
      "sin `-n`, open activa la instancia existente y descarta los --args",
    ).toMatch(/open\s+-n\s+-a/);
  });
});
