import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
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

  /**
   * ⚠️ El agente se auto-actualiza, así que este script corre en cada versión.
   * Tras el update a 1.1.82 la ventana de permisos volvió a salir, y eso no es
   * un detalle de estilo: un aviso que reaparece en cada actualización enseña
   * a cerrarlo sin leer, que es lo contrario de lo que esta ventana persigue.
   */
  describe("la ventana de permisos se ofrece UNA vez, no en cada update", () => {
    const MARKER = "/Library/Application Support/Tracenium/.permissions-prompted";

    it("se salta el lanzamiento si ya se ofreció", () => {
      expect(text).toContain(MARKER);
      expect(
        text,
        "sin la comprobación, cada auto-update reabre la ventana",
      ).toMatch(/if \[ -f "\$SETUP_MARKER" \]/);
    });

    it("deja la marca al ofrecerla, no al aceptarla", () => {
      const open = text.indexOf("--args --setup");
      const touch = text.indexOf('touch "$SETUP_MARKER"');
      expect(touch, "no se deja marca: volvería a preguntar en la próxima versión")
        .toBeGreaterThan(-1);
      expect(
        touch,
        "la marca va DESPUÉS de abrir la ventana, en la misma rama",
      ).toBeGreaterThan(open);
    });

    it("la marca vive fuera de Agent/, que es 700 y se borra", () => {
      expect(MARKER).not.toContain("/Agent/");
    });
  });
});

/**
 * 🔴 La otra punta del mismo problema: el PREINSTALL.
 *
 * El iMac Intel de T1 (26-sep) sumó 25 crashes de TraceniumAgentStatus en
 * cuatro minutos, uno cada ~10 s, justo tras un `agent_update`. El preinstall
 * solo paraba la bandeja del dueño de /dev/console; con la sesión abierta pero
 * sin estar en pantalla no había usuario de consola, la bandeja seguía viva,
 * PackageKit le reescribía el binario debajo y KeepAlive la relanzaba contra
 * un bundle a medio escribir. DEX lo contó como "Unstable application".
 */
describe("preinstall de macOS: la bandeja se para en todas las sesiones", () => {
  const PREINSTALL = path.resolve(__dirname, "../../privsvc/macos/pkg-scripts/preinstall");
  const pre = readFileSync(PREINSTALL, "utf8");

  it("⭐ no depende del usuario de consola", () => {
    expect(pre, "volvería a saltarse la sesión que no está en pantalla").not.toMatch(/stat -f %Su \/dev\/console/);
  });

  it("recorre los mismos UID que el postinstall restaura (dominio gui vivo)", () => {
    expect(pre).toContain("dscl . -list /Users UniqueID");
    expect(pre).toMatch(/launchctl print "gui\/\$uid"/);
    expect(pre).toMatch(/launchctl bootout "gui\/\$uid\/com\.certusws\.tracenium\.agentstatus"/);
  });

  it("mata también la instancia suelta, y DESPUÉS del bootout", () => {
    const bootout = pre.indexOf('bootout "gui/$uid/com.certusws.tracenium.agentstatus"');
    const kill = pre.indexOf(`pkill -f "${STATUS_APP_BINARY}"`);
    expect(kill, "la del `open --setup` no la gestiona launchd").toBeGreaterThan(-1);
    expect(kill, "antes del bootout, KeepAlive la relanzaría").toBeGreaterThan(bootout);
  });

  it("es sh válido", () => {
    expect(() => execFileSync("/bin/sh", ["-n", PREINSTALL])).not.toThrow();
  });

  // El node del 27-sep murió con "SIGKILL (Code Signature Invalid)" 10 s
  // después del preinstall: seguía vivo cuando PackageKit reescribió
  // Runtime/node. bootout manda SIGTERM y vuelve; no espera.
  it("⭐ espera a que el node salga, y lo mata antes de que llegue el payload", () => {
    const bootout = pre.indexOf("bootout system/com.certusws.tracenium.privsvc");
    const wait = pre.indexOf('pgrep -f "$NODE_BIN"');
    const kill = pre.indexOf('pkill -9 -f "$NODE_BIN"');
    expect(pre).toContain('NODE_BIN="/Library/Application Support/Tracenium/Runtime/node"');
    expect(wait, "sin espera, el payload llega con el node vivo").toBeGreaterThan(bootout);
    expect(kill, "lo que no sale solo lo mata el kernel a mitad, con informe").toBeGreaterThan(wait);
    expect(pre, "un tope, o un node colgado cuelga el Installer").toMatch(/\[ "\$waited" -lt \d+ \]/);
  });
});

/**
 * La bandeja pedía macOS 13 sin usar nada de 13; los otros dos helpers piden
 * 12.3. Con LSMinimumSystemVersion 13.0, LaunchServices se negaba a abrirla en
 * Monterey y la ventana de permisos del `--setup` no salía en el iMac de T1.
 */
describe("la bandeja arranca en macOS 12.3, como los helpers", () => {
  const root = path.resolve(__dirname, "../../macos/TraceniumAgentStatus");

  it("Package.swift e Info.plist dicen lo mismo: 12.3", () => {
    expect(readFileSync(path.join(root, "Package.swift"), "utf8")).toContain('.macOS("12.3")');
    expect(readFileSync(path.join(root, "Resources/Info.plist"), "utf8")).toMatch(
      /<key>LSMinimumSystemVersion<\/key>\s*<string>12\.3<\/string>/
    );
  });

  it("y los helpers del pkg siguen en 12.3", () => {
    const build = readFileSync(path.resolve(__dirname, "../../scripts/build-macos-pkg.sh"), "utf8");
    expect(build).toContain("x86_64-apple-macos12.3");
    expect(build).toMatch(/<key>LSMinimumSystemVersion<\/key>\s*<string>12\.3<\/string>/);
  });
});
