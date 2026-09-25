import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

/**
 * 🔴 La bandeja de Windows desapareció de un equipo entero tras el update.
 *
 * `%ProgramData%\Tracenium\Agent\logs\tray-crash.log`, 25-sep-2026, repetido
 * cada cinco minutos durante hora y media:
 *
 *   NullReferenceException
 *     at RemoteSessionBanner.LayoutChildren()
 *     at RemoteSessionBanner.OnResize(EventArgs e)
 *     at Control.set_Height(Int32 value)
 *     at RemoteSessionBanner..ctor()
 *     at TrayApplicationContext..ctor()
 *
 * La trampa es de WinForms y no salta a la vista leyendo el código: asignar
 * `Height` dentro del constructor levanta `OnResize`, y `OnResize` es una
 * sobrescritura NUESTRA que toca campos que el constructor todavía no ha
 * asignado. El objeto se está construyendo y ya le están llamando a un método
 * que lo supone terminado.
 *
 * Por qué se llevó por delante la bandeja entera y no solo la franja: ese
 * `new RemoteSessionBanner()` era un inicializador de campo de
 * `TrayApplicationContext`, o sea que corría ANTES de crear el `NotifyIcon`.
 * El constructor entero moría, `Application.Run` no llegaba a arrancar y el
 * proceso se iba sin haber puesto nunca el icono. Determinista: el reinicio lo
 * reproducía igual.
 *
 * ── Por qué esta prueba vive aquí y no en C# ────────────────────────
 *
 * No hay proyecto de pruebas para el tray, y aunque lo hubiera, WinForms no
 * se instancia en este Mac: el fallo solo se ve ejecutando en Windows. Lo que
 * SÍ se puede comprobar desde aquí es la forma del código, que es donde vive
 * la trampa. Es el mismo enfoque que `control-message-routing` o
 * `ipc-request-envelope`: cuando el tipo no puede sujetar la invariante, la
 * sujeta un escáner de fuentes.
 */

const TRAY_DIR = path.resolve(__dirname, "../../windows/Tracenium.AgentTray");

/** Los .cs del tray, con su contenido. */
function traySources(): Array<{ name: string; text: string }> {
  return readdirSync(TRAY_DIR)
    .filter((f) => f.endsWith(".cs"))
    .map((name) => ({
      name,
      text: readFileSync(path.join(TRAY_DIR, name), "utf8"),
    }));
}

/**
 * El cuerpo del constructor de `cls`, desde la firma hasta el cierre a su
 * mismo nivel de indentación. Basta con esa heurística: todos estos ficheros
 * están formateados igual.
 */
function constructorBody(text: string, cls: string): string | null {
  const start = text.indexOf(`public ${cls}(`);
  if (start < 0) return null;
  const end = text.indexOf("\n    }", start);
  return end < 0 ? text.slice(start) : text.slice(start, end);
}

/** Propiedades cuya asignación dispara un relayout en WinForms. */
const RESIZING_PROPERTIES = ["Height", "Width", "Size", "ClientSize", "Bounds"];

describe("WinForms: nadie coloca hijos que aún no existen", () => {
  it("toda sobrescritura de OnResize tiene guarda de construcción", () => {
    const offenders: string[] = [];
    for (const { name, text } of traySources()) {
      if (!/protected override void On(Resize|Layout|SizeChanged)\b/.test(text)) continue;
      // La guarda puede estar en el propio override o en el método al que
      // delega; con que el fichero la tenga basta, porque son ficheros de una
      // sola ventana.
      if (!/if \(!_built\) return;/.test(text)) {
        offenders.push(name);
      }
    }
    expect(
      offenders,
      "estas ventanas colocan hijos desde un evento del sistema sin comprobar "
        + "que ya existan; un OnResize durante el constructor las tumba, y si "
        + "se construyen antes que el NotifyIcon se llevan la bandeja entera",
    ).toEqual([]);
  });

  it("ningún constructor cambia el tamaño antes de declararse construido", () => {
    const offenders: string[] = [];
    for (const { name, text } of traySources()) {
      if (!text.includes("_built")) continue;
      const cls = name.replace(/\.cs$/, "");
      const ctor = constructorBody(text, cls);
      if (!ctor) continue;

      const builtAt = ctor.indexOf("_built = true");
      expect(builtAt, `${name}: el constructor nunca marca _built = true`).toBeGreaterThan(-1);

      for (const prop of RESIZING_PROPERTIES) {
        // ⚠️ Exactamente la indentación del cuerpo del constructor y con `;`
        // al final: así se distingue `Height = 52;` sobre la propia ventana de
        // un `Size = new Size(54, 20),` dentro del inicializador de un hijo,
        // que es inofensivo y que la primera versión de esta prueba delató
        // como si fuera el fallo.
        const at = ctor.search(new RegExp(`^ {8}${prop} = .*;$`, "m"));
        if (at >= 0 && at < builtAt) {
          offenders.push(`${name}: asigna ${prop} antes de _built = true`);
        }
      }
    }
    expect(
      offenders,
      "asignar tamaño levanta OnResize sobre un objeto a medio construir — "
        + "es la traza exacta del tray-crash.log del 25-sep",
    ).toEqual([]);
  });

  /**
   * La otra mitad del fallo: aunque la ventana reviente, el icono tiene que
   * estar puesto. Se comprueba que las tres ventanas ya no sean
   * inicializadores de campo, que es lo que las ponía por delante del
   * `NotifyIcon`.
   */
  it("las ventanas no se construyen antes que el icono de la bandeja", () => {
    const text = readFileSync(path.join(TRAY_DIR, "TrayApplicationContext.cs"), "utf8");
    const fieldInit = /private\s+(?:readonly\s+)?(StatusForm|DeviceInfoFlyout|RemoteSessionBanner)\s+_\w+\s*=\s*new\(\)/g;
    const found = [...text.matchAll(fieldInit)].map((m) => m[1]);
    expect(
      found,
      "un inicializador de campo corre ANTES del cuerpo del constructor, o sea "
        + "antes de que exista el NotifyIcon: si lanza, no hay icono en absoluto",
    ).toEqual([]);

    const ctor = constructorBody(text, "TrayApplicationContext");
    expect(ctor).not.toBeNull();
    const iconAt = ctor!.indexOf("_notifyIcon = new NotifyIcon");
    expect(iconAt, "el constructor ya no crea el NotifyIcon").toBeGreaterThan(-1);
    for (const cls of ["new StatusForm", "new DeviceInfoFlyout", "new RemoteSessionBanner"]) {
      const at = ctor!.indexOf(cls);
      expect(at, `${cls} no se construye en el constructor`).toBeGreaterThan(-1);
      expect(
        at,
        `${cls} se construye ANTES del NotifyIcon; si lanza, la bandeja no aparece`,
      ).toBeGreaterThan(iconAt);
    }
  });
});
