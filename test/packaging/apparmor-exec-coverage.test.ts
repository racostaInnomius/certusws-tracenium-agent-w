import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";

/**
 * Que el perfil de AppArmor permita ejecutar TODO binario que el código lanza.
 *
 * Por qué este test existe
 * ----------------------------------------------------------------------------
 * `packaging/linux/apparmor/usr.lib.tracenium.privsvc` lo instala NUESTRO
 * PROPIO .deb y es un allowlist: lo que no está listado, se deniega. Añadir un
 * shell-out en el código sin añadir su regla no rompe la compilación, no rompe
 * ningún test y no falla al arrancar — falla en el endpoint, en runtime, con un
 * EACCES que no menciona AppArmor por ningún lado.
 *
 * En 1.1.35 le faltó la regla de `/usr/bin/systemd-run`, que es como privsvc
 * lanza el dpkg del auto-update. El resultado no fue "el update falla": fue un
 * DEADLOCK, porque el arreglo del perfil viajaba dentro del update que el
 * propio perfil bloqueaba. SRVOC-MainAgent estuvo cuatro días congelado
 * bajando nueve versiones sin instalar ninguna, y sólo salió con un `dpkg -i`
 * manual por SSH.
 *
 * Un fallback en el instalador evita que vuelva a ser terminal, pero no evita
 * el hueco. Esto sí: el hueco se convierte en un test rojo antes de publicar.
 *
 * ⚠️ Se escanean DOS raíces, no una. El perfil se ancla al BINARIO
 * (`profile tracenium-privsvc /usr/lib/tracenium/node`), y los dos servicios
 * arrancan ese mismo node — así que un perfil escrito para el broker
 * privilegiado confina también al AgentCore. `aa-status` lo confirma en campo:
 * ambos PIDs aparecen bajo `tracenium-privsvc`.
 */

const REPO = path.resolve(__dirname, "../..");
const PROFILE = path.join(
  REPO,
  "packaging/linux/apparmor/usr.lib.tracenium.privsvc"
);
const ROOTS = ["privsvc/linux/src", "src"];

/**
 * Binarios que sólo existen en ramas de macOS o Windows.
 *
 * `src/` es multiplataforma y el análisis es estático, así que no puede saber
 * que un `/usr/bin/dscl` vive detrás de un `process.platform === "darwin"`.
 * La lista es explícita a propósito: si algún día uno de éstos se invoca en
 * Linux, quitarlo de aquí es el recordatorio de que necesita regla.
 */
const NON_LINUX = new Set([
  "/usr/bin/dscl", // macOS: directory services
  "/usr/bin/mdls", // macOS: metadata
  "/usr/bin/security", // macOS: keychain
  "/usr/bin/stat", // macOS: -f%Su sobre /dev/console (en Linux sería otra sintaxis)
  "/usr/sbin/installer", // macOS: instalador de .pkg
  "/usr/sbin/pkgutil", // macOS: consulta de recibos
]);

const BIN_RE = /"((?:\/usr\/bin|\/usr\/sbin|\/bin|\/sbin)\/[a-zA-Z0-9._-]+)"/g;

function sourceFiles(root: string): string[] {
  const abs = path.join(REPO, root);
  if (!fs.existsSync(abs)) return [];
  const out: string[] = [];
  for (const entry of fs.readdirSync(abs, { withFileTypes: true })) {
    const full = path.join(abs, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(path.join(root, entry.name)));
    else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".d.ts")) out.push(full);
  }
  return out;
}

/** Quita comentarios de línea y de bloque para no contar rutas de ejemplo. */
function stripComments(src: string): string {
  return src
    .split("\n")
    .filter((l) => {
      const t = l.trim();
      return !t.startsWith("//") && !t.startsWith("*") && !t.startsWith("/*");
    })
    .join("\n");
}

/**
 * Los binarios que el código realmente EJECUTA.
 *
 * La distinción que importa: `existsSync("/usr/sbin/auditd")` sólo pregunta si
 * un paquete está instalado — nunca lo ejecuta, y pedir regla para él sería
 * ampliar la superficie sin motivo. Se clasifica por OCURRENCIA, no por ruta,
 * porque hay binarios que aparecen de las dos formas:
 *
 *   hasExecutable("/usr/bin/dnf5") ? "/usr/bin/dnf5" : ...
 *
 * La primera es sonda, la segunda es el comando. Si TODAS las apariciones de
 * una ruta son sondas, no necesita regla; basta una que no lo sea.
 */
function executedBinaries(): Map<string, string[]> {
  const found = new Map<string, string[]>();

  for (const root of ROOTS) {
    for (const file of sourceFiles(root)) {
      const src = stripComments(fs.readFileSync(file, "utf8"));

      for (const m of src.matchAll(BIN_RE)) {
        const bin = m[1];
        if (NON_LINUX.has(bin)) continue;

        const total = src.split(`"${bin}"`).length - 1;
        const probes =
          (src.split(`existsSync("${bin}")`).length - 1) +
          (src.split(`hasExecutable("${bin}")`).length - 1);

        if (probes >= total) continue; // sólo se comprueba su existencia

        const rel = path.relative(REPO, file);
        const where = found.get(bin) ?? [];
        if (!where.includes(rel)) where.push(rel);
        found.set(bin, where);
      }
    }
  }

  return found;
}

/** Rutas con permiso de ejecución (ix / Ux / Px / Cx / ux / px / cx). */
function execRules(profile: string): string[] {
  const rules: string[] = [];
  for (const line of profile.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const m = t.match(/^(\/\S+)\s+([A-Za-z]*x)\s*,/);
    if (m) rules.push(m[1]);
  }
  return rules;
}

/** `ix` sobre `/usr/bin/*` cubriría `/usr/bin/curl`. Hoy no hay globs, pero el
 *  perfil es editable a mano y conviene no volverse rojo por una regla válida. */
function covers(rule: string, bin: string): boolean {
  if (rule === bin) return true;
  if (!rule.includes("*")) return false;
  const rx = new RegExp(
    "^" + rule.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*/g, ".*").replace(/(?<!\.)\*/g, "[^/]*") + "$"
  );
  return rx.test(bin);
}

describe("perfil AppArmor: cobertura de exec", () => {
  it("el perfil existe y define reglas de ejecución", () => {
    expect(fs.existsSync(PROFILE)).toBe(true);
    expect(execRules(fs.readFileSync(PROFILE, "utf8")).length).toBeGreaterThan(5);
  });

  it("detecta binarios ejecutados y descarta las meras comprobaciones", () => {
    const bins = executedBinaries();

    // Ancla del incidente: si alguien quita este spawn, el test debe notarlo
    // en vez de pasar en verde sobre un escaneo que ya no encuentra nada.
    expect([...bins.keys()]).toContain("/usr/bin/systemd-run");

    // Contraparte: auditd sólo se consulta con existsSync, nunca se ejecuta.
    expect([...bins.keys()]).not.toContain("/usr/sbin/auditd");
  });

  it("TODO binario ejecutado tiene regla de exec en el perfil", () => {
    const profile = fs.readFileSync(PROFILE, "utf8");
    const rules = execRules(profile);
    const bins = executedBinaries();

    const missing: string[] = [];
    for (const [bin, files] of bins) {
      if (!rules.some((r) => covers(r, bin))) {
        missing.push(`${bin}  ← ${files.join(", ")}`);
      }
    }

    expect(
      missing,
      "Estos binarios se ejecutan pero el perfil de AppArmor no los permite.\n" +
        "En el endpoint fallarán con EACCES, sin mencionar AppArmor.\n" +
        "Añadir su regla en packaging/linux/apparmor/usr.lib.tracenium.privsvc:\n" +
        "  ix = hereda este perfil (lecturas acotadas que no lanzan subprocesos)\n" +
        "  Ux = sin confinar (gestores de paquetes y cualquier cosa que lance postinst)\n\n" +
        missing.join("\n")
    ).toEqual([]);
  });
});
