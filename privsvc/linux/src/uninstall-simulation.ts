// privsvc/linux/src/uninstall-simulation.ts
//
// Antes de desinstalar un paquete, preguntar al gestor qué MÁS se llevaría.
//
// ── Por qué existe ───────────────────────────────────────────────────────
//
// `apt-get remove -y <pkg>` y `dnf remove -y <pkg>` desinstalan, sin
// preguntar, todo lo que DEPENDE del paquete. Es su comportamiento documentado,
// no un fallo, y con `-y` nadie lo ve. Quitar `firefox` en un Ubuntu se lleva
// el metapaquete `ubuntu-desktop`; quitar una librería puede llevarse medio
// sistema.
//
// Mientras la desinstalación sólo salía del CATÁLOGO, el paquete lo había
// elegido alguien a propósito. Desde el INVENTARIO (ADR-0019) el operador puede
// señalar cualquier fila, y lo que ve en la vista previa es UN paquete. Si en el
// equipo se van doce, la vista previa mintió — y una desinstalación no tiene
// deshacer.
//
// Así que se simula primero (`apt-get -s remove`, `dnf remove --assumeno`) y
// se RECHAZA si la transacción toca algo más que el objetivo.
//
// ── Qué se permite y qué no ──────────────────────────────────────────────
//
//   · Dependientes (lo que necesita al objetivo) → NO. Son cosas que alguien
//     usa, y el operador no las pidió.
//   · «Dependencias que quedan sin uso» de dnf (clean_requirements_on_remove,
//     activo por defecto) → SÍ, pero se informa. dnf sólo las marca cuando se
//     instalaron COMO dependencia y ya nadie las necesita: es la limpieza
//     normal, no un daño colateral. apt no hace esto en `remove`.
//   · Otro paquete bajo el propio «Removing:» → NO. Pasa cuando el nombre es
//     un «provides» de otro paquete: se pidió uno y se quitaría otro.
//
// ⚠️ LO QUE NO SE ENTIENDE, SE RECHAZA. Si la salida no tiene la forma esperada
// (otra versión del gestor, otro idioma) no se sabe qué se llevaría, y en una
// operación irreversible «no sé» es «no».

export type SimulationVerdict =
  /** Sólo el objetivo (más, en dnf, dependencias ya sin uso). Adelante. */
  | { ok: true; kind: "proceed"; unusedDependencies: string[] }
  /** El paquete no está instalado: no hay nada que ejecutar. */
  | { ok: true; kind: "not_installed" }
  /** Se llevaría otros paquetes: rechazar con la lista. */
  | { ok: false; code: "would_remove_dependents"; dependents: string[] }
  /** No se entendió la salida: rechazar sin adivinar. */
  | { ok: false; code: "uninstall_simulation_unreadable"; detail: string };

/**
 * ¿Tiene forma de nombre de paquete? Debian exige empezar por alfanumérico y
 * sólo `+ - .` después; RPM es más laxo (admite `_`). Se acepta la unión, con
 * `:arquitectura` opcional.
 *
 * ⚠️ Lo que importa es el primer carácter: un «-s» o «--purge» que llegara
 * como nombre sería una OPCIÓN para apt, aunque no haya shell de por medio.
 */
export function isPackageName(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9+._~-]*(?::[A-Za-z0-9_-]+)?$/.test(String(name || ""));
}

/** `libfoo:amd64` → `libfoo`. La arquitectura no cambia qué paquete es. */
function bareName(name: string): string {
  return name.replace(/:[A-Za-z0-9_-]+$/, "");
}

function uniq(xs: string[]): string[] {
  return [...new Set(xs)];
}

/**
 * Lee la salida de `apt-get -s remove <pkg>` (con LANG=C).
 *
 * Cada paquete que se quitaría aparece en una línea `Remv <nombre> [versión]`
 * (o `Purg` si fuese purge). Es la parte estable de la salida; la frase
 * «The following packages will be REMOVED:» cambia de formato entre versiones.
 */
export function judgeAptSimulation(
  target: string,
  output: string,
  exitCode: number
): SimulationVerdict {
  const text = String(output || "");
  const want = bareName(target.trim());

  if (/Unable to locate package/i.test(text) || /is not installed, so not removed/i.test(text)) {
    return { ok: true, kind: "not_installed" };
  }
  if (exitCode !== 0) {
    return {
      ok: false,
      code: "uninstall_simulation_unreadable",
      detail: `apt-get -s remove exited ${exitCode}`,
    };
  }

  const removed = uniq(
    text
      .split("\n")
      .map((l) => /^(?:Remv|Purg)\s+(\S+)/.exec(l.trim()))
      .filter((m): m is RegExpExecArray => m !== null)
      .map((m) => bareName(m[1]))
  );

  if (removed.length === 0 || !removed.includes(want)) {
    // Ni «no instalado» ni el objetivo en la lista: no sabemos qué pasaría.
    return {
      ok: false,
      code: "uninstall_simulation_unreadable",
      detail: `apt-get simulation did not list ${want} for removal`,
    };
  }

  const others = removed.filter((n) => n !== want);
  if (others.length > 0) return { ok: false, code: "would_remove_dependents", dependents: others };
  return { ok: true, kind: "proceed", unusedDependencies: [] };
}

type DnfSection = "target" | "unused" | "collateral";

/**
 * Sólo DOS secciones se permiten; todas las demás son daño colateral.
 *
 * ⚠️ AL REVÉS NO: listar las secciones peligrosas («Removing dependent
 * packages:» en dnf, «Removing for dependencies:» en yum de RHEL 7…) dejaría
 * pasar la que no se previó — otra versión, otra redacción. Enumerar lo que se
 * permite falla cerrado.
 */
function dnfSectionOf(header: string): DnfSection {
  const h = header.trim().toLowerCase();
  if (h === "removing:") return "target";
  if (h === "removing unused dependencies:") return "unused";
  return "collateral";
}

/**
 * Lee la salida de `dnf remove --assumeno <pkg>` (o yum), con LANG=C.
 *
 * ⚠️ EL CÓDIGO DE SALIDA NO DICE NADA: con `--assumeno` dnf termina en 1 cada
 * vez que HAY transacción («Operation aborted.»), que es justo el caso normal.
 * Se decide por la tabla.
 *
 * La tabla agrupa por secciones («Removing:», «Removing dependent packages:»…)
 * y cada fila de paquete va sangrada un espacio. Un nombre largo se parte en
 * dos líneas y la continuación va MUY sangrada (columnas de arquitectura,
 * versión…): por eso sólo cuentan las filas con sangría corta.
 */
export function judgeDnfSimulation(target: string, output: string): SimulationVerdict {
  const text = String(output || "");
  const want = bareName(target.trim());

  if (
    /No match for argument/i.test(text) ||
    /No packages marked for removal/i.test(text) ||
    /No packages to remove/i.test(text)
  ) {
    return { ok: true, kind: "not_installed" };
  }

  const bySection: Record<DnfSection, string[]> = { target: [], unused: [], collateral: [] };
  let section: DnfSection | null = null;
  let sawTable = false;

  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (/^Transaction Summary/i.test(trimmed)) break;

    // Cabecera de sección: sin sangría y termina en «:».
    if (!/^\s/.test(line) && trimmed.endsWith(":")) {
      section = dnfSectionOf(trimmed);
      sawTable = true;
      continue;
    }
    if (!section) continue;

    const indent = line.length - line.trimStart().length;
    if (indent === 0 || indent > 2) continue; // separadores, continuaciones
    const name = trimmed.split(/\s+/)[0];
    if (name) bySection[section].push(bareName(name));
  }

  const targets = uniq(bySection.target);
  if (!sawTable || !targets.includes(want)) {
    return {
      ok: false,
      code: "uninstall_simulation_unreadable",
      detail: `dnf simulation did not list ${want} for removal`,
    };
  }

  // Otro nombre bajo «Removing:» = el pedido era un «provides» de otro paquete.
  const collateral = uniq([...targets.filter((n) => n !== want), ...bySection.collateral]);
  if (collateral.length > 0) {
    return { ok: false, code: "would_remove_dependents", dependents: collateral };
  }
  return { ok: true, kind: "proceed", unusedDependencies: uniq(bySection.unused) };
}

/**
 * El mensaje que llega al operador. Con la lista, recortada: el porqué de un
 * rechazo sin decir QUÉ se habría llevado obliga a entrar al equipo a mirarlo.
 */
export function dependentsMessage(target: string, dependents: string[], max = 10): string {
  const shown = dependents.slice(0, max).join(", ");
  const rest = dependents.length > max ? ` and ${dependents.length - max} more` : "";
  return (
    `Removing ${target} would also remove ${dependents.length} other package(s) that depend on it: ` +
    `${shown}${rest}. Nothing was uninstalled.`
  );
}
