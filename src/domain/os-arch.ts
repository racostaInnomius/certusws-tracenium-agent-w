// src/domain/os-arch.ts
//
// La arquitectura del EQUIPO, no la del proceso.
//
// ⚠️ `os.arch()` y `process.arch` responden a otra pregunta: «¿para qué
// arquitectura se compiló ESTE binario de Node?». Se contesta en tiempo de
// compilación y no sabe nada del sistema donde corre. Coinciden con la de la
// máquina en una ejecución nativa —el caso de casi toda la flota— pero Windows
// on ARM ejecuta binarios x64 bajo emulación sin decir nada, y ahí las dos
// respuestas se separan:
//
//   W11-JPR-LAB02 (tenant 1) es una VM Windows 11 ARM64 sobre Apple Silicon.
//   El portal la pintaba `x64` en Asset Management → Hardware Inventory
//   mientras los macOS arm64 salían bien, porque en macOS los dos paquetes son
//   nativos y la pregunta equivocada da por casualidad la respuesta correcta.
//
// Por qué importa más que la estética de una columna:
//
//   · ADR-0016 (catálogo global de software) elige el binario por
//     (plataforma, arquitectura). Un equipo ARM64 marcado x64 recibe el
//     paquete equivocado — y el campo no admite «no sé» río abajo: el backend
//     lo guarda tal cual en `host_current_status.arch`.
//   · `agent.arch` del envelope de facts es lo que el backend mira para
//     ofrecer el .msi de un `agent_update`. Con el valor del proceso, un
//     ARM64 emulado se queda clavado en la rama x64 para siempre: se actualiza,
//     sigue emulado, vuelve a decir x64.
//   · La infopage promete «architecture (x64 / arm64)». Un dato que se publica
//     como promesa no puede ser el de otra pregunta.
//
// Cómo se contesta bien en Windows, sin lanzar procesos ni P/Invoke:
//
//   PROCESSOR_ARCHITEW6432 SÓLO existe en un proceso emulado (WOW64), y lo que
//   lleva es la arquitectura NATIVA de la máquina. PROCESSOR_ARCHITECTURE lleva
//   la del proceso. Así que:
//
//     ARM64 nativo        → ARCHITECTURE=ARM64, ARCHITEW6432 ausente
//     x64 sobre ARM64     → ARCHITECTURE=AMD64, ARCHITEW6432=ARM64   ← el bug
//     x86 sobre ARM64     → ARCHITECTURE=x86,   ARCHITEW6432=ARM64
//     x64 nativo          → ARCHITECTURE=AMD64, ARCHITEW6432 ausente
//     x86 sobre x64       → ARCHITECTURE=x86,   ARCHITEW6432=AMD64
//
//   Mirar ARCHITEW6432 primero y ARCHITECTURE después contesta las cinco. No
//   abre un proceso, no depende del PATH y no necesita privilegios — el mismo
//   criterio por el que boot-time.ts no llama a `systeminfo`.
//
// El PrivSvc podría contestarlo con más autoridad (`RuntimeInformation.
// OSArchitecture`, que por dentro es IsWow64Process2), pero eso son un viaje
// de IPC por snapshot y un binario nuevo que publicar; las variables de entorno
// dan la misma respuesta hoy, en un proceso que ya está arrancado. Si algún día
// hiciera falta la vía nativa, el sitio donde enchufarla es `detectOsArch`, y
// sus tres llamadores no se enteran.
//
// ⚠️ macOS y Linux siguen saliendo por el arch del proceso, y NO es un olvido:
// los paquetes de esas dos plataformas se compilan por arquitectura (ver
// `pkg:linux:arm64` / `pkg:macos:x64`), así que el proceso es nativo y las dos
// preguntas coinciden. Rosetta rompería eso igual que la emulación de Windows,
// pero detectarlo exige `sysctl.proc_translated` —un subproceso— y hoy no hay
// ningún .pkg x64 en la flota arm64 que lo justifique.

export type AgentArch = "x64" | "arm64";

/**
 * Lo que hace falta para contestar. Se inyecta entero en vez de leer `process`
 * dentro para que el test pueda montar la máquina emulada, que es justo la que
 * no tenemos a mano.
 */
export interface ArchProbe {
  /** `process.platform` / `os.platform()`: "win32" | "darwin" | "linux" | … */
  platform: string;
  /** `process.arch` / `os.arch()`: la del BINARIO de Node. */
  processArch: string;
  env: Record<string, string | undefined>;
}

export function currentArchProbe(): ArchProbe {
  return { platform: process.platform, processArch: process.arch, env: process.env };
}

/**
 * Los nombres que da Windows no son los de Node. Devuelve `null` —no un
 * valor por defecto— cuando la cadena no es una de las dos que publicamos:
 * quien llama decide qué hacer con el «no sé», y así `x86` no se convierte en
 * `x64` a espaldas de nadie en el camino de reporte.
 */
function normalizeArch(raw: string | undefined | null): AgentArch | null {
  switch (String(raw ?? "").trim().toLowerCase()) {
    case "arm64":
    case "aarch64":
      return "arm64";
    case "x64":
    case "amd64":
    case "x86_64":
      return "x64";
    default:
      return null;
  }
}

/**
 * La arquitectura del SISTEMA OPERATIVO, o `null` si no se puede determinar
 * con certeza. El primitivo: los dos helpers de abajo sólo eligen qué hacer
 * con ese `null`.
 */
export function detectOsArch(probe: ArchProbe = currentArchProbe()): AgentArch | null {
  // Escotilla de escape ya existente en el camino de actualización (y usada
  // por sus tests para fijar el arch del host). Se respeta aquí para que las
  // cuatro respuestas del agente sigan siendo UNA: si se fuerza el instalador
  // arm64, el inventario que lo justifica no puede decir otra cosa.
  const override = normalizeArch(probe.env.TRACENIUM_ARCH);
  if (override) return override;

  if (probe.platform === "win32") {
    // ⚠️ ARCHITEW6432 PRIMERO. Es el único de los dos que habla de la máquina;
    // el otro habla del proceso, que es exactamente el dato que este módulo
    // existe para dejar de publicar.
    const native = normalizeArch(probe.env.PROCESSOR_ARCHITEW6432);
    if (native) return native;

    const current = normalizeArch(probe.env.PROCESSOR_ARCHITECTURE);
    if (current) return current;

    // Ni una ni otra: entorno recortado. Caemos al proceso abajo, que como
    // mínimo es cierto sobre el proceso.
  }

  return normalizeArch(probe.processArch);
}

/**
 * Para INFORMAR (inventario, envelope de facts, enrolamiento). Prefiere la del
 * sistema; cuando no se sabe, devuelve la del proceso TAL CUAL en vez de
 * inventarse una de las dos que publicamos — un `ia32` o un `ppc64` siguen
 * saliendo con su nombre en lugar de disfrazarse de x64.
 */
export function reportedOsArch(probe: ArchProbe = currentArchProbe()): string {
  return detectOsArch(probe) ?? probe.processArch;
}

/**
 * Para ELEGIR UN BINARIO (self-update). Aquí no cabe el «no sé»: sólo hay dos
 * ramas publicadas y hay que entrar por una. Mantiene el desempate histórico
 * —lo que no sea arm64 se trata como x64— para no cambiar a qué .msi apunta un
 * equipo que hoy se actualiza bien.
 */
export function resolveOsArch(probe: ArchProbe = currentArchProbe()): AgentArch {
  return detectOsArch(probe) ?? (probe.processArch === "arm64" ? "arm64" : "x64");
}

/** La del proceso, sin adornos. Viaja junto a la del sistema para que una
 *  discrepancia se lea como «este equipo está emulando» y no como un dato
 *  contradictorio. */
export function processArch(probe: ArchProbe = currentArchProbe()): string {
  return probe.processArch;
}
