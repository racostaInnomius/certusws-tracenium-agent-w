// Lo que un `.app` dice de sí mismo en su Info.plist.
//
// ⚠️ Por qué existe este archivo, y por qué NO se usa `mdls`.
//
// El colector leía `kMDItemCFBundleIdentifier` con `mdls`, que consulta el
// índice de Spotlight en vez del bundle. Cuando Spotlight no puede resolver la
// ruta, `mdls` sale con código 1 y el identificador se pierde — y no se pierde
// en una app suelta: se pierde en TODAS las de esa máquina a la vez.
//
// Medido en la flota (2026-08-20, fuente macos-app-bundle):
//
//   Clifi, Mauricio, Rodrigo, Vivian ...  0% sin bundle id
//   Bob ................................  3%
//   JPR-MacBookPro ..................... 98%
//   Diego-3 ............................ 94%
//
// El identificador es la LLAVE con la que el colector fusiona la misma app
// vista por dos fuentes (el bundle y el recibo de pkgutil). Sin llave, la
// fusión no se rompe ruidosamente: se apaga en silencio para ese equipo. Por
// eso JPR-MacBookPro, con 98% de llaves ausentes, era el peor de la flota con
// 286 filas y cinco versiones de Keynote conviviendo.
//
// El Info.plist es el bundle mismo. No depende de que un índice esté sano, y
// en la misma máquina donde `mdls` fallaba al 98% dio identificador en 43 de 48
// apps y versión en 42 de 48 — versión que el colector anterior ni siquiera
// pedía.

export interface MacBundleInfo {
  /** CFBundleIdentifier — la llave de fusión entre fuentes. */
  bundleId: string | null;
  /**
   * CFBundleShortVersionString, la que el usuario reconoce ("129.0.2").
   *
   * Se prefiere sobre CFBundleVersion, que es el número de build del vendor
   * ("12924.8.19") y no cruza con ningún catálogo. PMP third-party y la
   * detección de CVE cruzan por nombre + versión, así que la que sirve es la
   * que el vendor publica.
   */
  version: string | null;
  /** CFBundleDisplayName / CFBundleName, cuando difieren del nombre del archivo. */
  displayName: string | null;
}

const EMPTY: MacBundleInfo = { bundleId: null, version: null, displayName: null };

/**
 * Un valor de plist que sirva como texto, o null.
 *
 * Los plists traen números, booleanos y arreglos; un CFBundleShortVersionString
 * numérico (2.0 en vez de "2.0") es legal y aparece. Se acepta el número y se
 * rechaza todo lo demás, en vez de dejar que un `String(objeto)` meta
 * "[object Object]" en el inventario.
 */
function plistString(value: unknown): string | null {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed ? trimmed : null;
  }
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return null;
}

/**
 * Extrae identidad y versión de la salida JSON de `plutil` sobre un Info.plist.
 *
 * Puro a propósito: el colector no se puede ejercitar sin una Mac, pero esto
 * sí, que es donde vive la decisión de qué campo gana.
 */
export function parseBundleInfo(stdout: unknown): MacBundleInfo {
  if (typeof stdout !== "string") return EMPTY;
  const text = stdout.trim();
  if (!text) return EMPTY;

  let parsed: any;
  try {
    parsed = JSON.parse(text);
  } catch {
    // plutil escribe sus errores en stdout tal como hacía mdls. No es JSON, no
    // es un bundle, y tratarlo como dato es cómo la ruta del archivo terminaba
    // guardada en el lugar del identificador.
    return EMPTY;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return EMPTY;

  return {
    bundleId: plistString(parsed.CFBundleIdentifier),
    version:
      plistString(parsed.CFBundleShortVersionString) ??
      // Último recurso: sin la versión corta, un build number identifica la
      // instalación mejor que un null, aunque no cruce con catálogos.
      plistString(parsed.CFBundleVersion),
    displayName:
      plistString(parsed.CFBundleDisplayName) ?? plistString(parsed.CFBundleName),
  };
}
