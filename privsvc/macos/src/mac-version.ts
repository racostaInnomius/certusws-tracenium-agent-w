// privsvc/macos/src/mac-version.ts
//
// Comparar versiones (de apps y de macOS) sin nada de E/S, para poder probarlo.
//
// ⚠️ SIN IMPORTS A PROPÓSITO. sdp.ts arrastra logger, rutas y execFile; esto
// se importa desde los tests sin arrastrar nada de eso.

/**
 * Compara dos versiones con puntos, número a número. Los trozos que faltan
 * cuentan como 0 (`13` == `13.0` == `13.0.0`) y lo que no empieza por un
 * número, también.
 *
 * Se movió aquí desde sdp.ts, donde ya lo usaba la regla de detección
 * `bundle_version`; ahora lo comparte con la guarda de SO de abajo.
 *
 * ⚠️ Sirve para macOS porque sus versiones son numéricas y crecientes, también
 * a través del salto de 15 a 26 (macOS pasó a numerarse por año): 26 > 15.
 */
export function compareSemver(a: string, b: string): number {
  const parse = (v: string) =>
    String(v || "")
      .split(/[.-]/)
      .map((seg) => {
        const m = /^\d+/.exec(seg);
        return m ? Number(m[0]) : 0;
      });
  const av = parse(a);
  const bv = parse(b);
  const n = Math.max(av.length, bv.length);
  for (let i = 0; i < n; i++) {
    const ai = av[i] ?? 0;
    const bi = bv[i] ?? 0;
    if (ai !== bi) return ai > bi ? 1 : -1;
  }
  return 0;
}

/** ¿Parece una versión de macOS? Al menos un número delante. */
function looksLikeVersion(v: string | null | undefined): v is string {
  return typeof v === "string" && /^\d+(\.\d+)*/.test(v.trim());
}

/**
 * ¿Este Mac es demasiado viejo para la app que se va a copiar?
 *
 * 🔴 POR QUÉ EXISTE (30-sep, T1). Un deploy de Chrome 154 (DMG) llegó a
 * `iMac-de-iMac-2`, con macOS 12.7.6. Chrome 154 exige 13.0. El agente borró
 * el Chrome 150 que funcionaba, copió el nuevo, y devolvió exit 0: navegador
 * roto y deploy en verde.
 *
 * Un DMG no tiene instalador: es una copia de ficheros, y copiar nunca falla
 * por la versión del SO. Un MSI tiene sus LaunchConditions y un PKG su
 * `allowed-os-versions`; el DMG no tiene nada. La versión mínima la declara la
 * propia app en `LSMinimumSystemVersion` —la clave que leyó el aviso del Finder
 * («requiere macOS 13.0 o posterior»)—, así que se usa esa: no la teclea nadie.
 *
 * ⚠️ SI NO SE PUEDE SABER, SE DEJA PASAR. Sin la clave (muchas apps no la
 * declaran) o con una versión ilegible no hay nada que comparar, y bloquear
 * todas las instalaciones de Mac por un dato ausente sería peor que el caso
 * que esto evita. Es el comportamiento de antes.
 */
export function osTooOld(
  minimumSystemVersion: string | null | undefined,
  currentOsVersion: string | null | undefined
): boolean {
  if (!looksLikeVersion(minimumSystemVersion) || !looksLikeVersion(currentOsVersion)) {
    return false;
  }
  return compareSemver(currentOsVersion.trim(), minimumSystemVersion.trim()) < 0;
}
