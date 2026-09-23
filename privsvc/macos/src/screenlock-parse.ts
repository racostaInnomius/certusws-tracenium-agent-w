// privsvc/macos/src/screenlock-parse.ts
//
// Parser for `sysadminctl -screenLock status`. On modern macOS
// (Ventura+) the GUI's "require password after screen saver / sleep"
// toggle no longer writes `askForPassword` to com.apple.screensaver —
// the key simply does not exist even with the setting ON — so the
// defaults-based collector was structurally not_applicable on every
// unmanaged Mac. sysadminctl is the supported way to read the live
// setting (per-user; must run in the console user's context).
//
// Output quirks this pins:
//   - sysadminctl prints to STDERR, with a syslog-style prefix:
//       2026-08-19 22:17:55.934 sysadminctl[55361:106849336] screenLock delay is immediate
//   - three shapes: "screenLock delay is immediate",
//     "screenLock delay is N seconds", "screenLock is off".
//
// Absent ≠ compliant: anything unrecognized returns undefined, never a
// verdict.

export type ScreenLockStatus = {
  passwordRequired: boolean;
  // 0 = immediately; undefined when the lock is off.
  delaySeconds: number | undefined;
};

export function parseSysadminctlScreenLock(output: string | null | undefined): ScreenLockStatus | undefined {
  const text = String(output ?? "");
  if (/screenLock\s+delay\s+is\s+immediate/i.test(text)) {
    return { passwordRequired: true, delaySeconds: 0 };
  }
  const delay = text.match(/screenLock\s+delay\s+is\s+(\d+)\s+second/i);
  if (delay) {
    return { passwordRequired: true, delaySeconds: Number(delay[1]) };
  }
  if (/screenLock\s+is\s+off/i.test(text)) {
    return { passwordRequired: false, delaySeconds: undefined };
  }
  return undefined;
}

/**
 * ¿Se pudo leer el bloqueo de pantalla, y si no, por qué?
 *
 * ⚠️ La diferencia que esto fija: "no está puesto" es un veredicto; "no había
 * nadie con sesión" no lo es. Callar el valor hacía que el control plane
 * resolviera `not_applicable` —"a este equipo no le toca"— y cerrara el
 * hallazgo. Un Mac de T113 alternó pass → not_applicable → pass en 4 segundos
 * el 23-sep-2026 al pasar por la pantalla de login.
 *
 * El backend lee `available: false` + `reason` y deja el check como NO
 * EVALUADO: conserva el veredicto anterior y no escribe evento.
 */
export function screenLockAvailability(input: {
  /** El valor resuelto, o undefined si ninguna lectura dio uno. */
  passwordRequired: boolean | undefined;
  /** Si había usuario en la consola: sin él, las lecturas por usuario no corren. */
  hasConsoleUser: boolean;
  source: string;
}): { available: true } | { available: false; reason: "no_console_user" | "unavailable" | "not_readable" } {
  if (input.passwordRequired !== undefined) return { available: true };
  if (!input.hasConsoleUser) return { available: false, reason: "no_console_user" };
  // Con usuario: o las lecturas fallaron, o corrieron y no hay nada que leer —
  // en macOS moderno el interruptor no escribe la clave, así que tampoco se
  // puede afirmar cumplimiento desde ahí.
  return { available: false, reason: input.source === "unavailable" ? "unavailable" : "not_readable" };
}
