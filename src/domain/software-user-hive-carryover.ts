// src/domain/software-user-hive-carryover.ts
//
// Lo que no se vio porque el perfil no estaba cargado NO se desinstaló.
//
// ⚠️ EL DEFECTO (T111, 25–27 sep). Las apps instaladas por usuario (Teams,
// RingCentral, Zoom, OneDrive, el applet de LogMeIn…) viven en el NTUSER.DAT
// de su perfil, y el PrivSvc —que corre como SYSTEM— sólo las ve mientras
// HKEY_USERS\<SID> está montado, es decir, con sesión. El delta comparaba ese
// inventario parcial contra la línea base y las daba por DESINSTALADAS al
// cerrar sesión y por instaladas al volver: DESKTOP-CAST-PV «perdía» todo a
// las ~18:28Z y lo «reinstalaba» a las ~06:28Z, con el mismo install_id, y la
// pestaña Activity lo contaba dos veces al día.
//
// El PrivSvc dice ahora qué perfiles EXISTEN y no pudo leer
// (`userHives.unread`). De ésos se conserva lo que la línea base ya sabía,
// tal cual: ni se quita ni se «actualiza». Un perfil borrado del equipo ya no
// sale en esa lista, así que sus apps sí se van.
//
// Un PrivSvc anterior no manda la lista: `unreadSids` llega null y nada
// cambia (la regla de antes, que es la única honesta sin el dato).

import type { SoftwareApplication } from "./normalize-app";

// Mismo formato que UninstallIdentity.BuildUserKeyPath en el PrivSvc:
// HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<sub>
// y el mismo criterio de persona que IsUserProfileHive: AD/local (S-1-5-21-…)
// y Entra ID (S-1-12-1-…).
const USER_KEY_PATH = /^HKU\\(S-1-(?:5-21|12-1)-\d+-\d+-\d+-\d+)\\/i;

/** El SID del perfil al que pertenece una app por usuario; null si es de máquina. */
export function userSidOfKeyPath(keyPath: string | null | undefined): string | null {
  const m = USER_KEY_PATH.exec(keyPath ?? "");
  return m ? m[1].toUpperCase() : null;
}

/**
 * El inventario de este escaneo más lo que la línea base tenía de los perfiles
 * que no se pudieron leer y hoy no aparece.
 */
export function carryOverUnreadUserApps(
  current: SoftwareApplication[],
  previous: SoftwareApplication[],
  unreadSids: readonly string[] | null | undefined
): { apps: SoftwareApplication[]; carried: number } {
  if (!unreadSids || unreadSids.length === 0) return { apps: current, carried: 0 };
  const unread = new Set(unreadSids.map((s) => s.toUpperCase()));
  const seen = new Set(current.map((a) => a.installId).filter(Boolean));
  const carried = previous.filter((p) => {
    if (!p.installId || seen.has(p.installId)) return false;
    const sid = userSidOfKeyPath(p.uninstallKeyPath);
    return sid !== null && unread.has(sid);
  });
  return carried.length === 0 ? { apps: current, carried: 0 } : { apps: [...current, ...carried], carried: carried.length };
}
