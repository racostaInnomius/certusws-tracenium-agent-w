// src/domain/os-revision.ts
//
// La REVISIÓN de Windows (el UBR), que es el número que dice si un equipo está
// parcheado.
//
// EL CASO QUE LO MOTIVA
//
// El 25-sep-2026, con RDP caído en `msi-erp` (tenant 111) por un defecto
// documentado de KB5122882, la pregunta operativa era una sola: «¿qué OTROS
// equipos están en esa misma build?». No se podía contestar desde el inventario.
// `host_current_status.os_version` guarda `10.0.20348` — la build, cortada justo
// ANTES de la cifra que importa. `20348` es Windows Server 2022 y no dice nada
// sobre parches: lo dice `20348.5622`.
//
// Y el dato ya estaba en la flota, en el sitio equivocado: el colector de CDP lo
// lee para decidir capacidad TLS (`plugins/cdp/providers/os-tls-capability.ts`)
// y lo deja en `cdp_host_tls_capability.ubr`, una tabla que habla de TLS, está
// detrás del plugin de CDP y a la que nadie va a preguntar por parches. En T111
// cubría 46 de 57 equipos; los 11 restantes —tres de ellos servidores— no tenían
// ninguna fila. Así que había que contestar a mano y con huecos.
//
// Esto NO sustituye a ese colector: CDP sigue necesitando el valor junto a su
// propia medición. Lo que hace es ponerlo también donde se pregunta por el
// parque, en el inventario, para todos los equipos y sin depender de qué plugins
// tenga contratado el cliente.
//
// POR QUÉ SE LEE DEL REGISTRO Y NO DE `systeminformation`
//
// `si.osInfo().release` devuelve `10.0.20348` en Windows: la revisión no está.
// El único sitio donde vive es
// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UBR`, un REG_DWORD legible
// por cualquier usuario — no hace falta privsvc ni elevación.
//
// ⚠️ Se lee con `bootstrap/registry.ts` a propósito, que invoca `reg.exe` con
// `execFileSync` y vista `/reg:64`, y NO con `execSync`: esa diferencia es la
// que hizo que DanielA-PC pasara semanas hablando con `localhost` (ver la
// cabecera de ese módulo). Leer un DWORD con ese módulo era imposible hasta
// ahora — sólo admitía cadenas — y esa era la razón callada de que esto no se
// hubiera hecho antes.

import { readRegistryValue } from "../bootstrap/registry";

/** Donde Windows guarda build, revisión y versión comercial. */
export const CURRENT_VERSION_KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

export interface OsRevisionRead {
  /** El UBR como entero, o null si no se pudo leer. */
  revision: number | null;
  /** Por qué no se pudo. Ausente cuando `revision` no es null. */
  detail?: string;
}

/**
 * Lee el UBR. Nunca lanza.
 *
 * Fuera de Windows devuelve null sin intentar nada: el UBR es un concepto de
 * Windows, no un dato que falte en macOS y Linux. El `detail` lo dice, para que
 * quien lo registre no lo cuente como una avería.
 */
export function readOsRevision(): OsRevisionRead {
  if (process.platform !== "win32") {
    return { revision: null, detail: "not windows" };
  }

  const { value, detail } = readRegistryValue(CURRENT_VERSION_KEY, "UBR");
  if (value === null) return { revision: null, detail };

  // `readRegistryValue` ya devuelve el decimal de un REG_DWORD. Se valida igual
  // antes de convertir: un dato del registro que no sea un entero es una
  // lectura mala, y `Number("")` es 0 — un cero que se leería como «revisión 0»,
  // que es una build REAL y existente. Confundir «no pude leer» con «revisión 0»
  // es exactamente el error que este módulo existe para no cometer.
  if (!/^\d+$/.test(value)) {
    return { revision: null, detail: `UBR no es un entero: ${JSON.stringify(value)}` };
  }

  const n = Number(value);
  if (!Number.isSafeInteger(n)) {
    return { revision: null, detail: `UBR fuera de rango: ${value}` };
  }

  return { revision: n };
}

/**
 * La versión completa `build.revisión` a partir del release que ya reporta
 * `systeminformation` y del UBR.
 *
 * Se devuelve APARTE y no se pisa `release`, por dos razones concretas:
 *
 *   · `host_current_status.os_version` la consumen hoy la agrupación de activos,
 *     el catálogo de ciclo de vida de SO (`os-lifecycle-sync`), la
 *     aplicabilidad de frameworks y los criterios de grupos dinámicos. Alargar
 *     la cadena de `10.0.20348` a `10.0.20348.5622` partiría cada grupo en
 *     tantos trozos como revisiones haya en la flota.
 *   · Un equipo cuya revisión no se pudo leer seguiría teniendo su `os_version`
 *     de siempre. La revisión es un dato ADICIONAL que puede faltar, no una
 *     versión mejor de uno que ya existe.
 */
export function composeFullVersion(release: unknown, revision: number | null): string | null {
  if (typeof release !== "string" || !release.trim()) return null;
  const base = release.trim();
  return revision === null ? base : `${base}.${revision}`;
}
