// src/plugins/pmp/patch-selection.ts
//
// Los parches que pide un patch_install, o NINGUNO. PURO.
//
// ⚠️ UNA LISTA VACÍA NO ES «NADA», ES «TODO» (23-sep-2026). El script de Windows
// Update del privsvc seleccionaba, sin lista, TODO lo que encontrara la
// búsqueda. El 8-sep un job con `kbArticleIds: []` instaló así 3
// actualizaciones que nadie había elegido, con reinicio.
//
// El control plane ya no crea jobs sin lista y el privsvc nuevo los rechaza,
// pero entre los dos hay versiones que conviven: un privsvc viejo sigue leyendo
// «vacío» como «todo». Esta es la barrera que viaja con el agente, que se
// actualiza antes que el MSI.

/**
 * Los identificadores limpios, o `null` si no queda ninguno.
 *
 * ⚠️ `null`, no `[]`: un array vacío es exactamente el valor que el script
 * viejo convierte en «instala todo», y devolverlo invitaría a pasarlo.
 */
export function selectedPatchIds(payload: unknown): string[] | null {
  const lista = (payload as { kbArticleIds?: unknown } | null | undefined)?.kbArticleIds;
  if (!Array.isArray(lista)) return null;
  const ids = lista.map((item) => String(item ?? "").trim()).filter(Boolean);
  return ids.length > 0 ? ids : null;
}

/**
 * Forma de un id de parche. Misma regla que el control plane
 * (`isSafePatchId`), repetida aquí porque el agente es la última barrera antes
 * del privsvc y un control plane viejo —o un payload hecho a mano— puede no
 * haberla aplicado.
 *
 * ⚠️ POR QUÉ (auditoría 1-oct-2026): el PrivSvc de Windows interpola cada id
 * dentro de una cadena de PowerShell entre comillas dobles que corre como
 * SYSTEM, y `KB1$(…)` ejecutaba lo de dentro. En Linux un id que empiece por
 * `-` llega a apt/dnf como opción (`-oDPkg::Pre-Invoke::=…`).
 */
const PATCH_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 \u00A0._:+~(),-]{0,199}$/;
/** En Windows la selección es por artículo KB: nada más tiene sentido. */
const WINDOWS_KB_PATTERN = /^KB\d{1,10}$/i;

/** Los ids que NO tienen forma de id para esta plataforma (vacío = todos bien). */
export function unsafePatchIds(ids: string[], platform: NodeJS.Platform = process.platform): string[] {
  const forma = platform === "win32" ? WINDOWS_KB_PATTERN : PATCH_ID_PATTERN;
  return ids.filter((id) => !forma.test(id));
}

