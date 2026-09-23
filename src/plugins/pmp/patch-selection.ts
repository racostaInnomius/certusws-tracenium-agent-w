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
