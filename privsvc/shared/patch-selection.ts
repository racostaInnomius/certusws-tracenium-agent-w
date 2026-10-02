// privsvc/shared/patch-selection.ts
//
// La selección de un patch.install en los privsvc de Linux y macOS. PURO.
//
// ⚠️ POR QUÉ (auditoría PMP 1-oct-2026). Los dos privsvc leían una lista
// VACÍA como «todo»: Linux hacía `apt-get dist-upgrade -y` (que además puede
// DESINSTALAR paquetes) o `dnf upgrade -y`, y macOS `softwareupdate --all`.
// El control plane y el agente ya lo rechazan, pero el privsvc es la última
// barrera y no se fía de quien le llame. Y un id que empiece por `-` llegaría
// a apt/dnf como OPCIÓN (`-oDPkg::Pre-Invoke::=…` ejecuta como root).
//
// Instalar todo lo pendiente se pide mandando la LISTA de lo pendiente.

/** Misma forma que el control plane (`isSafePatchId`) y el agente. */
const PATCH_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9  ._:+~(),-]{0,199}$/;

export type PatchSelection =
  | { ok: true; ids: string[] }
  | { ok: false; code: "patch_install_no_selection" | "patch_install_invalid_id"; message: string };

export function readPatchSelection(params: Record<string, unknown> | undefined): PatchSelection {
  const raw = params?.kbArticleIds;
  const ids = Array.isArray(raw) ? raw.map((item) => String(item ?? "").trim()).filter(Boolean) : [];
  if (ids.length === 0) {
    return {
      ok: false,
      code: "patch_install_no_selection",
      message:
        "patch.install needs an explicit list of updates; an empty list is refused " +
        "instead of installing everything available.",
    };
  }
  const malformed = ids.filter((id) => !PATCH_ID_PATTERN.test(id));
  if (malformed.length > 0) {
    return {
      ok: false,
      code: "patch_install_invalid_id",
      message: `patch.install refused ${malformed.length} of ${ids.length} ids that are not package or update names.`,
    };
  }
  return { ok: true, ids };
}
