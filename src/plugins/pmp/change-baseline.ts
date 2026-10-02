// src/plugins/pmp/change-baseline.ts
//
// ADR-0038 F2 — la foto previa de un CAMBIO, no sólo de un parche. Antes de un
// despliegue de software, una remediación o un reinicio bajo demanda, si el
// control plane lo pide (`payload.verification`), se fotografía lo mismo que
// antes de un parche: servicios automáticos en marcha, las comprobaciones
// declaradas y qué escucha el equipo. Después, un `patch_verify` con el id del
// cambio compara.
//
// Antes de `patch_install` se toma SIEMPRE (F1). En los demás, sólo si se pide:
// un despliegue de Zoom a 1.000 puestos no necesita 1.000 verificaciones; el
// control plane lo pide donde hay comprobaciones declaradas.
//
// Nunca bloquea el cambio: si la foto falla, la verificación dirá «sin foto».

import { defaultProbeDeps, type ProbeDeps } from "../live-query/probes";
import { parseChecks, runCheck, snapshotServices, type VerificationBaseline } from "./verification";
import { observeListeners } from "./listeners";
import { saveBaseline } from "./verification-store";

const DRY_RUN_MODES = new Set(["dry_run", "revert_dry_run"]);

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

/** ¿Hay que fotografiar antes de este job? PURO. */
export function wantsBaseline(jobType: string, payload: any): boolean {
  if (jobType === "patch_install") return String(payload?.mode || "install").trim().toLowerCase() === "install";
  if (!isObject(payload?.verification)) return false;
  if (jobType === "software_install" || jobType === "device_reboot") return true;
  if (jobType === "patch_remediate") {
    // Un ensayo no cambia nada: no hay qué verificar. Un lote, si algún fix
    // escribe de verdad.
    const modes: string[] = Array.isArray(payload?.items)
      ? payload.items.map((i: any) => String(i?.mode || "apply"))
      : [String(payload?.mode || "apply")];
    return modes.some((m) => !DRY_RUN_MODES.has(m));
  }
  return false;
}

export async function captureChangeBaseline(
  jobId: string,
  payload: any,
  opts: { deps?: ProbeDeps; save?: (b: VerificationBaseline) => void; logger?: { warn?: (...a: any[]) => void } } = {}
): Promise<void> {
  try {
    const deps = opts.deps ?? defaultProbeDeps();
    const checks = parseChecks(payload?.verification?.checks);
    const [services, checksBefore, listeners] = await Promise.all([
      snapshotServices(deps),
      Promise.all(checks.map((c) => runCheck(deps, c))),
      observeListeners(deps),
    ]);
    (opts.save ?? saveBaseline)({
      jobId,
      capturedAt: new Date().toISOString(),
      services,
      checks,
      checksBefore,
      ...(listeners.ok ? { listeners: listeners.listeners } : {}),
    });
  } catch (err) {
    opts.logger?.warn?.("[pmp] pre-change verification snapshot failed", { jobId, err: String(err) });
  }
}
