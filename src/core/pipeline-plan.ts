// src/core/pipeline-plan.ts
//
// Qué pipelines deben estar armados, cada cuánto, y si de verdad van a hacer
// algo. Puro: el scheduler lo lee de la policy y decide con el diff.
//
// ⚠️ EL PROBLEMA QUE RESUELVE (prod, 16-sep)
// `PolicyRuntime.applyUpdate()` emite TODOS sus eventos de cambio en cada
// aplicación, haya cambiado algo o no, y el backend reenvía la misma policy
// (el reconciliador del heartbeat; grpc-stream la reaplica aunque el hash
// coincida). Cinco de esos eventos llamaban a `startPipelines`, que para todo,
// re-arma y lanza EN EL ACTO compliance, CDP y el escaneo de parches. Resultado:
// cada reenvío ponía a la flota entera de un tenant a escanear Windows Update a
// la vez contra el mismo WSUS y a hacer cola en el carril lento del PrivSvc.
// T111: 1.788 escaneos de parches en 14 días para 55 equipos con ciclo de 24 h,
// ráfagas de 73 en una hora; 95 fallos «Windows Update scan exceeded 150s».
//
// Ahora un evento de policy sólo toca lo que cambió:
//   · nada cambió                → nada (ni re-armar, ni escanear)
//   · cambió armado o intervalo  → re-armar ESE pipeline, sin escanear
//   · pasó a hacer algo de verdad → re-armar y escanear ya (activar PMP en el
//                                   portal sigue dando el primer escaneo al momento)

export const PIPELINE_KEYS = ["inventory", "update", "compliance", "cdp", "patch"] as const;
export type PipelineKey = (typeof PIPELINE_KEYS)[number];

export interface PipelineState {
  /** El scheduler le arma temporizador (la condición de módulo de hoy). */
  armed: boolean;
  /**
   * Además su run() hará trabajo: armado Y su plugin habilitado. Es la
   * condición con la que cada run*() decide no salir antes de tiempo, y la
   * que importa para «acaba de activarse».
   */
  effective: boolean;
  intervalSeconds: number;
}

export type PipelinePlan = Record<PipelineKey, PipelineState>;

/** Lo mínimo de PolicyRuntime que hace falta. */
export interface PlanSource {
  isInventoryEnabled(): boolean;
  isUpdateEnabled(): boolean;
  isComplianceEnabled(): boolean;
  isPatchEnabled(): boolean;
  pluginEnabled(key: string): boolean;
  getInventoryInterval(): number;
  getUpdateInterval(): number;
  getComplianceInterval(): number;
  getCdpInterval(): number;
  getPatchInterval(): number;
}

/**
 * ⚠️ Cada `effective` repite a propósito el guard del run*() correspondiente
 * en scheduler.ts. Si aquí faltara el plugin, activar PMP en un tenant con el
 * módulo ya activo no cambiaría el plan y el primer escaneo esperaría 24 h.
 */
export function readPipelinePlan(p: PlanSource): PipelinePlan {
  const inventory = p.isInventoryEnabled();
  const update = p.isUpdateEnabled();
  const compliance = p.isComplianceEnabled();
  const cdp = p.pluginEnabled("cdp");
  const patch = p.isPatchEnabled();
  return {
    inventory: { armed: inventory, effective: inventory && p.pluginEnabled("amp"), intervalSeconds: p.getInventoryInterval() },
    update: { armed: update, effective: update, intervalSeconds: p.getUpdateInterval() },
    compliance: { armed: compliance, effective: compliance && p.pluginEnabled("scp"), intervalSeconds: p.getComplianceInterval() },
    cdp: { armed: cdp, effective: cdp, intervalSeconds: p.getCdpInterval() },
    patch: { armed: patch, effective: patch && p.pluginEnabled("pmp"), intervalSeconds: p.getPatchInterval() },
  };
}

export interface PipelineDiff {
  /** Hay que parar su temporizador y, si sigue armado, volver a armarlo. */
  rearm: PipelineKey[];
  /** Acaba de pasar a hacer trabajo: correr ya. */
  runNow: PipelineKey[];
}

export function diffPipelinePlan(prev: PipelinePlan | null, next: PipelinePlan): PipelineDiff {
  const rearm: PipelineKey[] = [];
  const runNow: PipelineKey[] = [];
  for (const key of PIPELINE_KEYS) {
    const a = prev?.[key];
    const b = next[key];
    if (!a || a.armed !== b.armed || (b.armed && a.intervalSeconds !== b.intervalSeconds)) {
      rearm.push(key);
    }
    if (b.effective && !a?.effective) runNow.push(key);
  }
  return { rearm, runNow };
}

/**
 * Plugins y módulos habilitados, como firma. Cambia ⇒ las capabilities que
 * reporta el inventario cambian y conviene mandarlas ya (el motivo del tick de
 * inventario forzado en pluginsChanged/modulesChanged). No cambia ⇒ ese tick
 * sólo recolectaba lo mismo otra vez.
 */
export function capabilitySignature(plugins: string[], modules: string[]): string {
  return `${[...plugins].sort().join(",")}|${[...modules].sort().join(",")}`;
}
