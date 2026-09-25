// src/update/battery-gate.ts
//
// Si el equipo tiene tan poca batería que instalar el agente es un riesgo.
//
// Que el portátil vaya con batería NO es motivo para no actualizar: hasta
// 1.1.81 la tarea de Windows se creaba con los valores por defecto de
// `schtasks` ("No Start On Batteries"), y W11_JPR_LAB se quedó en 1.1.77 con
// cuatro jobs de update aceptados y ninguna tarea arrancada (25-sep). Un
// portátil que casi siempre va con batería no se actualizaba nunca.
//
// Lo que sí es un riesgo es quedarse sin batería A MITAD del instalador: el
// MSI para los servicios, reemplaza binarios y los vuelve a arrancar, y un
// apagón en medio deja el agente parado o a medio instalar. Ese es el único
// caso que se aplaza, y se decide aquí —donde se puede decir por qué— y no en
// Task Scheduler, que calla.

import si from "systeminformation";
import { normalizeBattery, type BatteryRuntime } from "../domain/battery";

/** Por debajo de esta carga, sin corriente, el update se aplaza. */
export const UPDATE_MIN_BATTERY_PERCENT = 10;

/** Prefijo del `skipped` cuando el update se aplazó por batería baja. */
export const UPDATE_BATTERY_DEFERRED_PREFIX = "battery_low:";

/** Tope de la lectura: una consulta WMI colgada no puede retener el update. */
const READ_TIMEOUT_MS = 15_000;

/**
 * La carga que impide actualizar, o null si se puede seguir.
 *
 * Solo aplaza cuando lo sabe: sin batería, sin porcentaje, enchufado o
 * cargando, se sigue. Una lectura que falla nunca bloquea el update — sería
 * volver a lo de antes, un equipo atascado sin motivo visible.
 */
export function batteryBlocksUpdate(battery: BatteryRuntime | undefined): number | null {
  if (!battery?.present || battery.percent === null) return null;
  if (battery.acConnected === true || battery.isCharging === true) return null;
  return battery.percent < UPDATE_MIN_BATTERY_PERCENT ? battery.percent : null;
}

/** La batería ahora mismo, o undefined si no se pudo leer a tiempo. */
export async function readBatteryForUpdate(): Promise<BatteryRuntime | undefined> {
  let timer: NodeJS.Timeout | undefined;
  try {
    const timeout = new Promise<undefined>((resolve) => {
      timer = setTimeout(() => resolve(undefined), READ_TIMEOUT_MS);
    });
    const raw = await Promise.race([si.battery(), timeout]);
    return normalizeBattery(raw);
  } catch {
    return undefined;
  } finally {
    if (timer) clearTimeout(timer);
  }
}
