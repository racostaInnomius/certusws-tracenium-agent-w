// src/transport/heartbeat-message.ts
//
// El mensaje de heartbeat que el agente escribe en el stream.
//
// ⭐ POR QUÉ LLEVA `uptimeSeconds`
// El backend responde «¿volvió este equipo del reinicio que pidió el parche?»
// con la HORA DE ARRANQUE, que deriva de este campo con su propio reloj. La
// prueba de campo de MSIG-TSPDC (12-sep-2026) demostró que la alternativa —
// «visto después del parche»— no prueba nada: Windows tardó seis minutos en
// reiniciar tras la petición, con los heartbeats fluyendo todo ese rato.
//
// El campo existía en el proto desde siempre, pero sólo lo rellenaba el
// heartbeat propio del PrivSvc de Windows (`Environment.TickCount64`, cada
// 30 s). Este, el que manda el AgentCore en las tres plataformas, iba sin él,
// y en proto3 un int64 ausente llega como 0. Linux y macOS no mandaban nunca
// el dato.
//
// `os.uptime()` es el uptime de la MÁQUINA (GetTickCount64 en Windows,
// /proc/uptime en Linux, kern.boottime en macOS), no el del proceso: con
// `process.uptime()` cada reciclaje del AgentCore parecería un reinicio.

import os from "os";
import { normalizeUptimeSeconds } from "../domain/boot-time";

export interface HeartbeatMessage {
  deviceId: string;
  tenantId: string;
  agentVersion: string;
  ts: number;
  /**
   * Segundos desde que arrancó el SISTEMA. Se omite cuando no hay un valor
   * positivo: en proto3 el 0 es indistinguible de «no vino», y el backend lo
   * trata como «no se sabe». Mandar un 0 legítimo no añadiría nada.
   */
  uptimeSeconds?: number;
}

export function buildHeartbeat(input: {
  deviceId: string;
  tenantId: string;
  agentVersion: string;
  nowMs?: number;
  /** Inyectable para tests; por defecto `os.uptime()`. */
  readUptime?: () => unknown;
}): HeartbeatMessage {
  const msg: HeartbeatMessage = {
    deviceId: input.deviceId,
    tenantId: input.tenantId,
    agentVersion: input.agentVersion,
    ts: input.nowMs ?? Date.now(),
  };

  let raw: unknown;
  try {
    raw = (input.readUptime ?? (() => os.uptime()))();
  } catch {
    // Un fallo leyendo el contador no puede tumbar el heartbeat: es la señal
    // de vida del agente, y sin él el stream se declara muerto.
    raw = null;
  }
  const uptime = normalizeUptimeSeconds(raw);
  if (uptime !== null && uptime > 0) msg.uptimeSeconds = uptime;

  return msg;
}
