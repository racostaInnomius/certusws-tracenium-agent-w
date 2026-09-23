// test/core/shutdown.test.ts
//
// La parada del servicio no puede parecer una caída.
//
// El caso real: al auto-actualizarse, WinSW manda CTRL_BREAK al proceso, Node
// lo entrega como SIGBREAK, nadie lo atendía, y Windows mataba el agente con
// 0xC000013A (-1073741510). El SCM lo registraba como «The Tracenium Agent
// Core service terminated unexpectedly», y esa línea roja acabó usándose como
// prueba de que Tracenium había tumbado un servidor que nunca tumbó.

import { describe, expect, it, vi } from "vitest";
import { registerShutdownHandlers, SHUTDOWN_SIGNALS } from "../../src/core/shutdown";

/** Un `process` de mentira: guarda los manejadores y el código de salida. */
function fakeProcess() {
  const handlers = new Map<string, () => void>();
  const exits: number[] = [];
  return {
    handlers,
    exits,
    on(signal: string, handler: () => void) {
      handlers.set(signal, handler);
      return this;
    },
    exit(code: number) {
      exits.push(code);
    },
  };
}

describe("registerShutdownHandlers", () => {
  it("⭐ atiende SIGBREAK: es la señal con la que Windows para un servicio", () => {
    const p = fakeProcess();
    registerShutdownHandlers(p, () => {});
    expect([...p.handlers.keys()]).toContain("SIGBREAK");
  });

  it("y las demás: SIGTERM, SIGINT y el cierre de consola", () => {
    const p = fakeProcess();
    registerShutdownHandlers(p, () => {});
    expect([...p.handlers.keys()].sort()).toEqual(["SIGBREAK", "SIGHUP", "SIGINT", "SIGTERM"]);
  });

  it("🔴 SIEMPRE sale con 0: cualquier otro código es lo que el SCM lee como «terminated unexpectedly»", () => {
    const p = fakeProcess();
    registerShutdownHandlers(p, () => {});
    for (const signal of SHUTDOWN_SIGNALS) p.handlers.get(signal)!();
    expect(p.exits).toEqual([0, 0, 0, 0]);
  });

  it("deja dicho en el log cuál fue la señal, para poder correlacionar después", () => {
    const p = fakeProcess();
    const log = vi.fn();
    registerShutdownHandlers(p, log);
    p.handlers.get("SIGBREAK")!();
    expect(log).toHaveBeenCalledWith("[INFO] SIGBREAK received. Shutting down...");
  });
});
