import { describe, it, expect } from "vitest";
import {
  bootTimeFromProcStat,
  bootTimeFromUptime,
  normalizeUptimeSeconds,
  parseProcStatBtime,
  readBootTime
} from "../../src/domain/boot-time";

// 2026-09-05T12:00:00Z
const AHORA = Date.parse("2026-09-05T12:00:00.000Z");

describe("normalizeUptimeSeconds", () => {
  it("acepta el cero: el primer segundo tras arrancar es real", () => {
    expect(normalizeUptimeSeconds(0)).toBe(0);
  });

  it("rechaza lo que no puede ser un contador", () => {
    for (const raw of [-1, NaN, Infinity, null, undefined, "", {}, "hola"]) {
      expect(normalizeUptimeSeconds(raw)).toBeNull();
    }
  });

  it("rechaza un valor absurdo en vez de fabricar un arranque en 1970", () => {
    expect(normalizeUptimeSeconds(60 * 365 * 24 * 3600)).toBeNull();
  });
});

describe("bootTimeFromUptime", () => {
  it("resta el contador al reloj", () => {
    // 3 horas encendido.
    expect(bootTimeFromUptime(AHORA, 3 * 3600)).toBe("2026-09-05T09:00:00.000Z");
  });

  it("⚠️ redondea al minuto para que el instante no baile entre snapshots", () => {
    // Dos lecturas del mismo arranque separadas por unos segundos: si no se
    // redondeara, cada snapshot daría un instante distinto y cualquier alerta
    // de "reinició" se llenaría de reinicios que no ocurrieron.
    const a = bootTimeFromUptime(AHORA, 3 * 3600 + 12);
    const b = bootTimeFromUptime(AHORA + 9_000, 3 * 3600 + 21);

    expect(a).toBe(b);
  });

  it("sin contador utilizable no inventa un instante", () => {
    expect(bootTimeFromUptime(AHORA, null)).toBeNull();
    expect(bootTimeFromUptime(AHORA, -5)).toBeNull();
    expect(bootTimeFromUptime(0, 3600)).toBeNull();
  });
});

describe("parseProcStatBtime", () => {
  const PROC_STAT = [
    "cpu  1234 0 5678 91011 12 0 34 0 0 0",
    "intr 1234567 0 0",
    "ctxt 98765432",
    "btime 1788609600",
    "processes 12345",
    "procs_running 2"
  ].join("\n");

  it("encuentra btime entre las demás líneas", () => {
    expect(parseProcStatBtime(PROC_STAT)).toBe(1788609600);
  });

  it("un btime de 0 es un kernel que no lo sabe, no el 1 de enero de 1970", () => {
    expect(parseProcStatBtime("btime 0")).toBeNull();
  });

  it("sin la línea, null", () => {
    expect(parseProcStatBtime("cpu 1 2 3\nprocesses 4")).toBeNull();
    expect(parseProcStatBtime(null)).toBeNull();
  });

  it("no confunde una línea que empieza igual", () => {
    expect(parseProcStatBtime("btimefoo 999\nbtime 1788609600")).toBe(1788609600);
  });
});

describe("bootTimeFromProcStat", () => {
  it("convierte el epoch a ISO", () => {
    expect(bootTimeFromProcStat("btime 1788609600")).toBe("2026-09-05T12:00:00.000Z");
  });
});

describe("readBootTime", () => {
  it("en Linux gana /proc/stat, que no se ve afectado por la suspensión", () => {
    // El contador dice 1 hora; el kernel dice que arrancó a las 12:00 de ayer.
    // Ese hueco ES el dato: el equipo estuvo suspendido, no se reinició.
    const r = readBootTime({
      nowMs: AHORA,
      uptimeSeconds: 3600,
      readProcStat: () => "btime 1788523200"
    });

    expect(r.bootTimeUtc).toBe("2026-09-04T12:00:00.000Z");
    // ⚠️ Y el contador crudo se conserva igual: es la otra mitad del
    // diagnóstico, no un duplicado.
    expect(r.uptimeSeconds).toBe(3600);
  });

  it("si /proc/stat no se puede leer, cae al contador", () => {
    const r = readBootTime({
      nowMs: AHORA,
      uptimeSeconds: 3600,
      readProcStat: () => {
        throw new Error("EACCES");
      }
    });

    expect(r.bootTimeUtc).toBe("2026-09-05T11:00:00.000Z");
  });

  it("sin fuente de fichero —Windows, macOS— usa el contador", () => {
    const r = readBootTime({ nowMs: AHORA, uptimeSeconds: 7200 });
    expect(r.bootTimeUtc).toBe("2026-09-05T10:00:00.000Z");
  });

  it("⚠️ sin nada utilizable devuelve null, nunca la hora actual", () => {
    // Un arranque "hace cero segundos" en cada snapshot haría que toda la
    // flota pareciera recién reiniciada, que es peor que no tener el dato.
    const r = readBootTime({ nowMs: AHORA, uptimeSeconds: "no soy un número" });

    expect(r.bootTimeUtc).toBeNull();
    expect(r.uptimeSeconds).toBeNull();
  });
});
