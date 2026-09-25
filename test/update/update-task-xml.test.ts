// test/update/update-task-xml.test.ts
//
// La tarea programada que lanza el MSI del update en Windows.
//
// 🔴 W11_JPR_LAB (Latitude 5400) se quedó en 1.1.77 con cuatro jobs de update
// aceptados (24/25-sep). Las cuatro tareas estaban creadas y ninguna corrió:
// Last Run Time 11/30/1999, Last Result 267011, Power Management "Stop On
// Battery Mode, No Start On Batteries" — lo que `schtasks /sc ONCE` pone por
// defecto. Un portátil con batería no se actualizaba nunca.
//
// Sustituye a schtasks-start-time.test.ts: con `/st HH:MM` había que truncar
// al minuto y el margen de 90 s era lo que evitaba programar en el pasado. El
// XML lleva segundos, así que aquella cuenta ya no existe.

import { describe, it, expect } from "vitest";
import {
  buildUpdateTaskXml,
  encodeTaskXml,
  localIsoSeconds,
  updateTaskNamesIn
} from "../../src/update/updater-runner";

const startAt = new Date(2026, 8, 25, 11, 10, 16); // hora local
const endAt = new Date(2026, 8, 26, 11, 10, 16);
const shimPath = "C:\\WINDOWS\\TEMP\\tracenium-update-1790356126476-7092.cmd";
const xml = buildUpdateTaskXml({ shimPath, startAt, endAt });

/** El valor de un elemento del XML, o null si no está. */
const el = (name: string) => xml.match(new RegExp(`<${name}>([^<]*)</${name}>`))?.[1] ?? null;

describe("la tarea del update arranca con batería", () => {
  it("⭐ no se niega a arrancar con batería", () => {
    expect(el("DisallowStartIfOnBatteries")).toBe("false");
  });

  it("⭐ y no mata el instalador si se desenchufa a mitad", () => {
    // Con el valor por defecto, desenchufar paraba la tarea con msiexec
    // dentro: servicios parados y binarios a medio reemplazar.
    expect(el("StopIfGoingOnBatteries")).toBe("false");
  });

  it("recoge un arranque perdido (equipo dormido a esa hora)", () => {
    expect(el("StartWhenAvailable")).toBe("true");
  });
});

describe("cuándo arranca y cuándo se borra sola", () => {
  it("StartBoundary en hora local, con segundos", () => {
    expect(el("StartBoundary")).toBe("2026-09-25T11:10:16");
  });

  it("una tarea que nunca corrió caduca y Task Scheduler la borra", () => {
    // En W11_JPR_LAB había 27 huérfanas, desde mayo.
    expect(el("EndBoundary")).toBe("2026-09-26T11:10:16");
    expect(el("DeleteExpiredTaskAfter")).toBe("PT1H");
  });

  it("localIsoSeconds rellena con ceros", () => {
    expect(localIsoSeconds(new Date(2026, 0, 2, 3, 4, 5))).toBe("2026-01-02T03:04:05");
  });
});

describe("quién y qué ejecuta", () => {
  it("corre como LocalSystem con privilegios máximos, como /ru SYSTEM /rl HIGHEST", () => {
    expect(el("UserId")).toBe("S-1-5-18");
    expect(el("RunLevel")).toBe("HighestAvailable");
  });

  it("ejecuta el shim", () => {
    expect(el("Command")).toBe(shimPath);
  });

  it("escapa lo que rompería el XML en la ruta", () => {
    const x = buildUpdateTaskXml({ shimPath: "C:\\a&b\\<x>.cmd", startAt, endAt });
    expect(x).toContain("<Command>C:\\a&amp;b\\&lt;x&gt;.cmd</Command>");
  });

  it("se escribe en UTF-16LE con BOM, que es lo que schtasks /xml acepta siempre", () => {
    const buf = encodeTaskXml(xml);
    expect([...buf.subarray(0, 2)]).toEqual([0xff, 0xfe]);
    expect(buf.subarray(2).toString("utf16le")).toBe(xml);
  });
});

describe("updateTaskNamesIn — las tareas viejas que hay que barrer", () => {
  it("saca los nombres del listado CSV de schtasks, sin duplicados", () => {
    const listing = [
      `"\\TraceniumAgentUpdate_1790268500162","N/A","Ready"`,
      `"\\TraceniumAgentUpdate_1790268500162","N/A","Ready"`,
      `"\\Microsoft\\Windows\\Defrag\\ScheduledDefrag","N/A","Ready"`,
      `"\\TraceniumAgentUpdate_1779335780735","5/27/2026 12:45:00 PM","Ready"`,
      `"\\MyTraceniumAgentUpdate_1","N/A","Ready"`
    ].join("\r\n");
    expect(updateTaskNamesIn(listing)).toEqual([
      "TraceniumAgentUpdate_1790268500162",
      "TraceniumAgentUpdate_1779335780735"
    ]);
  });

  it("un listado vacío o en otro idioma sin tareas nuestras no borra nada", () => {
    expect(updateTaskNamesIn("")).toEqual([]);
    expect(updateTaskNamesIn(`"\\Tarea programada","N/D","Listo"`)).toEqual([]);
  });
});
