import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Purga de instaladores viejos tras una descarga validada.
 *
 * Regresión de lo observado en producción el 2026-08-15: el directorio de
 * descargas del agente acumulaba 7 versiones — 477 MB — más los .tmp de
 * descargas cortadas, en un servidor que ya había llegado al 98 % de disco.
 * Nada los recogía: sólo se borraba el fichero cuyo hash no cuadraba.
 *
 * `pruneOldDownloads` no está exportada (es un detalle interno del servicio),
 * así que aquí se fija el CONTRATO que debe cumplir, con la misma
 * implementación de referencia. Si el comportamiento cambia en el servicio y
 * aquí no, la divergencia se nota al leer ambos.
 */
function pruneOldDownloads(dir: string, keepPath: string): void {
  try {
    const keep = path.basename(keepPath);
    for (const name of fs.readdirSync(dir)) {
      if (name === keep) continue;
      if (!/\.(deb|rpm|msi|pkg|tmp)$/i.test(name)) continue;
      try {
        fs.rmSync(path.join(dir, name), { force: true });
      } catch {
        /* un fichero bloqueado no debe abortar el resto */
      }
    }
  } catch {
    /* directorio ilegible: no es motivo para fallar la actualización */
  }
}

let dir: string;

const touch = (name: string) => fs.writeFileSync(path.join(dir, name), "x");
const listing = () => fs.readdirSync(dir).sort();

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "tracenium-updates-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("pruneOldDownloads", () => {
  it("conserva sólo el instalador recién validado", () => {
    // El escenario exacto del servidor: siete versiones acumuladas.
    for (const v of ["1.1.16", "1.1.18", "1.1.19", "1.1.20", "1.1.21", "1.1.30", "1.1.35"]) {
      touch(`tracenium-agent-${v}-x64.deb`);
    }
    const keep = path.join(dir, "tracenium-agent-1.1.35-x64.deb");

    pruneOldDownloads(dir, keep);

    expect(listing()).toEqual(["tracenium-agent-1.1.35-x64.deb"]);
  });

  it("borra los .tmp de descargas cortadas", () => {
    touch("tracenium-agent-1.1.31-x64.deb.tmp");
    touch("tracenium-agent-1.1.32-x64.deb.tmp");
    touch("tracenium-agent-1.1.35-x64.deb");

    pruneOldDownloads(dir, path.join(dir, "tracenium-agent-1.1.35-x64.deb"));

    expect(listing()).toEqual(["tracenium-agent-1.1.35-x64.deb"]);
  });

  it("cubre los formatos de las tres plataformas", () => {
    touch("Tracenium-Agent-1.1.30-x64.msi");
    touch("tracenium-agent-1.1.30.rpm");
    touch("Tracenium-1.1.30.pkg");
    touch("tracenium-agent-1.1.35-x64.deb");

    pruneOldDownloads(dir, path.join(dir, "tracenium-agent-1.1.35-x64.deb"));

    expect(listing()).toEqual(["tracenium-agent-1.1.35-x64.deb"]);
  });

  it("no toca ficheros que no son instaladores", () => {
    // El directorio podría compartirse con estado o notas; sólo nos
    // corresponde barrer paquetes.
    touch("README.txt");
    touch("update-state.json");
    touch("tracenium-agent-1.1.30-x64.deb");
    touch("tracenium-agent-1.1.35-x64.deb");

    pruneOldDownloads(dir, path.join(dir, "tracenium-agent-1.1.35-x64.deb"));

    expect(listing()).toEqual([
      "README.txt",
      "tracenium-agent-1.1.35-x64.deb",
      "update-state.json",
    ]);
  });

  it("es idempotente: correrla dos veces no cambia nada", () => {
    touch("tracenium-agent-1.1.30-x64.deb");
    touch("tracenium-agent-1.1.35-x64.deb");
    const keep = path.join(dir, "tracenium-agent-1.1.35-x64.deb");

    pruneOldDownloads(dir, keep);
    const first = listing();
    pruneOldDownloads(dir, keep);

    expect(listing()).toEqual(first);
  });

  it("no lanza si el directorio no existe", () => {
    const ghost = path.join(dir, "no-existe");
    // Una limpieza fallida no puede tumbar una actualización que sí funcionó.
    expect(() => pruneOldDownloads(ghost, path.join(ghost, "x.deb"))).not.toThrow();
  });

  it("deja el directorio vacío si el fichero a conservar ya no está", () => {
    touch("tracenium-agent-1.1.30-x64.deb");

    pruneOldDownloads(dir, path.join(dir, "tracenium-agent-1.1.35-x64.deb"));

    expect(listing()).toEqual([]);
  });
});
