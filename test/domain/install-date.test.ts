// test/domain/install-date.test.ts
//
// La fecha de instalación: cómo se interpreta en cada fuente, y que sobreviva
// a las tres listas que ya se comieron otros campos (el normalizador, el delta
// y la fusión de fuentes de macOS).

import { describe, it, expect } from "vitest";
import {
  installedOnFromDate,
  installedOnFromEpochSeconds,
  installedOnFromWindowsRegistry,
  isInstalledOn,
} from "../../src/domain/install-date";
import { normalizeApp } from "../../src/domain/normalize-app";
import { computeSoftwareDelta } from "../../src/domain/software-inventory-delta";
import { mergeMacAppsBySource } from "../../src/plugins/amp/providers/macos";

describe("installedOnFromWindowsRegistry", () => {
  it.each([
    ["20240315", "2024-03-15"],
    ["2024-03-15", "2024-03-15"],
    ["2024-03-15T10:00:00", "2024-03-15"],
    [" 20240315 ", "2024-03-15"],
  ])("%s → %s", (raw, out) => {
    expect(installedOnFromWindowsRegistry(raw)).toBe(out);
  });

  it("⚠️ día/mes ambiguo: no se adivina", () => {
    expect(installedOnFromWindowsRegistry("15/03/2024")).toBeUndefined();
    expect(installedOnFromWindowsRegistry("03/04/2024")).toBeUndefined();
  });

  it("fechas imposibles o basura: nada", () => {
    expect(installedOnFromWindowsRegistry("20240231")).toBeUndefined();
    expect(installedOnFromWindowsRegistry("19000101")).toBeUndefined();
    expect(installedOnFromWindowsRegistry("99991231")).toBeUndefined();
    expect(installedOnFromWindowsRegistry("")).toBeUndefined();
    expect(installedOnFromWindowsRegistry(null)).toBeUndefined();
    expect(installedOnFromWindowsRegistry({})).toBeUndefined();
  });

  it("un DWORD con epoch se convierte al día local del equipo", () => {
    const epoch = Math.floor(new Date(2024, 2, 15, 12, 0, 0).getTime() / 1000);
    expect(installedOnFromWindowsRegistry(epoch)).toBe("2024-03-15");
    expect(installedOnFromWindowsRegistry(String(epoch))).toBe("2024-03-15");
  });
});

describe("installedOnFromDate / FromEpochSeconds", () => {
  it("usa la fecha LOCAL, no la UTC", () => {
    // 23:30 locales: en UTC puede ser ya el día siguiente, y el equipo dice hoy.
    expect(installedOnFromDate(new Date(2025, 5, 10, 23, 30))).toBe("2025-06-10");
  });

  it("birthtime 0 (sistemas de ficheros que no la guardan) no es 1970", () => {
    expect(installedOnFromDate(new Date(0))).toBeUndefined();
    expect(installedOnFromDate(null)).toBeUndefined();
    expect(installedOnFromDate(new Date("nope"))).toBeUndefined();
  });

  it("pkgutil / rpm: segundos desde epoch, en número o texto", () => {
    const secs = Math.floor(new Date(2023, 8, 1, 9).getTime() / 1000);
    expect(installedOnFromEpochSeconds(secs)).toBe("2023-09-01");
    expect(installedOnFromEpochSeconds(`${secs}`)).toBe("2023-09-01");
    expect(installedOnFromEpochSeconds("(none)")).toBeUndefined();
    expect(installedOnFromEpochSeconds(undefined)).toBeUndefined();
  });

  it("isInstalledOn rechaza el futuro", () => {
    const next = new Date();
    next.setDate(next.getDate() + 10);
    const s = `${next.getFullYear()}-${String(next.getMonth() + 1).padStart(2, "0")}-${String(next.getDate()).padStart(2, "0")}`;
    expect(isInstalledOn(s)).toBe(false);
  });
});

describe("normalizeApp", () => {
  it("⭐ la fecha llega a la salida", () => {
    expect(normalizeApp({ name: "7-Zip", source: "win32-registry", installedOn: "2024-03-15" })!.installedOn).toBe("2024-03-15");
  });

  it("una fecha inválida no viaja", () => {
    expect(normalizeApp({ name: "7-Zip", source: "win32-registry", installedOn: "2024-02-31" })!.installedOn).toBeUndefined();
    expect(normalizeApp({ name: "7-Zip", source: "win32-registry", installedOn: null })!.installedOn).toBeUndefined();
  });

  it("no forma parte de la identidad: el installId no cambia con la fecha", () => {
    const a = normalizeApp({ name: "7-Zip", source: "win32-registry", installedOn: "2024-03-15" })!;
    const b = normalizeApp({ name: "7-Zip", source: "win32-registry" })!;
    expect(a.installId).toBe(b.installId);
  });
});

describe("delta", () => {
  const sin = normalizeApp({ name: "7-Zip", version: "24.07", source: "win32-registry" })!;
  const con = { ...sin, installedOn: "2024-03-15" };

  it("⭐ estrenar fecha cuenta como cambio (así llega a las apps que ya estaban)", () => {
    expect(computeSoftwareDelta([con], [sin]).delta.updated).toHaveLength(1);
  });

  it("misma fecha: sin cambio", () => {
    expect(computeSoftwareDelta([con], [con]).hasChanges).toBe(false);
  });

  it("⚠️ una lectura que pierde la fecha NO es un cambio (si no, oscilaría)", () => {
    expect(computeSoftwareDelta([sin], [con]).hasChanges).toBe(false);
  });

  it("una reinstalación con fecha nueva sí lo es", () => {
    expect(computeSoftwareDelta([{ ...con, installedOn: "2026-09-01" }], [con]).delta.updated).toHaveLength(1);
  });
});

describe("macOS — fusión de fuentes", () => {
  it("si el bundle no tiene fecha, se queda la del recibo del mismo paquete", () => {
    const bundle = normalizeApp({ name: "Microsoft OneNote", source: "macos-app-bundle", packageFamilyName: "com.microsoft.onenote.mac" })!;
    const recibo = normalizeApp({
      name: "com.microsoft.onenote.mac",
      source: "pkgutil",
      packageFamilyName: "com.microsoft.onenote.mac",
      installedOn: "2025-02-03",
    })!;
    const [merged] = mergeMacAppsBySource([bundle, recibo]);
    expect(merged.source).toBe("macos-app-bundle");
    expect(merged.installedOn).toBe("2025-02-03");
  });

  it("y si el bundle la tiene, manda la suya", () => {
    const bundle = normalizeApp({
      name: "Microsoft OneNote",
      source: "macos-app-bundle",
      packageFamilyName: "com.microsoft.onenote.mac",
      installedOn: "2025-03-01",
    })!;
    const recibo = normalizeApp({
      name: "com.microsoft.onenote.mac",
      source: "pkgutil",
      packageFamilyName: "com.microsoft.onenote.mac",
      installedOn: "2025-02-03",
    })!;
    expect(mergeMacAppsBySource([recibo, bundle])[0].installedOn).toBe("2025-03-01");
  });
});
