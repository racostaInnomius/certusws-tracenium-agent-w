// Lo no visto porque el perfil no tenía sesión no se desinstaló
// (src/domain/software-user-hive-carryover.ts).

import { describe, expect, it } from "vitest";
import { carryOverUnreadUserApps, userSidOfKeyPath } from "../../src/domain/software-user-hive-carryover";

const ANA = "S-1-5-21-1111111111-222222222-3333333333-1001";
const BETO = "S-1-5-21-1111111111-222222222-3333333333-1002";
const UNINSTALL = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";

const app = (installId: string, keyPath?: string) =>
  ({ installId, name: installId, uninstallKeyPath: keyPath }) as any;

describe("userSidOfKeyPath", () => {
  it("saca el SID de una ruta por usuario, en mayúsculas", () => {
    expect(userSidOfKeyPath(`HKU\\${ANA}${UNINSTALL}ZoomUMX`)).toBe(ANA);
    expect(userSidOfKeyPath(`hku\\${ANA.toLowerCase()}${UNINSTALL}ZoomUMX`)).toBe(ANA);
  });

  it("⭐ también los usuarios de Entra ID (S-1-12-1-…)", () => {
    const entra = "S-1-12-1-3570604255-1238987765-2263183267-4104715137";
    expect(userSidOfKeyPath(`HKU\\${entra}${UNINSTALL}ZoomUMX`)).toBe(entra);
    expect(carryOverUnreadUserApps([], [app("zoom", `HKU\\${entra}${UNINSTALL}ZoomUMX`)], [entra]).carried).toBe(1);
  });

  it("máquina, HKCU de SYSTEM o sin ruta → null", () => {
    expect(userSidOfKeyPath(`HKLM${UNINSTALL}{GUID}`)).toBeNull();
    expect(userSidOfKeyPath(`HKCU${UNINSTALL}x`)).toBeNull();
    expect(userSidOfKeyPath("HKU\\S-1-5-18\\SOFTWARE\\x")).toBeNull();
    expect(userSidOfKeyPath(undefined)).toBeNull();
  });
});

describe("carryOverUnreadUserApps", () => {
  const teamsAna = app("teams", `HKU\\${ANA}${UNINSTALL}Teams`);
  const zoomBeto = app("zoom", `HKU\\${BETO}${UNINSTALL}ZoomUMX`);
  const chrome = app("chrome", `HKLM${UNINSTALL}Chrome`);

  it("⭐ conserva lo de los perfiles no leídos, y sólo eso", () => {
    const r = carryOverUnreadUserApps([], [teamsAna, zoomBeto, chrome], [BETO]);
    expect(r.apps.map((a) => a.installId)).toEqual(["zoom"]);
    expect(r.carried).toBe(1);
  });

  it("no duplica lo que este escaneo ya vio (p. ej. desde otro perfil con sesión)", () => {
    const zoomAna = app("zoom", `HKU\\${ANA}${UNINSTALL}ZoomUMX`);
    const r = carryOverUnreadUserApps([zoomAna], [zoomBeto], [BETO]);
    expect(r.apps).toEqual([zoomAna]);
    expect(r.carried).toBe(0);
  });

  it("una app de máquina que falta sí se va, aunque haya perfiles sin leer", () => {
    expect(carryOverUnreadUserApps([], [chrome], [ANA]).apps).toEqual([]);
  });

  it("sin lista (PrivSvc anterior) o vacía: devuelve el escaneo tal cual", () => {
    const actual = [chrome];
    expect(carryOverUnreadUserApps(actual, [teamsAna], null).apps).toBe(actual);
    expect(carryOverUnreadUserApps(actual, [teamsAna], []).apps).toBe(actual);
  });

  it("compara el SID sin distinguir mayúsculas", () => {
    expect(carryOverUnreadUserApps([], [teamsAna], [ANA.toLowerCase()]).carried).toBe(1);
  });
});
