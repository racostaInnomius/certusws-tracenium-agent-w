// De la lectura al payload. Se dobla el REPOSITORIO SQLite, no la lógica.
import { describe, it, expect, vi, beforeEach } from "vitest";

const load = vi.fn();
const upsert = vi.fn();
const del = vi.fn();
vi.mock("../../src/domain/browser-extension-baseline-repo", () => ({
  loadBrowserExtensionBaseline: (...a: any[]) => load(...a),
  upsertBrowserExtensionBaseline: (...a: any[]) => upsert(...a),
  deleteBrowserExtensionsByIds: (...a: any[]) => del(...a),
}));

import { buildBrowserExtensionInventory } from "../../src/plugins/amp/providers/browser-extensions-pipeline";

const ext = (id: string, over: any = {}) => ({
  installId: `chrome|jdoe|Default|${id}`, browser: "chrome", extensionId: id, name: id, version: "1", osUser: "jdoe", profile: "Default",
  enabled: true, installSource: "store", permissions: ["tabs"], hostPermissions: [], manifestVersion: 3, updateUrl: null, installedAtUtc: null,
  detectedAtUtc: "2026-09-14T00:00:00.000Z", ...over,
}) as any;
const scan = (extensions: any[], scope: any = "collected") => ({ extensions, scope, profiles: 1, profileErrors: 0 });

beforeEach(() => { load.mockReset(); upsert.mockReset(); del.mockReset(); load.mockReturnValue([]); });

describe("buildBrowserExtensionInventory", () => {
  it("⚠️ unavailable / unsupported no tocan la baseline ni se anuncian como cambio", () => {
    for (const scope of ["unavailable", "unsupported"]) {
      const r = buildBrowserExtensionInventory(scan([], scope));
      expect(r).toMatchObject({ count: 0, hasChanges: false, scope });
    }
    expect(load).not.toHaveBeenCalled();
    expect(upsert).not.toHaveBeenCalled();
  });

  it("primera pasada: foto completa aunque esté vacía, con scope", () => {
    const r = buildBrowserExtensionInventory(scan([]));
    expect(r).toMatchObject({ count: 0, items: [], hasChanges: true, scope: "collected", profiles: 1 });
  });

  it("una actualización que AMPLÍA permisos es un `updated` (el patrón de extensión comprada)", () => {
    load.mockReturnValue([ext("a"), ext("b")]);
    const r = buildBrowserExtensionInventory(scan([ext("a", { hostPermissions: ["<all_urls>"] }), ext("b")]));
    expect(r.hasChanges).toBe(true);
    expect(r.items).toBeUndefined();
    expect(r.delta!.updated.map((e: any) => e.extensionId)).toEqual(["a"]);
    expect(upsert).toHaveBeenCalledWith([expect.objectContaining({ extensionId: "a" })]);
  });

  it("sin cambios: sólo recuento; quitada: delete en la baseline", () => {
    load.mockReturnValue([ext("a")]);
    expect(buildBrowserExtensionInventory(scan([ext("a")]))).toMatchObject({ hasChanges: false, count: 1, delta: null });
    const r = buildBrowserExtensionInventory(scan([]));
    expect(r.delta!.removed).toHaveLength(1);
    expect(del).toHaveBeenCalledWith(["chrome|jdoe|Default|a"]);
  });
});
