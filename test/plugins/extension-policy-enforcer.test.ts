// El reconciliador contra un PrivSvc en memoria con el comportamiento de
// BrowserPolicyList.cs (lectura, escritura optimista con `expected`).
import { describe, it, expect } from "vitest";
import { enforceExtensionPolicy, type OwnedStore } from "../../src/plugins/amp/providers/extension-policy-enforcer";
import { parseExtensionPolicy } from "../../src/domain/extension-policy";

const A = "a".repeat(32);
const B = "b".repeat(32);

function fakePriv(initial: Record<string, string[]> = {}, opts: { conflictOnce?: string; failRead?: string } = {}) {
  const lists: Record<string, string[]> = { ...initial };
  const calls: any[] = [];
  let conflicted = false;
  return {
    lists,
    calls,
    priv: {
      close() {},
      async call(req: any) {
        calls.push(req);
        const key = `${req.params.browser}/${req.params.list}`;
        if (req.method === "browser.policy_list.read") {
          if (opts.failRead === key) return { ok: false, error: { code: "REGISTRY_READ_FAILED", message: "UnauthorizedAccessException" } };
          return { ok: true, result: { entries: [...(lists[key] ?? [])] } };
        }
        const current = lists[key] ?? [];
        if (opts.conflictOnce === key && !conflicted) {
          conflicted = true;
          lists[key] = [...current, "gpo-added-meanwhile"];
          return { ok: true, result: { status: "conflict", entries: lists[key] } };
        }
        if (JSON.stringify(current) !== JSON.stringify(req.params.expected)) return { ok: true, result: { status: "conflict", entries: current } };
        lists[key] = [...req.params.entries];
        return { ok: true, result: { status: "written", entries: lists[key] } };
      },
    },
  };
}

function memOwned(): OwnedStore & { data: Record<string, string[]> } {
  const data: Record<string, string[]> = {};
  return { data, load: (b, l) => [...(data[`${b}/${l}`] ?? [])], save: (b, l, owned) => { data[`${b}/${l}`] = [...owned]; } };
}

describe("enforceExtensionPolicy", () => {
  it("⚠️ política SIN bloque: no toca el registro aunque haya ids nuestros (no es 'retirar')", async () => {
    const f = fakePriv({ "chrome/blocklist": [A] });
    const owned = memOwned();
    owned.data["chrome/blocklist"] = [A];
    expect(await enforceExtensionPolicy({ priv: f.priv, policy: parseExtensionPolicy(undefined), owned })).toEqual([]);
    expect(f.calls).toEqual([]);
    expect(f.lists["chrome/blocklist"]).toEqual([A]);
  });

  it("sin política ni nada nuestro no toca el registro", async () => {
    const f = fakePriv();
    expect(await enforceExtensionPolicy({ priv: f.priv, policy: parseExtensionPolicy({})!, owned: memOwned() })).toEqual([]);
    expect(f.calls).toEqual([]);
  });

  it("bloquear, volver a pasar (sin cambios) y retirar la regla deja lo de la GPO intacto", async () => {
    const f = fakePriv({ "chrome/blocklist": ["gpo-entry"] });
    const owned = memOwned();

    const r1 = await enforceExtensionPolicy({ priv: f.priv, policy: parseExtensionPolicy({ chrome: { blocklist: [A] } })!, owned });
    expect(r1).toEqual([{ browser: "chrome", list: "blocklist", status: "written", present: [A], foreign: 1 }]);
    expect(f.lists["chrome/blocklist"]).toEqual(["gpo-entry", A]);

    const r2 = await enforceExtensionPolicy({ priv: f.priv, policy: parseExtensionPolicy({ chrome: { blocklist: [A] } })!, owned });
    expect(r2[0].status).toBe("unchanged");
    expect(f.calls.filter((c) => c.method === "browser.policy_list.write")).toHaveLength(1);

    const r3 = await enforceExtensionPolicy({ priv: f.priv, policy: parseExtensionPolicy({})!, owned });
    expect(r3[0]).toMatchObject({ status: "written", present: [] });
    expect(f.lists["chrome/blocklist"]).toEqual(["gpo-entry"]);
    expect(owned.data["chrome/blocklist"]).toEqual([]);
  });

  it("un conflicto no anota nada como nuestro; la pasada siguiente lo resuelve sobre la lista nueva", async () => {
    const f = fakePriv({}, { conflictOnce: "edge/allowlist" });
    const owned = memOwned();
    const policy = parseExtensionPolicy({ edge: { allowlist: [B] } })!;
    const r1 = await enforceExtensionPolicy({ priv: f.priv, policy, owned });
    expect(r1[0].status).toBe("conflict");
    expect(owned.data["edge/allowlist"]).toBeUndefined();
    const r2 = await enforceExtensionPolicy({ priv: f.priv, policy, owned });
    expect(r2[0].status).toBe("written");
    expect(f.lists["edge/allowlist"]).toEqual(["gpo-added-meanwhile", B]);
  });

  it("un error en una lista no impide las demás", async () => {
    const f = fakePriv({}, { failRead: "chrome/blocklist" });
    const r = await enforceExtensionPolicy({ priv: f.priv, policy: parseExtensionPolicy({ chrome: { blocklist: [A] }, edge: { blocklist: [A] } })!, owned: memOwned() });
    expect(r.map((x) => [x.browser, x.status])).toEqual([["chrome", "error"], ["edge", "written"]]);
    expect(r[0].error).toContain("REGISTRY_READ_FAILED");
  });
});
