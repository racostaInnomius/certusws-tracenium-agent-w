// El plan de las listas de extensiones de Chrome/Edge: añadir sin pisar lo
// ajeno, quitar sólo lo nuestro, compactar la numeración.
import { describe, it, expect } from "vitest";
import { parseExtensionPolicy, planPolicyList } from "../../src/domain/extension-policy";

const A = "a".repeat(32);
const B = "b".repeat(32);
const C = "c".repeat(32);

describe("planPolicyList", () => {
  it("añade lo pedido al final, conservando lo que puso una GPO", () => {
    const p = planPolicyList(["gpo-entry", C], [A], []);
    expect(p).toMatchObject({ next: ["gpo-entry", C, A], changed: true, added: [A], removed: [], owned: [A] });
    expect(p.foreign).toEqual(["gpo-entry", C]);
  });

  it("al retirar la regla quita SOLO lo nuestro y compacta", () => {
    const p = planPolicyList(["gpo-entry", A, C], [], [A]);
    expect(p).toMatchObject({ next: ["gpo-entry", C], changed: true, removed: [A], owned: [] });
  });

  it("⚠️ un id que ya estaba por GPO no pasa a ser nuestro: dejar de pedirlo no lo quita", () => {
    const first = planPolicyList([B], [B], []);
    expect(first).toMatchObject({ changed: false, added: [], owned: [] });
    const later = planPolicyList([B], [], first.owned);
    expect(later).toMatchObject({ next: [B], changed: false, removed: [] });
  });

  it("si alguien borró lo nuestro, se vuelve a poner (reparación)", () => {
    const p = planPolicyList([], [A], [A]);
    expect(p).toMatchObject({ next: [A], changed: true, added: [A], owned: [A] });
  });

  it("sin nada que hacer no hay cambio; duplicados del registro se compactan", () => {
    expect(planPolicyList([A, B], [A], [A]).changed).toBe(false);
    expect(planPolicyList([A, A, B], [A], [A])).toMatchObject({ next: [A, B], changed: true });
  });
});

describe("parseExtensionPolicy", () => {
  it("falla cerrado: sólo ids válidos, `*` sólo en la blocklist, bloqueo gana a permiso", () => {
    const p = parseExtensionPolicy({ chrome: { blocklist: [A, "*", "../../evil", 7, A], allowlist: [A, B, "*"] }, edge: "junk", firefox: { blocklist: [A] } });
    expect(p.chrome).toEqual({ blocklist: [A, "*"], allowlist: [B] });
    expect(p.edge).toEqual({ blocklist: [], allowlist: [] });
    expect(Object.keys(p)).toEqual(["chrome", "edge"]);
    expect(parseExtensionPolicy(null)).toEqual({ chrome: { blocklist: [], allowlist: [] }, edge: { blocklist: [], allowlist: [] } });
  });
});
