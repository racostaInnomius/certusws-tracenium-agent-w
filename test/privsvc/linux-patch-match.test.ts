// test/privsvc/linux-patch-match.test.ts
//
// ⚠️ Auditoría PMP 1-oct-2026. El id de apt es `<paquete>-<versión>`: si el repo
// publica una versión nueva entre el escaneo que vio el operador y la
// instalación, el id pedido deja de existir aunque el paquete siga pendiente, y
// se descartaba en silencio («pido 23, casan 5» → success; installed=5).

import { describe, expect, it } from "vitest";
import { matchRequestedItems, parseAptUpgradable } from "../../privsvc/linux/src/patch-management";

const LIVE = parseAptUpgradable(
  [
    "Listing...",
    "openssl/noble-security 3.0.13-0ubuntu3.7 amd64 [upgradable from: 3.0.13-0ubuntu3.5]",
    "python3/noble-updates 3.12.3-0ubuntu2.2 amd64 [upgradable from: 3.12.3-0ubuntu2]",
    "python3-apt/noble-updates 2.7.7ubuntu5.4 amd64 [upgradable from: 2.7.7ubuntu5.2]",
    "python3-distupgrade/noble-updates 1:24.04.30 all [upgradable from: 1:24.04.28]",
  ].join("\n")
);

describe("matchRequestedItems", () => {
  it("casa exacto cuando el id sigue vigente", () => {
    const m = matchRequestedItems(LIVE, ["openssl-3.0.13-0ubuntu3.7"]);
    expect(m.selected.map((i) => i.packageName)).toEqual(["openssl"]);
    expect(m.unmatched).toEqual([]);
  });

  it("🔴 versión nueva publicada entretanto: casa por NOMBRE, no se descarta", () => {
    const m = matchRequestedItems(LIVE, ["openssl-3.0.13-0ubuntu3.6", "python3-distupgrade-1:24.04.29"]);
    expect(m.selected.map((i) => i.hotFixId)).toEqual([
      "openssl-3.0.13-0ubuntu3.7",
      "python3-distupgrade-1:24.04.30",
    ]);
    // Lo pedido viaja con el elemento elegido, para que el resultado lo diga.
    expect(m.requestedFor.get(m.selected[0])).toBe("openssl-3.0.13-0ubuntu3.6");
    expect(m.unmatched).toEqual([]);
  });

  it("⚠️ `python3-apt-…` no es una versión de `python3`: gana el nombre más largo", () => {
    const m = matchRequestedItems(LIVE, ["python3-apt-2.7.7ubuntu5.3"]);
    expect(m.selected.map((i) => i.packageName)).toEqual(["python3-apt"]);
  });

  it("lo que no está pendiente de ninguna forma sale en `unmatched`, no desaparece", () => {
    const m = matchRequestedItems(LIVE, ["openssl-3.0.13-0ubuntu3.7", "curl-8.5.0-2ubuntu10.7"]);
    expect(m.selected).toHaveLength(1);
    expect(m.unmatched).toEqual(["curl-8.5.0-2ubuntu10.7"]);
  });

  it("dos ids del mismo paquete no lo instalan dos veces", () => {
    const m = matchRequestedItems(LIVE, ["openssl-3.0.13-0ubuntu3.6", "openssl-3.0.13-0ubuntu3.7"]);
    expect(m.selected).toHaveLength(1);
  });
});
