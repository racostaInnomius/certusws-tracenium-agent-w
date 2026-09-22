// test/plugins/sdp-detection-rule.test.ts
//
// `normalizeRule` copia la regla CAMPO A CAMPO. Un campo que no esté en su
// lista se pierde antes de llegar a la privsvc, sin error — ya pasó con
// uptimeSeconds, antivirus.products y la identidad de desinstalación.
//
// ⚠️ Con `scope` el coste de perderlo es el peor posible: la privsvc buscaría
// una app de usuario en HKLM, no la vería, y el pre-detect cerraría la
// desinstalación como «ya no está» SIN EJECUTAR NADA.

import { describe, expect, it } from "vitest";
import { normalizeRule } from "../../src/plugins/sdp/detection";

describe("normalizeRule — registry_uninstall", () => {
  it("⭐ conserva scope: user", () => {
    expect(normalizeRule({ type: "registry_uninstall", displayNameLike: "Zoom Workplace", scope: "user" })).toEqual({
      type: "registry_uninstall",
      displayNameLike: "Zoom Workplace",
      scope: "user",
    });
  });

  it("sin scope no lo inventa", () => {
    expect(normalizeRule({ type: "registry_uninstall", displayNameLike: "Dropbox" })).toEqual({
      type: "registry_uninstall",
      displayNameLike: "Dropbox",
    });
  });

  it("un scope desconocido se descarta, no se pasa", () => {
    expect(normalizeRule({ type: "registry_uninstall", displayNameLike: "Dropbox", scope: "all" })).not.toHaveProperty(
      "scope"
    );
  });

  it("minVersion y scope conviven", () => {
    expect(
      normalizeRule({ type: "registry_uninstall", displayNameLike: "Zoom", minVersion: "6.0", scope: "user" })
    ).toEqual({ type: "registry_uninstall", displayNameLike: "Zoom", minVersion: "6.0", scope: "user" });
  });
});
