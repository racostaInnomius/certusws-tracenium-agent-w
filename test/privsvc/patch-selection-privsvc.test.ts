// test/privsvc/patch-selection-privsvc.test.ts
//
// 🔴 Auditoría PMP 1-oct-2026. Los privsvc de Linux y macOS leían una lista
// vacía como «todo»: `apt-get dist-upgrade -y` (puede DESINSTALAR paquetes),
// `dnf upgrade -y` o `softwareupdate --all`. Sólo los frenaba el agente. Y un id
// que empiece por `-` llegaría a apt/dnf como opción.
//
// Los handlers rechazan ANTES de escanear o ejecutar nada, así que se prueban de
// verdad, sin dobles: si algo llegara a apt/softwareupdate, el test lo vería
// como otro error (o se colgaría), no como este rechazo.

import { describe, expect, it } from "vitest";
import { readPatchSelection } from "../../privsvc/shared/patch-selection";
import { handlePatchInstall as linuxInstall } from "../../privsvc/linux/src/patch-management";
import { handlePatchInstall as macInstall } from "../../privsvc/macos/src/patch-management";

describe("readPatchSelection", () => {
  it("acepta ids reales de apt, dnf y softwareupdate", () => {
    const sel = readPatchSelection({
      kbArticleIds: [
        " containerd.io-2.3.5-1~ubuntu.26.04~resolute ",
        "python3-distupgrade-1:26.04.25",
        "openssl-1:3.0.7-27.el9.x86_64",
        "macOS Tahoe  26.7-25G229",
      ],
    });
    expect(sel).toMatchObject({ ok: true });
    expect(sel.ok && sel.ids[0]).toBe("containerd.io-2.3.5-1~ubuntu.26.04~resolute");
  });

  it.each([[{ kbArticleIds: [] }], [{}], [undefined], [{ kbArticleIds: ["", "  "] }], [{ kbArticleIds: "openssl" }]])(
    "🔴 sin lista → no_selection (%j)",
    (params) => {
      expect(readPatchSelection(params as any)).toMatchObject({ ok: false, code: "patch_install_no_selection" });
    }
  );

  it.each(["-oDPkg::Pre-Invoke::=touch /tmp/x", "pkg;reboot", "pkg|sh", "pkg$(id)", "a\nb", "a".repeat(201)])(
    "🔴 rechaza %j",
    (id) => {
      expect(readPatchSelection({ kbArticleIds: ["openssl", id] })).toMatchObject({
        ok: false,
        code: "patch_install_invalid_id",
      });
    }
  );
});

describe.each([
  ["linux", linuxInstall],
  ["macos", macInstall],
])("privsvc %s — patch.install", (_os, handle) => {
  it("🔴 lista vacía: falla con no_selection, no instala todo", async () => {
    const res = await handle({ v: 1, id: "t1", method: "patch.install", params: { mode: "install", kbArticleIds: [] } } as any);
    expect(res.ok).toBe(false);
    expect(res.error?.code).toBe("patch_install_no_selection");
  });

  it("🔴 un id con forma de opción no llega al gestor de paquetes", async () => {
    const res = await handle({
      v: 1,
      id: "t2",
      method: "patch.install",
      params: { mode: "install", kbArticleIds: ["-oAPT::Get::Assume-Yes=1"] },
    } as any);
    expect(res.ok).toBe(false);
    expect(res.error?.code).toBe("patch_install_invalid_id");
  });
});
