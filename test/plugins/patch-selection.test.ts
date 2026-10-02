// test/plugins/patch-selection.test.ts
//
// Una lista vacía de parches, para el script de Windows Update de un privsvc
// viejo, es «instala TODO». El 8-sep-2026 así se instalaron 3 actualizaciones
// que nadie había elegido. El agente se actualiza antes que el MSI, así que
// esta barrera es la que protege a los equipos con el privsvc viejo.

import { describe, expect, it } from "vitest";
import fs from "fs";
import path from "path";
import { selectedPatchIds, unmatchedRequested, unsafePatchIds } from "../../src/plugins/pmp/patch-selection";

describe("selectedPatchIds", () => {
  it("devuelve la lista limpia", () => {
    expect(selectedPatchIds({ kbArticleIds: [" KB5122882 ", "KB5126149"] })).toEqual(["KB5122882", "KB5126149"]);
  });

  it("🔴 vacía, ausente, nula, no-lista, o sólo huecos → null, NUNCA []", () => {
    for (const p of [{ kbArticleIds: [] }, {}, null, undefined, { kbArticleIds: "KB1" }, { kbArticleIds: ["", "  ", null] }]) {
      // `[]` es exactamente el valor que el script viejo convierte en «todo».
      expect(selectedPatchIds(p)).toBeNull();
    }
  });

  it("acepta nombres de paquete (Linux, macOS)", () => {
    expect(selectedPatchIds({ kbArticleIds: ["openssl"] })).toEqual(["openssl"]);
  });
});

describe("⚠️ el manejador de patch_install rechaza antes de llamar al privsvc", () => {
  // Guarda de regresión barata sobre grpc-stream.ts, que no tiene test de
  // manejador: el rechazo tiene que ir ANTES de `patch.install`.
  it("el rechazo aparece antes que la llamada al privsvc", () => {
    const src = fs.readFileSync(path.join(__dirname, "../../src/transport/grpc-stream.ts"), "utf8");
    const rechazo = src.indexOf("patch_install rejected: no_patches_selected");
    const llamada = src.indexOf('method: "patch.install"');
    expect(rechazo).toBeGreaterThan(0);
    expect(llamada).toBeGreaterThan(rechazo);
  });
});

describe("🔴 unsafePatchIds — un id llega al privsvc sólo si tiene forma de id (1-oct-2026)", () => {
  it("Windows: sólo artículos KB; una subexpresión de PowerShell no pasa", () => {
    expect(unsafePatchIds(["KB5129195", "kb2267602"], "win32")).toEqual([]);
    expect(unsafePatchIds(["KB1$(Restart-Computer)", 'KB1"; whoami; "', "KB1`n", "5066747"], "win32")).toHaveLength(4);
  });

  it("Linux/macOS: nombres de paquete y etiquetas reales pasan", () => {
    const reales = [
      "containerd.io-2.3.5-1~ubuntu.26.04~resolute",
      "python3-distupgrade-1:26.04.25",
      "ubuntu-virt-1:10.2.1+ds-1ubuntu3.2",
      "macOS Tahoe \u00A026.7-25G229",
      "Command Line Tools for Xcode 27.0-27.0",
    ];
    expect(unsafePatchIds(reales, "linux")).toEqual([]);
    expect(unsafePatchIds(reales, "darwin")).toEqual([]);
  });

  it("Linux: un id que empieza por guion sería una OPCIÓN de apt/dnf", () => {
    expect(unsafePatchIds(["-oDPkg::Pre-Invoke::=touch", "pkg;reboot", "pkg|sh", "a\nb"], "linux")).toHaveLength(4);
  });

  it("el manejador lo rechaza ANTES de llamar al privsvc", () => {
    const src = fs.readFileSync(path.join(__dirname, "../../src/transport/grpc-stream.ts"), "utf8");
    const rechazo = src.indexOf("patch_install rejected: invalid_patch_id");
    const llamada = src.indexOf('method: "patch.install"');
    expect(rechazo).toBeGreaterThan(0);
    expect(llamada).toBeGreaterThan(rechazo);
  });
});

describe("🔴 unmatchedRequested — lo pedido que el privsvc no devolvió se nombra (1-oct-2026)", () => {
  it("Windows: por KB, sin distinguir mayúsculas", () => {
    expect(
      unmatchedRequested(["KB5129195", "KB2267602", "KB4052623"], [{ kb: "kb5129195" }, { kb: "KB2267602" }])
    ).toEqual(["KB4052623"]);
  });

  it("Linux: por el id pedido (`kb`) aunque se instalara una versión más nueva (`updateId`)", () => {
    expect(
      unmatchedRequested(
        ["openssl-3.0.13-0ubuntu3.6", "curl-8.5.0-2ubuntu10.7"],
        [{ kb: "openssl-3.0.13-0ubuntu3.6", updateId: "openssl-3.0.13-0ubuntu3.7" }]
      )
    ).toEqual(["curl-8.5.0-2ubuntu10.7"]);
  });

  it("privsvc viejo (Linux sin `kb`): casa por updateId", () => {
    expect(unmatchedRequested(["openssl-3.0.13-0ubuntu3.7"], [{ updateId: "openssl-3.0.13-0ubuntu3.7" }])).toEqual([]);
  });

  it("el ACK lleva notMatched y los resultados una fila por cada uno", () => {
    const src = fs.readFileSync(path.join(__dirname, "../../src/transport/grpc-stream.ts"), "utf8");
    expect(src).toContain("unmatchedRequested(kbArticleIds, devueltos)");
    expect(src).toContain("notMatched=${sinCasar.length}");
  });
});

describe("Windows sin KB: «UID:<UpdateID>» (1-oct-2026)", () => {
  it("unsafePatchIds lo acepta en Windows y rechaza un UID mal formado", () => {
    expect(unsafePatchIds(["UID:3f2c9a10-1b2c-4d5e-8f90-abcdef123456"], "win32")).toEqual([]);
    expect(unsafePatchIds(["UID:$(whoami)", "UID:3f2c9a10"], "win32")).toHaveLength(2);
  });

  it("unmatchedRequested casa «UID:<guid>» con el updateId del resultado", () => {
    expect(
      unmatchedRequested(["UID:3F2C9A10-1B2C-4D5E-8F90-ABCDEF123456"], [{ updateId: "3f2c9a10-1b2c-4d5e-8f90-abcdef123456" }])
    ).toEqual([]);
  });
});

