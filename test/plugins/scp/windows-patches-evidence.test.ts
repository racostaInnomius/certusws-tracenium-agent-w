// test/plugins/scp/windows-patches-evidence.test.ts
//
// El bloque `patches` de SCP en Windows, tal y como sale del agente.
//
// `buildPatchesEvidence` RECONSTRUYE el objeto que manda PrivSvc: lo que no
// copia no sale del equipo. Desde el 22-sep-2026 PrivSvc manda, además de las
// instalaciones correctas, los fallos y las desinstalaciones del historial de
// Windows Update —la materia prima del Confidence Score de parches—, y este
// paso los habría tirado en silencio.

import { describe, it, expect } from "vitest";
import { buildPatchesEvidence } from "../../../src/plugins/scp/providers/windows";

const ok = { hotFixId: "KB5122882", installedOn: "2026-09-20T00:31:39Z", resultCode: 2, operation: "install" };
const fallo = { hotFixId: "KB5120708", attemptedOn: "2026-09-10T03:00:00Z", resultCode: 4, hresult: "0x80070070", operation: "install" };
const rollback = { hotFixId: "KB5094126", attemptedOn: "2026-08-15T10:00:00Z", resultCode: 2, hresult: "0x00000000", operation: "uninstall" };

describe("buildPatchesEvidence (Windows)", () => {
  it("⭐ los fallos y las desinstalaciones salen del equipo", () => {
    const ev = buildPatchesEvidence({
      patches: { count: 1, lastScanUtc: "2026-09-22T00:00:00Z", items: [ok], failures: [fallo], uninstalls: [rollback] },
    });
    expect(ev.failures).toEqual([fallo]);
    expect(ev.uninstalls).toEqual([rollback]);
  });

  it("⭐ `items` y `count` siguen siendo SÓLO las instalaciones correctas", () => {
    // Lo leen los checks de SCP («parcheado en los últimos N días»): un fallo
    // aquí contaría como equipo parcheado.
    const ev = buildPatchesEvidence({ patches: { count: 1, items: [ok], failures: [fallo, fallo], uninstalls: [rollback] } });
    expect(ev.items).toEqual([ok]);
    expect(ev.count).toBe(1);
  });

  it("⚠️ ausente ≠ vacío: un PrivSvc antiguo no manda los campos, y no se inventan", () => {
    // Convertir la ausencia en [] diría «sin fallos» sobre algo que nadie miró.
    const ev = buildPatchesEvidence({ patches: { count: 1, items: [ok] } });
    expect(ev).not.toHaveProperty("failures");
    expect(ev).not.toHaveProperty("uninstalls");
  });

  it("el respaldo Get-HotFix (no ve fallos) tampoco los inventa", () => {
    const ev = buildPatchesEvidence({ patches: { status: "present", count: 1, source: "fallback", items: [ok] } });
    expect(ev).not.toHaveProperty("failures");
  });

  it("[] se conserva como [] — se miró y no hubo ninguno", () => {
    const ev = buildPatchesEvidence({ patches: { count: 1, items: [ok], failures: [], uninstalls: [] } });
    expect(ev.failures).toEqual([]);
    expect(ev.uninstalls).toEqual([]);
  });

  it("un objeto suelto donde iba un array de uno se lee como lista", () => {
    // PowerShell desenvuelve un array de un elemento si se le escapa un pipe.
    const ev = buildPatchesEvidence({ patches: { items: [ok], failures: fallo } });
    expect(ev.failures).toEqual([fallo]);
  });

  it("sin bloque `patches` no aparece nada nuevo", () => {
    const ev = buildPatchesEvidence({});
    expect(ev.items).toEqual([]);
    expect(ev).not.toHaveProperty("failures");
  });
});
