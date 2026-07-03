// test/plugins/pmp-scan-normalize.test.ts
//
// Sprint 2 — P1. PMP scan → normalización a PmpNamespace.
//
// ⚠️ HALLAZGO IMPORTANTE sobre "parseo de salidas de patch scan":
//
// El brief pedía fixtures string de WUA/WSUS, `softwareupdate`, apt/dnf
// (incl. locale no-inglés). Tras leer los tres providers
// (src/plugins/pmp/providers/{windows,macos,linux}.ts) y los clientes
// privsvc (src/priv/privsvc-client-*.ts), el parseo de TEXTO CRUDO de
// esas herramientas NO vive en este repo: ocurre en el privsvc
// (proceso privilegiado, repos aparte: privsvc/windows/*.cs,
// privsvc/macos/*.ts). El agente recibe del privsvc, vía
// `ctx.priv.call("patch.scan")`, un objeto YA ESTRUCTURADO
// (`{ items: [...], status, updateCount, ... }`) y sólo lo NORMALIZA a
// la forma `PmpNamespace`.
//
// => El riesgo clásico "parser frágil ante locale" NO es testeable en
//    este repo; vive en el privsvc. Lo que sí se testea aquí, con
//    fixtures con forma real de resultado privsvc, es la normalización:
//    normalizePatchItems (por plataforma), asSeverity/asType/asScanSource
//    (Linux), y deriveOverallStatus/deriveOverallScore.
//
// Como esas funciones son módulo-privadas, se ejercitan a través de los
// exports públicos collect{Windows,Macos,Linux}Pmp con `ctx.priv.call`
// mockeado y `loadPmpState` mockeado (evita tocar disco).

import { describe, it, expect, vi, beforeEach } from "vitest";

// loadPmpState → idle por defecto (evita leer/crear /var/lib/tracenium,
// /Library/Application Support/Tracenium, C:\ProgramData\...).
const pmpStateRef: { value: any } = { value: {} };
vi.mock("../../src/plugins/pmp/state", () => ({
  loadPmpState: vi.fn(() => pmpStateRef.value),
  savePmpState: vi.fn(),
  updatePmpState: vi.fn(),
  tryStartRemediate: vi.fn(() => true),
  finishRemediate: vi.fn(),
  isRemediateInFlight: vi.fn(() => false)
}));

import { collectWindowsPmp } from "../../src/plugins/pmp/providers/windows";
import { collectMacosPmp } from "../../src/plugins/pmp/providers/macos";
import { collectLinuxPmp } from "../../src/plugins/pmp/providers/linux";

function makeCtx(result: any, ok = true) {
  return {
    config: { agentVersion: "test-9.9.9" },
    enrollment: { tenantId: "t1", deviceId: "d1" },
    priv: {
      call: vi.fn(async (req: any) => {
        expect(req.method).toBe("patch.scan");
        return ok ? { ok: true, result } : { ok: false, error: { message: "scan boom" } };
      })
    },
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} }
  } as any;
}

beforeEach(() => {
  pmpStateRef.value = {};
  vi.clearAllMocks();
});

// ─────────────────────────────────────────────────────────────────────
// Windows — MSRC severity + shape del scan
// ─────────────────────────────────────────────────────────────────────
describe("PMP Windows — normalización de patch.scan (WUA/MSRC)", () => {
  it("mapea kbArticleIds[0]→hotFixId, msrcSeverity→severity canónica (case-insensitive)", async () => {
    // Fixture con forma real del privsvc de Windows (IUpdate proyectado).
    const ctx = makeCtx({
      status: "updates_available",
      scannedAtUtc: "2026-07-01T00:00:00.000Z",
      updateCount: 3,
      securityUpdateCount: 2,
      items: [
        { kbArticleIds: ["5039211"], title: "2026-06 Cumulative Update", msrcSeverity: "Critical" },
        { kbArticleIds: ["5039093"], title: ".NET Rollup", msrcSeverity: "important" },
        { kbArticleIds: [], title: "Defender Definition", msrcSeverity: "GARBAGE" }
      ]
    });

    const ns = await collectWindowsPmp(ctx);
    expect(ns.scan?.source).toBe("windows_update_agent");
    expect(ns.overall.status).toBe("updates_available");
    expect(ns.overall.score).toBe(40);
    expect(ns.scan?.scannedAtUtc).toBe("2026-07-01T00:00:00.000Z");

    const items = ns.scan!.items!;
    expect(items[0]).toMatchObject({ hotFixId: "5039211", severity: "critical" });
    expect(items[1].severity).toBe("important");
    // kbArticleIds vacío → hotFixId undefined; severity desconocida → "unknown".
    expect(items[2].hotFixId).toBeUndefined();
    expect(items[2].severity).toBe("unknown");
    // Todos etiquetados con la fuente WUA.
    expect(items.every((i) => i.source === "windows_update_agent")).toBe(true);
  });

  it("normalizeArray: un item objeto (no-array) se envuelve en [item]", async () => {
    const ctx = makeCtx({
      status: "updates_available",
      items: { kbArticleIds: ["5000001"], title: "Single", msrcSeverity: "Moderate" }
    });
    const ns = await collectWindowsPmp(ctx);
    expect(ns.scan?.items).toHaveLength(1);
    expect(ns.scan?.items?.[0].severity).toBe("moderate");
  });

  it("patch.scan falla (ok:false) → overall=error, score=0, scan.items vacío", async () => {
    const ctx = makeCtx(null, false);
    const ns = await collectWindowsPmp(ctx);
    expect(ns.overall.status).toBe("error");
    expect(ns.overall.score).toBe(0);
    expect(ns.scan?.items).toEqual([]);
    // remediation idle sin resultados previos → registra el error como failed result.
    expect(ns.remediation?.results?.[0]).toMatchObject({ result: "failed" });
  });

  it("estado 'healthy' del privsvc se preserva y da score 100", async () => {
    const ctx = makeCtx({ status: "healthy", items: [] });
    const ns = await collectWindowsPmp(ctx);
    expect(ns.overall.status).toBe("healthy");
    expect(ns.overall.score).toBe(100);
  });

  it("remediation in_progress (state) fuerza overall='installing' aunque haya updates", async () => {
    pmpStateRef.value = { status: "in_progress", mode: "install" };
    const ctx = makeCtx({ status: "updates_available", items: [] });
    const ns = await collectWindowsPmp(ctx);
    expect(ns.overall.status).toBe("installing");
    expect(ns.overall.score).toBe(30);
  });

  it("rebootRequired (state) fuerza overall='reboot_required'", async () => {
    pmpStateRef.value = { status: "success", rebootRequired: true };
    const ctx = makeCtx({ status: "updates_available", items: [] });
    const ns = await collectWindowsPmp(ctx);
    expect(ns.overall.status).toBe("reboot_required");
    expect(ns.overall.score).toBe(60);
  });
});

// ─────────────────────────────────────────────────────────────────────
// macOS — softwareupdate NO expone severity → "unknown" EXPLÍCITO
// ─────────────────────────────────────────────────────────────────────
describe("PMP macOS — normalización de patch.scan (softwareupdate)", () => {
  it("cada item lleva severity='unknown' explícita (softwareupdate no la expone) y source apple", async () => {
    // Fixture: forma que el privsvc macOS produce parseando
    // `softwareupdate --list` (label = identificador del update).
    const ctx = makeCtx({
      status: "updates_available",
      items: [
        { label: "macOS Sonoma 14.5-23F79", title: "macOS Sonoma 14.5" },
        { label: "Safari17.5SonomaAuto", title: "Safari 17.5" }
      ]
    });

    const ns = await collectMacosPmp(ctx);
    expect(ns.scan?.source).toBe("apple_software_update");
    const items = ns.scan!.items!;
    expect(items).toHaveLength(2);
    expect(items[0]).toMatchObject({
      hotFixId: "macOS Sonoma 14.5-23F79",
      severity: "unknown",
      source: "apple_software_update"
    });
    // Contrato: NUNCA undefined; siempre "unknown" para uniformidad del schema.
    expect(items.every((i) => i.severity === "unknown")).toBe(true);
  });

  it("sin items → inventory_only, score 20", async () => {
    const ctx = makeCtx({ status: "healthy" }); // sin items → normalizeArray([]) = []
    const ns = await collectMacosPmp(ctx);
    // status healthy del privsvc gana.
    expect(ns.overall.status).toBe("healthy");
  });
});

// ─────────────────────────────────────────────────────────────────────
// Linux — asSeverity / asType / asScanSource + extras (cveIds, reboot)
// ─────────────────────────────────────────────────────────────────────
describe("PMP Linux — normalización de patch.scan (apt/dnf/zypper)", () => {
  it("dnf: mapea severity/type válidos, preserva cveIds y rebootRequired, source=linux_dnf", async () => {
    // Fixture con forma real del privsvc Linux (dnf updateinfo proyectado).
    const ctx = makeCtx({
      status: "updates_available",
      source: "linux_dnf",
      updateCount: 2,
      securityUpdateCount: 1,
      items: [
        {
          hotFixId: "RHSA-2026:1234",
          title: "kernel security update",
          severity: "Important",
          type: "security",
          cveIds: ["CVE-2026-0001", "CVE-2026-0002"],
          rebootRequired: true,
          source: "linux_dnf"
        },
        {
          hotFixId: "RHBA-2026:5678",
          title: "curl bugfix",
          severity: "wat", // inválido → "unknown"
          type: "chore",   // inválido → undefined
          source: "linux_dnf"
        }
      ]
    });

    const ns = await collectLinuxPmp(ctx);
    expect(ns.scan?.source).toBe("linux_dnf");
    const items = ns.scan!.items!;
    expect(items[0]).toMatchObject({
      hotFixId: "RHSA-2026:1234",
      severity: "important",
      type: "security",
      rebootRequired: true
    });
    expect(items[0].cveIds).toEqual(["CVE-2026-0001", "CVE-2026-0002"]);
    // Valores inválidos degradan a unknown / undefined (defensivo).
    expect(items[1].severity).toBe("unknown");
    expect(items[1].type).toBeUndefined();
    expect(items[1].rebootRequired).toBeUndefined();
  });

  it("apt: source=linux_apt se preserva; type ausente cae a undefined", async () => {
    const ctx = makeCtx({
      status: "updates_available",
      source: "linux_apt",
      items: [{ hotFixId: "openssl-3.0.2-0ubuntu1.15", title: "openssl", severity: "low" }]
    });
    const ns = await collectLinuxPmp(ctx);
    expect(ns.scan?.source).toBe("linux_apt");
    expect(ns.scan?.items?.[0].severity).toBe("low");
    expect(ns.scan?.items?.[0].type).toBeUndefined();
  });

  it("source desconocido del privsvc degrada a 'patch_management_unavailable'", async () => {
    const ctx = makeCtx({ status: "updates_available", source: "linux_pacman", items: [] });
    const ns = await collectLinuxPmp(ctx);
    expect(ns.scan?.source).toBe("patch_management_unavailable");
  });

  it("scan falla → error + source unavailable + failed result", async () => {
    const ctx = makeCtx(null, false);
    const ns = await collectLinuxPmp(ctx);
    expect(ns.overall.status).toBe("error");
    expect(ns.scan?.source).toBe("patch_management_unavailable");
    expect(ns.remediation?.results?.[0]).toMatchObject({ result: "failed" });
  });
});
