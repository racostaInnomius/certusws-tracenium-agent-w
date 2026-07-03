// test/plugins/sdp-forensics.test.ts
//
// B3 — lado-agente: el plugin SDP debe EMITIR los snapshots de
// detección pre/post en el ACK (`detectBefore` / `detectAfter`) como
// base64url, para que el backend los persista en las columnas JSONB
// `detection_before` / `detection_after`.
//
// Contrato verificado contra el backend (repo hermano):
//   certusws-tracenium/modules/software-delivery/install-result-reducer.ts
//     - keys: `detectBefore` / `detectAfter`   (parseAckMessage, ~L155-164)
//     - encoding: Buffer.from(value, "base64url") → JSON.parse
//       (decodeJsonB64, ~L98-109)
//     - guard oversized: value.length > 24_000 → undefined
//
// Estrategia: se ejecuta el `runSoftwareInstall` REAL con un
// `ctx.priv.call` mockeado que:
//   - `sdp.detect`   → devuelve { matched, snapshot }
//   - `sdp.download` → ok con stagingPath
//   - `sdp.install`  → ok con exitCode 0
// y se decodifica el ACK emitido replicando la lógica del backend
// (decodeJsonB64) para probar compatibilidad REAL del contrato.

import os from "os";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { runSoftwareInstall, FORENSICS_B64_MAX_LEN } from "../../src/plugins/sdp";

// ── Réplica EXACTA del decoder del backend (install-result-reducer.ts)
// para probar el round-trip contra el contrato real, no una versión
// idealizada. ───────────────────────────────────────────────────────
function backendDecodeJsonB64(value: string | undefined): unknown {
  if (!value || typeof value !== "string") return undefined;
  if (value.length > 24_000) return undefined;
  try {
    const json = Buffer.from(value, "base64url").toString("utf8");
    if (!json) return undefined;
    if (json.length > 16_384) return undefined;
    return JSON.parse(json);
  } catch {
    return undefined;
  }
}

// ── Réplica del parser de segmentos del backend para extraer el valor
// crudo de una key del ACK. IMPORTANTE: separa por `;` y por el PRIMER
// `=`, igual que parseAckMessage. ────────────────────────────────────
function extractAckKey(message: string, key: string): string | undefined {
  const segments = message.split(";").map((s) => s.trim()).filter(Boolean);
  for (const seg of segments.slice(1)) {
    const eq = seg.indexOf("=");
    if (eq <= 0) continue;
    if (seg.slice(0, eq).trim() === key) return seg.slice(eq + 1).trim();
  }
  return undefined;
}

// Plataforma local normalizada al vocabulario del backend, para que el
// snapshot del paquete pase el guard de "platform fit" del plugin.
function localPlatform(): "windows" | "macos" | "linux" {
  const p = os.platform();
  if (p === "win32") return "windows";
  if (p === "darwin") return "macos";
  return "linux";
}

// `command_exit` es aplicable en win32/darwin/linux, así que la regla
// de detección corre en cualquier host de CI.
function makePackage(overrides: Record<string, unknown> = {}) {
  return {
    id: 42,
    name: "TestPkg",
    version: "1.0.0",
    platform: localPlatform(),
    arch: "x64",
    format: "exe",
    downloadPath: "https://example/pkg",
    sha256: "abc",
    detectionRule: { type: "command_exit", cmd: "true" },
    expectedExitCodes: [0],
    ...overrides,
  };
}

// ctx mínimo: sólo lo que el plugin toca.
function makeCtx(privCall: (req: any) => Promise<any>) {
  const warns: any[][] = [];
  return {
    ctx: {
      enrollment: { tenantId: "t1", deviceId: "d1" },
      policyRuntime: { pluginEnabled: () => true },
      priv: { call: vi.fn(privCall) },
      logger: {
        info: () => {},
        warn: (...a: any[]) => warns.push(a),
        error: () => {},
      },
    } as any,
    warns,
  };
}

// Router de priv.call por método, con snapshots configurables.
function privRouter(opts: {
  preMatched: boolean;
  preSnapshot?: unknown;
  postMatched?: boolean;
  postSnapshot?: unknown;
  installExit?: number;
}) {
  let detectCalls = 0;
  return async (req: any) => {
    if (req.method === "sdp.detect") {
      detectCalls++;
      const isPre = detectCalls === 1;
      return {
        ok: true,
        result: {
          matched: isPre ? opts.preMatched : (opts.postMatched ?? true),
          snapshot: isPre ? opts.preSnapshot : opts.postSnapshot,
        },
      };
    }
    if (req.method === "sdp.download") {
      return { ok: true, result: { stagingPath: "/tmp/stage" } };
    }
    if (req.method === "sdp.install") {
      return { ok: true, result: { exitCode: opts.installExit ?? 0, durationMs: 5 } };
    }
    return { ok: false, error: { code: "unexpected_method" } };
  };
}

describe("SDP B3 forensics — emit detectBefore/detectAfter", () => {
  beforeEach(() => vi.clearAllMocks());

  it("emite detectBefore Y detectAfter (base64url) en el success path y round-trip decodifica al snapshot original", async () => {
    const preSnap = { found: false, checked: "registry", version: null };
    const postSnap = { found: true, checked: "registry", version: "1.0.0" };
    const { ctx } = makeCtx(
      privRouter({
        preMatched: false,
        preSnapshot: preSnap,
        postMatched: true,
        postSnapshot: postSnap,
      })
    );

    const ack = await runSoftwareInstall(ctx, "job-1", {
      deploymentId: 7,
      packageSnapshot: makePackage(),
    });

    expect(ack.outcome).toBe("success");
    const before = extractAckKey(ack.ackMessage, "detectBefore");
    const after = extractAckKey(ack.ackMessage, "detectAfter");
    expect(before).toBeDefined();
    expect(after).toBeDefined();
    // Alfabeto base64url: sin '+', '/', '='.
    expect(before!).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(after!).toMatch(/^[A-Za-z0-9_-]+$/);
    // Round-trip contra el decoder del backend.
    expect(backendDecodeJsonB64(before)).toEqual(preSnap);
    expect(backendDecodeJsonB64(after)).toEqual(postSnap);
  });

  it("emite sólo detectBefore cuando el pre-detect matchea (already_installed, sin post)", async () => {
    const preSnap = { found: true, version: "2.0.0" };
    const { ctx } = makeCtx(
      privRouter({ preMatched: true, preSnapshot: preSnap })
    );

    const ack = await runSoftwareInstall(ctx, "job-2", {
      deploymentId: 8,
      packageSnapshot: makePackage(),
    });

    expect(ack.outcome).toBe("already_installed");
    expect(extractAckKey(ack.ackMessage, "detectBefore")).toBeDefined();
    // No hubo post-detect → la key se OMITE (backend usa COALESCE).
    expect(extractAckKey(ack.ackMessage, "detectAfter")).toBeUndefined();
    expect(backendDecodeJsonB64(extractAckKey(ack.ackMessage, "detectBefore"))).toEqual(
      preSnap
    );
  });

  it("OMITE la key cuando el privsvc no devolvió snapshot", async () => {
    const { ctx } = makeCtx(
      privRouter({
        preMatched: false,
        preSnapshot: undefined,
        postMatched: true,
        postSnapshot: undefined,
      })
    );

    const ack = await runSoftwareInstall(ctx, "job-3", {
      deploymentId: 9,
      packageSnapshot: makePackage(),
    });

    expect(ack.outcome).toBe("success");
    expect(extractAckKey(ack.ackMessage, "detectBefore")).toBeUndefined();
    expect(extractAckKey(ack.ackMessage, "detectAfter")).toBeUndefined();
  });

  it("oversized → OMITE la key y loguea warn; el resto del ACK sigue válido", async () => {
    // Un snapshot cuyo JSON base64url supera FORENSICS_B64_MAX_LEN.
    // base64 ≈ 4/3 del input; generamos un string bien por encima.
    const big = "x".repeat(FORENSICS_B64_MAX_LEN); // >20k chars → b64 ~27k
    const preSnap = { blob: big };
    const postSnap = { ok: true }; // pequeño, sí debe emitirse
    const { ctx, warns } = makeCtx(
      privRouter({
        preMatched: false,
        preSnapshot: preSnap,
        postMatched: true,
        postSnapshot: postSnap,
      })
    );

    const ack = await runSoftwareInstall(ctx, "job-4", {
      deploymentId: 10,
      packageSnapshot: makePackage(),
    });

    expect(ack.outcome).toBe("success");
    // Oversized omitido.
    expect(extractAckKey(ack.ackMessage, "detectBefore")).toBeUndefined();
    // El pequeño sí se emite.
    const after = extractAckKey(ack.ackMessage, "detectAfter");
    expect(after).toBeDefined();
    expect(backendDecodeJsonB64(after)).toEqual(postSnap);
    // Warn emitido para el oversized.
    expect(warns.some((w) => String(w[0]).includes("oversized"))).toBe(true);
    // Sanidad: el valor que SÍ emitimos está bajo el gate del backend.
    expect(after!.length).toBeLessThanOrEqual(24_000);
  });

  it("emite detectBefore+detectAfter también en post_detect_mismatch (failed)", async () => {
    const preSnap = { found: false };
    const postSnap = { found: false, reason: "gpo_reverted" };
    const { ctx } = makeCtx(
      privRouter({
        preMatched: false,
        preSnapshot: preSnap,
        postMatched: false, // no matchea tras instalar → post_detect_mismatch
        postSnapshot: postSnap,
      })
    );

    const ack = await runSoftwareInstall(ctx, "job-5", {
      deploymentId: 11,
      packageSnapshot: makePackage(),
    });

    expect(ack.outcome).toBe("failed");
    expect(ack.ackMessage).toContain("reason=post_detect_mismatch");
    expect(backendDecodeJsonB64(extractAckKey(ack.ackMessage, "detectBefore"))).toEqual(
      preSnap
    );
    expect(backendDecodeJsonB64(extractAckKey(ack.ackMessage, "detectAfter"))).toEqual(
      postSnap
    );
  });
});
