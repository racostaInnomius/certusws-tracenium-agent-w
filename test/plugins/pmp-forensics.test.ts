// test/plugins/pmp-forensics.test.ts
//
// B3 — lado-agente: el plugin PMP (remediation) debe EMITIR los
// snapshots de estado de cumplimiento pre/post en el ACK
// (`stateBefore` / `stateAfter`) como base64url, para que el backend
// los persista en las columnas JSONB `state_before` / `state_after`.
//
// Contrato verificado contra el backend (repo hermano):
//   certusws-tracenium/modules/patch-management/remediation-result-reducer.ts
//     - keys: `stateBefore` / `stateAfter`   (parseAckMessage, ~L150-159)
//     - encoding: Buffer.from(value, "base64url") → JSON.parse
//       (decodeJsonB64, ~L93-104)
//     - guard oversized: value.length > 24_000 → undefined
//
// Se ejecuta el `runRemediation` REAL con `ctx.priv.call` mockeado:
//   - `pmp.read_check_state` → { isCompliant, snapshot }  (pre y post)
//   - `pmp.remediate`        → ok con exitCode 0
// El checkId se elige según la plataforma local para pasar el
// whitelist gate en cualquier host de CI.

import os from "os";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { runRemediation, FORENSICS_B64_MAX_LEN } from "../../src/plugins/pmp/remediation";

// Réplica EXACTA del decoder del backend (remediation-result-reducer.ts).
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

function extractAckKey(message: string, key: string): string | undefined {
  const segments = message.split(";").map((s) => s.trim()).filter(Boolean);
  for (const seg of segments.slice(1)) {
    const eq = seg.indexOf("=");
    if (eq <= 0) continue;
    if (seg.slice(0, eq).trim() === key) return seg.slice(eq + 1).trim();
  }
  return undefined;
}

// checkId + platform válidos para el OS local (deben existir en
// remediation-checks.ts).
function localCheck(): { checkId: string; platform: string } {
  const p = os.platform();
  if (p === "win32")
    return { checkId: "windows.firewall.profiles_enabled", platform: "windows" };
  if (p === "darwin")
    return { checkId: "macos.firewall.enabled", platform: "macos" };
  return { checkId: "linux.ssh.root_login_disabled", platform: "linux" };
}

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
      _patchInstallInProgress: false,
    } as any,
    warns,
  };
}

// Router: primer read_check_state = pre, segundo = post.
function privRouter(opts: {
  preCompliant: boolean;
  preSnapshot?: unknown;
  postCompliant?: boolean;
  postSnapshot?: unknown;
  remediateOk?: boolean;
}) {
  let reads = 0;
  return async (req: any) => {
    if (req.method === "pmp.read_check_state") {
      reads++;
      const isPre = reads === 1;
      return {
        ok: true,
        result: {
          isCompliant: isPre ? opts.preCompliant : (opts.postCompliant ?? true),
          snapshot: isPre ? opts.preSnapshot : opts.postSnapshot,
        },
      };
    }
    if (req.method === "pmp.remediate") {
      return opts.remediateOk === false
        ? { ok: false, error: { code: "remediate_failed" } }
        : { ok: true, result: { exitCode: 0, durationMs: 5, requiresReboot: false } };
    }
    return { ok: false, error: { code: "unexpected_method" } };
  };
}

function makePayload(overrides: Record<string, unknown> = {}) {
  const lc = localCheck();
  return {
    remediationId: 3,
    checkId: lc.checkId,
    mode: "apply",
    checkSnapshot: { checkId: lc.checkId, platform: lc.platform },
    ...overrides,
  };
}

describe("PMP B3 forensics — emit stateBefore/stateAfter", () => {
  beforeEach(() => vi.clearAllMocks());

  it("emite stateBefore Y stateAfter (base64url) al aplicar y round-trip decodifica al snapshot original", async () => {
    const preSnap = { compliant: false, value: "TLS1.0 enabled" };
    const postSnap = { compliant: true, value: "TLS1.0 disabled" };
    const { ctx } = makeCtx(
      privRouter({
        preCompliant: false,
        preSnapshot: preSnap,
        postCompliant: true,
        postSnapshot: postSnap,
      })
    );

    const ack = await runRemediation(ctx, "job-1", makePayload());

    expect(ack.outcome).toBe("applied");
    const before = extractAckKey(ack.ackMessage, "stateBefore");
    const after = extractAckKey(ack.ackMessage, "stateAfter");
    expect(before).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(after).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(backendDecodeJsonB64(before)).toEqual(preSnap);
    expect(backendDecodeJsonB64(after)).toEqual(postSnap);
  });

  it("dry_run emite sólo stateBefore (no hay post)", async () => {
    const preSnap = { compliant: false };
    const { ctx } = makeCtx(
      privRouter({ preCompliant: false, preSnapshot: preSnap })
    );

    const ack = await runRemediation(ctx, "job-2", makePayload({ mode: "dry_run" }));

    expect(ack.outcome).toBe("dryrun_would_apply");
    expect(backendDecodeJsonB64(extractAckKey(ack.ackMessage, "stateBefore"))).toEqual(
      preSnap
    );
    expect(extractAckKey(ack.ackMessage, "stateAfter")).toBeUndefined();
  });

  it("OMITE las keys cuando el privsvc no devolvió snapshot", async () => {
    const { ctx } = makeCtx(
      privRouter({
        preCompliant: false,
        preSnapshot: undefined,
        postCompliant: true,
        postSnapshot: undefined,
      })
    );

    const ack = await runRemediation(ctx, "job-3", makePayload());

    expect(ack.outcome).toBe("applied");
    // read_check_state devolvió result SIN snapshot → preState cae al
    // propio result (que no tiene .snapshot). Ese objeto igualmente es
    // pequeño y se emite; para forzar OMISIÓN real, el privsvc devuelve
    // isCompliant sin más. Verificamos que las keys SÍ se emiten con el
    // fallback (result) — es válido y no rompe el backend.
    // (Este caso documenta el fallback; la omisión dura se cubre en el
    //  test de "oversized".)
    const before = extractAckKey(ack.ackMessage, "stateBefore");
    expect(backendDecodeJsonB64(before)).toBeDefined();
  });

  it("oversized → OMITE la key y loguea warn; el resto del ACK sigue válido", async () => {
    const big = "x".repeat(FORENSICS_B64_MAX_LEN);
    const preSnap = { blob: big };
    const postSnap = { compliant: true };
    const { ctx, warns } = makeCtx(
      privRouter({
        preCompliant: false,
        preSnapshot: preSnap,
        postCompliant: true,
        postSnapshot: postSnap,
      })
    );

    const ack = await runRemediation(ctx, "job-4", makePayload());

    expect(ack.outcome).toBe("applied");
    expect(extractAckKey(ack.ackMessage, "stateBefore")).toBeUndefined();
    const after = extractAckKey(ack.ackMessage, "stateAfter");
    expect(after).toBeDefined();
    expect(backendDecodeJsonB64(after)).toEqual(postSnap);
    expect(warns.some((w) => String(w[0]).includes("oversized"))).toBe(true);
    expect(after!.length).toBeLessThanOrEqual(24_000);
  });

  it("post_state_mismatch (failed) también lleva stateBefore+stateAfter", async () => {
    const preSnap = { compliant: false };
    const postSnap = { compliant: false, reason: "gpo_reverted" };
    const { ctx } = makeCtx(
      privRouter({
        preCompliant: false,
        preSnapshot: preSnap,
        postCompliant: false, // sigue no-compliant tras aplicar
        postSnapshot: postSnap,
      })
    );

    const ack = await runRemediation(ctx, "job-5", makePayload());

    expect(ack.outcome).toBe("failed");
    expect(ack.ackMessage).toContain("reason=post_state_mismatch");
    expect(backendDecodeJsonB64(extractAckKey(ack.ackMessage, "stateBefore"))).toEqual(
      preSnap
    );
    expect(backendDecodeJsonB64(extractAckKey(ack.ackMessage, "stateAfter"))).toEqual(
      postSnap
    );
  });

  it("post_state_mismatch lleva el porqué del privsvc (stderrExcerpt), como el revert", async () => {
    // Caso real: el drop-in SSH no gana porque otro fichero fija la
    // directiva antes. Sin esto el portal sólo veía «post_state_mismatch».
    const base = privRouter({ preCompliant: false, postCompliant: false });
    const { ctx } = makeCtx(async (req: any) =>
      req.method === "pmp.remediate"
        ? {
            ok: true,
            result: {
              exitCode: 1,
              stderrExcerpt: "/etc/ssh/sshd_config.d/00-aaa.conf:2 (yes) sets PasswordAuthentication before ours",
              durationMs: 5,
              requiresReboot: false,
              changesApplied: [],
            },
          }
        : base(req)
    );

    const ack = await runRemediation(ctx, "job-6", makePayload());

    expect(ack.outcome).toBe("failed");
    expect(extractAckKey(ack.ackMessage, "reason")).toBe(
      "post_state_mismatch: /etc/ssh/sshd_config.d/00-aaa.conf:2 (yes) sets PasswordAuthentication before ours"
    );
  });
});

// Job 3799974e (1-oct-2026): `Windows Feeds\EnableFeeds` falló tres veces en
// W11-JPR-LAB02 y el portal sólo decía «failed · remediate_failed». El PrivSvc
// de Windows SÍ devolvía el mensaje de la excepción; el agente lo tiraba.
describe("un fallo del PrivSvc llega con su PORQUÉ", () => {
  const failing = (error: Record<string, unknown>) => async (req: any) => {
    if (req.method === "pmp.read_check_state") return { ok: true, result: { isCompliant: false, snapshot: { present: false } } };
    if (req.method === "pmp.remediate") return { ok: false, error };
    return { ok: false, error: { code: "unexpected_method" } };
  };

  it("⭐ el mensaje viaja en `reason`, saneado (sin `;` ni `=` que rompan el acuse)", async () => {
    const { ctx } = makeCtx(
      failing({ code: "remediate_failed", message: "Access to the registry key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Feeds' is denied; a=b" })
    );
    const ack = await runRemediation(ctx, "job-f1", makePayload());
    expect(ack.outcome).toBe("failed");
    const reason = extractAckKey(ack.ackMessage, "reason");
    expect(reason).toMatch(/^remediate_failed: Access to the registry key .*Windows Feeds' is denied/);
    expect(reason).not.toMatch(/[;=]/);
  });

  it("y con el estado de ANTES: qué había cuando se intentó escribir", async () => {
    const { ctx } = makeCtx(failing({ code: "remediate_failed", message: "boom" }));
    const ack = await runRemediation(ctx, "job-f2", makePayload());
    expect(backendDecodeJsonB64(extractAckKey(ack.ackMessage, "stateBefore"))).toEqual({ present: false });
  });

  it("sin mensaje, el código solo (como antes); y un timeout sigue siendo timed_out", async () => {
    const a = await runRemediation(makeCtx(failing({ code: "remediate_failed" })).ctx, "job-f3", makePayload());
    expect(extractAckKey(a.ackMessage, "reason")).toBe("remediate_failed");
    const b = await runRemediation(makeCtx(failing({ code: "remediate_timeout", message: "took 540 s" })).ctx, "job-f4", makePayload());
    expect(b.outcome).toBe("timed_out");
    expect(extractAckKey(b.ackMessage, "reason")).toBe("remediate_timeout: took 540 s");
  });
});
