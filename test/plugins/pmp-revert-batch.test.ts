// test/plugins/pmp-revert-batch.test.ts
//
// Deshacer un fix (modos `revert` / `revert_dry_run`) y varios fixes en UN
// job (`items`), por el `runRemediation` REAL con `ctx.priv.call` mockeado.
//
// Contrato con el backend (repo hermano):
//   · revert: params.stateBefore = el `state` de pmp.read_check_state antes
//     del fix; `applied` sólo si al releer el estado ES el de antes.
//   · lote: UN ACK `patch_remediate_batch:done;items=<b64url(JSON [ack…])>`
//     que remediation-result-reducer.ts (parseBatchAckMessage) reparte fix a
//     fix por remediationId.

import os from "os";
import { describe, it, expect, vi } from "vitest";
import {
  runRemediation,
  encodeBatchAck,
  stateMatchesBefore,
  BATCH_ITEMS_B64_MAX,
  PMP_REMEDIATE_CAPABILITIES,
  pmpRemediateCapabilities,
} from "../../src/plugins/pmp/remediation";

function localCheck(): { checkId: string; platform: string } {
  const p = os.platform();
  if (p === "win32") return { checkId: "windows.firewall.profiles_enabled", platform: "windows" };
  if (p === "darwin") return { checkId: "macos.firewall.enabled", platform: "macos" };
  return { checkId: "linux.ssh.root_login_disabled", platform: "linux" };
}
const { checkId, platform } = localCheck();

function makeCtx(privCall: (req: any) => Promise<any>) {
  return {
    enrollment: { tenantId: "t1", deviceId: "d1" },
    policyRuntime: { pluginEnabled: () => true },
    priv: { call: vi.fn(privCall) },
    logger: { info: () => {}, warn: () => {}, error: () => {} },
    _patchInstallInProgress: false,
  } as any;
}

/** El agente lee `states` en orden (pre, post…); pmp.revert / remediate contestan ok. */
function router(states: unknown[], opts: { revert?: any; remediate?: any } = {}) {
  let i = 0;
  return async (req: any) => {
    if (req.method === "pmp.read_check_state") {
      const state = states[Math.min(i, states.length - 1)];
      i += 1;
      return { ok: true, result: { state, isCompliant: false, supported: true } };
    }
    if (req.method === "pmp.revert") return opts.revert ?? { ok: true, result: { exitCode: 0, durationMs: 5, requiresReboot: false, changesApplied: ["x"] } };
    if (req.method === "pmp.remediate") return opts.remediate ?? { ok: true, result: { exitCode: 0, durationMs: 5, requiresReboot: false, changesApplied: ["x"] } };
    return { ok: false, error: { code: "unexpected" } };
  };
}

const item = (over: Record<string, unknown> = {}) => ({
  remediationId: 11,
  checkId,
  mode: "revert",
  checkSnapshot: { checkId, platform },
  params: { stateBefore: { enabled: false } },
  ...over,
});

describe("revert — deshacer un fix", () => {
  it("⭐ revert_dry_run: si hoy no está como antes, «revertir cambiaría algo» y NO escribe", async () => {
    const ctx = makeCtx(router([{ enabled: true }]));
    const ack = await runRemediation(ctx, "job-1", item({ mode: "revert_dry_run" }));
    expect(ack.outcome).toBe("dryrun_would_apply");
    expect(ctx.priv.call.mock.calls.some(([r]: any) => r.method === "pmp.revert")).toBe(false);
  });

  it("revert_dry_run: si ya está como antes, lo dice", async () => {
    const ctx = makeCtx(router([{ enabled: false }]));
    expect((await runRemediation(ctx, "job-1", item({ mode: "revert_dry_run" }))).outcome).toBe("dryrun_already_compliant");
  });

  it("⭐ revert: llama a pmp.revert con el estado de antes y da `applied` sólo si al releer ES el de antes", async () => {
    const ctx = makeCtx(router([{ enabled: true }, { enabled: false }]));
    const ack = await runRemediation(ctx, "job-1", item());
    expect(ack.outcome).toBe("applied");
    expect(ack.ackMessage).toMatch(/^patch_remediate:applied;remediationId=11;/);
    const call = ctx.priv.call.mock.calls.find(([r]: any) => r.method === "pmp.revert")![0];
    expect(call.params).toMatchObject({ checkId, params: { stateBefore: { enabled: false } } });
  });

  it("revert que el PrivSvc da por bueno pero el estado no vuelve → failed post_state_mismatch", async () => {
    const ctx = makeCtx(router([{ enabled: true }, { enabled: true }]));
    const ack = await runRemediation(ctx, "job-1", item());
    expect(ack.outcome).toBe("failed");
    expect(ack.ackMessage).toMatch(/post_state_mismatch/);
  });

  it("revert con reinicio pendiente → applied_reboot_required", async () => {
    const ctx = makeCtx(router([{ enabled: true }, { enabled: false }], { revert: { ok: true, result: { exitCode: 0, requiresReboot: true } } }));
    expect((await runRemediation(ctx, "job-1", item())).outcome).toBe("applied_reboot_required");
  });

  it("un PrivSvc sin handler de revert → rejected (nunca reaplica el fix)", async () => {
    const ctx = makeCtx(router([{ enabled: true }], { revert: { ok: false, error: { code: "unsupported_check" } } }));
    const ack = await runRemediation(ctx, "job-1", item());
    expect(ack.outcome).toBe("rejected");
    expect(ctx.priv.call.mock.calls.some(([r]: any) => r.method === "pmp.remediate")).toBe(false);
  });

  it("sin stateBefore no hay revert", async () => {
    const ctx = makeCtx(router([{ enabled: true }]));
    const ack = await runRemediation(ctx, "job-1", item({ params: {} }));
    expect(ack.outcome).toBe("rejected");
    expect(ack.ackMessage).toMatch(/revert_without_state_before/);
  });

  it("stateMatchesBefore: clave a clave, listas sin importar el orden, queryError fuera", () => {
    expect(stateMatchesBefore({ a: 1, b: ["x", "y"], extra: 9 }, { a: 1, b: ["y", "x"] })).toBe(true);
    expect(stateMatchesBefore({ a: 2 }, { a: 1 })).toBe(false);
    expect(stateMatchesBefore({ a: 1 }, { a: 1, queryError: true })).toBe(true);
    // `raw` (salida literal del comando en macOS) no es estado.
    expect(stateMatchesBefore({ enabled: false, raw: "Firewall is disabled. (State = 0)\n" }, { enabled: false, raw: "Firewall is disabled. (State = 0)" })).toBe(true);
    expect(stateMatchesBefore({ a: null }, { a: null })).toBe(true);
    expect(stateMatchesBefore(null, { a: 1 })).toBe(false);
  });
});

describe("varios fixes en UN job", () => {
  const decode = (msg: string) => {
    const m = /items=([A-Za-z0-9_-]+)/.exec(msg)!;
    return JSON.parse(Buffer.from(m[1], "base64url").toString("utf8")) as string[];
  };

  it("⭐ un lock, en serie, y UN ACK con el de cada fix (su remediationId dentro)", async () => {
    const ctx = makeCtx(router([{ enabled: false }]));
    const ack = await runRemediation(ctx, "job-9", {
      items: [
        item({ remediationId: 21, mode: "dry_run", params: undefined }),
        item({ remediationId: 22, mode: "revert_dry_run" }),
      ],
    });
    expect(ack.ackMessage.startsWith("patch_remediate_batch:done;items=")).toBe(true);
    const items = decode(ack.ackMessage);
    expect(items).toHaveLength(2);
    expect(items[0]).toMatch(/^patch_remediate:dryrun_would_apply;remediationId=21;/);
    expect(items[1]).toMatch(/^patch_remediate:dryrun_already_compliant;remediationId=22;/);
    expect(ack.ackStatus).toBe(0);
  });

  it("con otra acción de PMP en curso, el lote entero se reintenta (ackStatus 1, ninguna fila tocada)", async () => {
    const ctx = makeCtx(router([{ enabled: false }]));
    ctx._patchInstallInProgress = true;
    const ack = await runRemediation(ctx, "job-9", { items: [item()] });
    expect(ack.ackStatus).toBe(1);
    expect(ack.ackMessage).toMatch(/^patch_remediate_batch:busy/);
  });

  it("un fix que falla no para a los demás; el lote sale con ackStatus 2", async () => {
    const ctx = makeCtx(router([{ enabled: true }, { enabled: true }, { enabled: true }]));
    const ack = await runRemediation(ctx, "job-9", { items: [item({ remediationId: 31 }), item({ remediationId: 32, mode: "revert_dry_run" })] });
    const items = decode(ack.ackMessage);
    expect(items[0]).toMatch(/patch_remediate:failed;remediationId=31/);
    expect(items[1]).toMatch(/patch_remediate:dryrun_would_apply;remediationId=32/);
    expect(ack.ackStatus).toBe(2);
  });

  it("si no cabe, se recorta lo forense (primero stateAfter), nunca el resultado", () => {
    const big = "A".repeat(20_000);
    const msgs = Array.from({ length: 60 }, (_, i) => `patch_remediate:applied;remediationId=${i + 1};stateBefore=${big};stateAfter=${big}`);
    const out = encodeBatchAck(msgs);
    const items = decode(out);
    expect(/items=([A-Za-z0-9_-]+)/.exec(out)![1].length).toBeLessThanOrEqual(BATCH_ITEMS_B64_MAX);
    expect(items).toHaveLength(60);
    expect(items.every((m) => /^patch_remediate:applied;remediationId=\d+/.test(m) && !m.includes("stateAfter="))).toBe(true);
  });

  it("el agente anuncia las dos capacidades", () => {
    expect(PMP_REMEDIATE_CAPABILITIES).toEqual(["pmp.remediate.batch", "pmp.remediate.revert"]);
    // El genérico de Linux sólo se anuncia en Linux.
    // pmp.patch_verify (ADR-0038 F1): la verificación post-cambio, en las tres.
    expect(pmpRemediateCapabilities("linux")).toEqual(["pmp.remediate.batch", "pmp.remediate.revert", "pmp.remediate.linux_config", "pmp.remediate.linux_config_v2", "pmp.remediate.linux_accepted_guard", "pmp.patch_verify"]);
    expect(pmpRemediateCapabilities("win32")).toEqual(["pmp.remediate.batch", "pmp.remediate.revert", "pmp.patch_verify"]);
    expect(pmpRemediateCapabilities("darwin")).toEqual(["pmp.remediate.batch", "pmp.remediate.revert", "pmp.remediate.macos_config", "pmp.patch_verify"]);
  });
});
