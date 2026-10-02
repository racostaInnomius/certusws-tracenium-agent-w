// test/plugins/pmp-redispatch-replay.test.ts
//
// ⚠️ Auditoría PMP 1-oct-2026. Si el ACK de un patch_install se pierde, el
// backend reenvía el MISMO job al vencer su plazo. Ejecutarlo otra vez daba un
// falso fallo (Windows ya no ofrece lo recién instalado → «no_matching_patches»)
// y, con rebootIfRequired, otro reinicio.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

import {
  AGENT_RESTARTED_ERROR,
  INTERRUPTED_BY_RESTART_MESSAGE,
  loadPmpState,
  reconcileStalePmpState,
  rememberSuccessAck,
  replayForRedispatch,
  updatePmpState,
} from "../../src/plugins/pmp/state";

let dir: string;
const prevEnv = process.env.TRACENIUM_STATE_DIR;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "tracenium-pmp-replay-"));
  process.env.TRACENIUM_STATE_DIR = dir;
});

afterEach(() => {
  if (prevEnv === undefined) delete process.env.TRACENIUM_STATE_DIR;
  else process.env.TRACENIUM_STATE_DIR = prevEnv;
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("replayForRedispatch", () => {
  it("un job nuevo se ejecuta", () => {
    expect(replayForRedispatch("job-1")).toBeNull();
  });

  it("🔴 el mismo job, ya acabado BIEN aquí → el mismo ACK de éxito, sin reinstalar", () => {
    const msg = "patch_install success; installed=2; failed=0; rebootRequired=true; rebootScheduled=true; rebootInSec=60";
    rememberSuccessAck("job-1", msg);
    expect(replayForRedispatch("job-1")).toEqual({ status: 0, message: msg });
    // Y sigue ahí si ESE ACK también se pierde.
    expect(replayForRedispatch("job-1")).toEqual({ status: 0, message: msg });
    expect(replayForRedispatch("job-2")).toBeNull();
  });

  it("🔴 el mismo job, cortado por un reinicio del agente → «interrupted», una sola vez", () => {
    updatePmpState({ status: "in_progress", jobId: "job-7", mode: "install" });
    reconcileStalePmpState();
    expect(loadPmpState()).toMatchObject({ jobId: "job-7", lastError: AGENT_RESTARTED_ERROR });

    expect(replayForRedispatch("job-7")).toEqual({ status: 2, message: INTERRUPTED_BY_RESTART_MESSAGE });
    // Un reintento explícito después vuelve a ejecutar.
    expect(replayForRedispatch("job-7")).toBeNull();
  });

  it("un job que FALLÓ aquí se vuelve a ejecutar si llega otra vez (reintento)", () => {
    updatePmpState({ status: "failed", jobId: "job-9", lastError: "patch_install failed" });
    expect(replayForRedispatch("job-9")).toBeNull();
  });

  it("la firma coincide con la que reconoce el control plane (install-interrupted.ts)", () => {
    expect(INTERRUPTED_BY_RESTART_MESSAGE).toMatch(/^patch_install interrupted: agent_restarted\b/);
  });
});
