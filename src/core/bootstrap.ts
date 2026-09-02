// src/core/bootstrap.ts
import fs from "fs";
import path from "path";
import { agentDataDir } from "../bootstrap/paths";
import { ensureEnrolled } from "../bootstrap/enroll";
import { EnrollmentStore } from "../bootstrap/enrollment-store";
import { AgentContext } from "./agent-context";
import { config } from "../bootstrap/config";
import { createPrivSvcClient } from "../priv";
import { maybeRenewClientCertificate } from "../bootstrap/cert-renewal";
import { PolicyStore } from "./policy-store";
import { PolicyRuntime } from "./policy-runtime";
import { PluginManager } from "./plugin-manager";
import { logger } from "../bootstrap/logger";
import { TrayStatusStore } from "../status/tray-status-store";
import { outbox } from "../queue/sqlite-outbox";
import { loadUpdateState } from "../update/update-state";
import { decideSourceReport, sourceReportPayload } from "../update/update-source-report";

export async function bootstrapContext(): Promise<AgentContext> {

  const store = new EnrollmentStore();
  let enrollment = await ensureEnrolled();
  const priv = createPrivSvcClient();

  try {
    enrollment = await maybeRenewClientCertificate({
      enrollment,
      store,
      priv,
      logger
    });
  } catch (err: any) {
    logger.warn("[cert-renewal] renewal failed; continuing with existing certificate", err?.message || err);
  }

  const policy = new PolicyStore();
  await policy.load();

  const policyRuntime = new PolicyRuntime(policy, logger);
  await policyRuntime.init();

  const pluginManager = new PluginManager();
  const trayStatus = new TrayStatusStore();

  const agent = {
    version: config.agentVersion,
    platform: process.platform === "win32" ? "windows" : process.platform
  };

  const ctx: AgentContext = {
    config,
    agent,
    enrollment,
    store,
    priv,
    policy,
    policyRuntime,
    plugins: pluginManager,
    trayStatus,
    logger
  };

  await pluginManager.init(ctx);

  reportUpdateSource(agent.version);

  return ctx;
}

/**
 * Tell the control plane who served the installer for the version now running.
 *
 * The periodic update check has no job and no ACK behind it, so its `servedBy`
 * was computed and then dropped — leaving the one mechanism that moves the
 * fleet on its own as the one we could not measure. The tier is on disk, so the
 * report waits for the boot AFTER the install rather than racing the installer
 * that is about to replace this process.
 *
 * Enqueued on the outbox, not written to the stream: the outbox already gives
 * this durability and retry across reconnects, and it dedupes identical
 * payloads that are still pending.
 *
 * ⚠️ NOT CLEARED AFTERWARDS, DELIBERATELY.
 *
 * The first version of this wiped `lastServedBy` as soon as it enqueued, which
 * turned one lost delivery into permanent data loss — and the window where that
 * happens is exactly a rollout, when the agent can boot and report before the
 * backend that knows how to store it is live. That is not hypothetical: the
 * first fleet-wide run of this reported into a control plane that had no table
 * yet, and the state was already gone by the time it did.
 *
 * Re-reporting is free instead: the backend upserts on
 * (tenant, device, version), so a repeat is the same row written twice, and the
 * version guard stops it as soon as the endpoint moves on. Idempotent
 * reconciliation over fire-and-forget — the same reason the DP warmer states a
 * desired world every tick rather than firing a command once.
 *
 * Best effort throughout. This is telemetry; an agent that cannot report where
 * its bytes came from must still finish starting up.
 */
/**
 * Lee y reporta el resultado del ÚLTIMO intento de actualización (Windows).
 *
 * El shim que lanza msiexec escribe su código de salida en un fichero del
 * directorio de datos. Hasta ahora ese código solo existía en el LastResult de
 * Task Scheduler: nadie lo mira, no viaja al control plane, y un update que
 * falló era indistinguible de uno que nunca llegó a programarse.
 *
 * Eso costó días de un equipo atascado en 1.1.56 reintentando 1.1.57 sin que
 * ningún log dijera por qué. Se lee UNA vez al arrancar —que es justo después
 * de que el update haya ocurrido o fallado— y se consume: dejarlo haría que se
 * reportara el mismo fallo en cada reinicio.
 */
function reportLastUpdateOutcome(): void {
  if (process.platform !== "win32") return;
  const file = path.join(agentDataDir(), "update-result.json");
  let raw: string;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch {
    return; // no hubo intento previo: el caso normal
  }
  try {
    fs.unlinkSync(file);
  } catch {
    /* si no se puede borrar se reportará dos veces; es preferible a perderlo */
  }

  try {
    const r = JSON.parse(raw);
    const exitCode = Number(r?.exitCode);
    if (exitCode === 0) {
      logger.info("[update] la instalación anterior terminó bien", { msi: r?.msi });
    } else {
      // warn, no info: un msiexec que falla deja al equipo en la versión
      // vieja, y eso tiene que verse. 1618 = otra instalación en curso;
      // 1603 = fallo genérico, casi siempre con la causa en el /l*v.
      logger.warn("[update] la instalación anterior FALLÓ", {
        msi: r?.msi,
        exitCode,
        atLocal: r?.atLocal,
        hint: `revisa update-msi-${r?.msi}.log en el directorio de datos`
      });
    }
  } catch {
    logger.warn("[update] resultado de instalación ilegible", { raw: raw.slice(0, 200) });
  }
}

function reportUpdateSource(runningVersion: string): void {
  try {
    reportLastUpdateOutcome();
    const report = decideSourceReport(loadUpdateState(), runningVersion);
    if (!report) return;

    outbox.enqueue({ type: "FACTS_SNAPSHOT", payload: sourceReportPayload(report) });
    logger.info("[update] reported install source", report);
  } catch (err: any) {
    logger.warn("[update] could not report install source", err?.message || err);
  }
}
