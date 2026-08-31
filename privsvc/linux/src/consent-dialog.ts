// privsvc/linux/src/consent-dialog.ts
//
// Diálogo de consentimiento para las dos puertas de ADR-0012 (Linux/X11).
//
// Mismo problema y misma solución que el indicador: Linux no tiene nada
// nuestro en la sesión gráfica, así que PrivSvc lanza el diálogo dentro de
// ella con `runuser` y espera la respuesta. Reutiliza el binario
// `tracenium-indicator` en su modo `--consent`, que comparte la conexión X, la
// fuente y los colores con la banda.
//
// ── Por qué el timeout va DOBLE ──────────────────────────────────────
//
//   El helper tiene su propio plazo y devuelve "timeout" por su cuenta. Aquí
//   hay otro, un poco más largo, que mata el proceso.
//
//   No es redundancia por gusto: el helper puede quedarse colgado ANTES de
//   llegar a su bucle —X que no responde, fuente que no carga, el proceso
//   parado por el planificador—, y en ese caso nadie contestaría nunca. Sin el
//   plazo de fuera, la sesión de soporte se quedaría esperando para siempre a
//   una persona que ya dijo que no, o que ni siquiera vio el diálogo.
//
// ── Por qué "cualquier cosa rara" es denegar ─────────────────────────
//
//   Salida ilegible, proceso muerto, spawn fallido: todo cuenta como
//   negativa. Un diálogo que no funcionó no puede convertirse en un permiso
//   concedido; ese es el único fallo de este módulo que sería grave.

import { spawn } from "child_process";
import path from "path";
import fs from "fs";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { success } from "./protocol";
import { logger } from "./logger";
import {
  activeGraphicalSession,
  buildRunuserArgs,
  homeForUser,
  resolveXauthority
} from "./x11-session";

export type Decision = "approved" | "denied" | "timeout";

/** Margen sobre el plazo del helper antes de matarlo desde fuera. */
const KILL_GRACE_MS = 10_000;

function helperPath(): string {
  const override = process.env.TRACENIUM_INDICATOR_HELPER;
  if (override && override.trim()) return override.trim();
  return path.resolve(__dirname, "tracenium-indicator");
}

/**
 * Interpreta la línea del helper.
 *
 * Pura y exportada: es donde se decide si alguien puede usar el equipo de otra
 * persona, y merece tests que no dependan de lanzar procesos.
 */
export function parseDecision(line: string): Decision {
  let parsed: any = null;
  try {
    parsed = JSON.parse(line);
  } catch {
    return "denied";
  }
  const d = parsed?.decision;
  if (d === "approved" || d === "denied" || d === "timeout") return d;
  // Incluye el caso {"ok":false,...}: el helper no pudo preguntar, así que no
  // hay permiso que conceder.
  return "denied";
}

export async function handleConsentRequest(
  req: PrivSvcRequest
): Promise<PrivSvcResponse> {
  const text = String(req.params?.text || "A remote operator is requesting access.");
  const allow = String(req.params?.allow || "Allow");
  const deny = String(req.params?.deny || "Don't allow");
  let timeoutSeconds = Number(req.params?.timeoutSeconds ?? 60);
  if (!Number.isFinite(timeoutSeconds) || timeoutSeconds < 5) timeoutSeconds = 60;

  const helper = helperPath();
  if (!fs.existsSync(helper)) {
    logger.error("consent_helper_missing", { helper });
    return success(req.id, { ok: true, decision: "denied" as Decision });
  }

  const session = await activeGraphicalSession(() =>
    logger.warn("consent_loginctl_unavailable")
  );
  if (!session || session.type === "wayland") {
    // Sin escritorio donde preguntar no hay a quién preguntar. Denegar es lo
    // correcto: la alternativa sería conceder acceso al equipo de alguien
    // basándose en que no pudimos localizarle.
    logger.warn("consent_no_desktop", { type: session?.type || "none" });
    return success(req.id, { ok: true, decision: "denied" as Decision });
  }

  const home = await homeForUser(session.user);
  const xauthority = await resolveXauthority(session, home);
  const extraEnv = [`USER=${session.user}`];
  if (home) extraEnv.push(`HOME=${home}`);

  const argv = buildRunuserArgs(
    session,
    xauthority,
    [
      helper, "--consent",
      "--text", text,
      "--allow", allow,
      "--deny", deny,
      "--timeout", String(Math.round(timeoutSeconds))
    ],
    extraEnv
  );

  const decision = await new Promise<Decision>((resolve) => {
    let out = "";
    let settled = false;
    const done = (d: Decision) => {
      if (settled) return;
      settled = true;
      clearTimeout(killer);
      resolve(d);
    };

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn("runuser", argv, { stdio: ["ignore", "pipe", "pipe"] });
    } catch (err: any) {
      logger.warn("consent_spawn_failed", { err: err?.message });
      resolve("denied");
      return;
    }

    const killer = setTimeout(() => {
      logger.warn("consent_helper_hung", { timeoutSeconds });
      try {
        child.kill("SIGKILL");
      } catch {
        /* ya murió */
      }
      done("timeout");
    }, timeoutSeconds * 1000 + KILL_GRACE_MS);

    child.stdout?.on("data", (b) => {
      out += String(b);
      const nl = out.indexOf("\n");
      if (nl >= 0) done(parseDecision(out.slice(0, nl).trim()));
    });
    // Drenar stderr aunque no se use: un hijo que llena su tubería se queda
    // bloqueado escribiendo, y el síntoma sería un diálogo que nunca responde.
    child.stderr?.on("data", () => {});
    child.once("error", (err: any) => {
      logger.warn("consent_child_error", { err: err?.message });
      done("denied");
    });
    child.once("exit", () => done(parseDecision(out.split("\n")[0]?.trim() || "")));
  });

  logger.info("consent_decision", { decision });
  return success(req.id, { ok: true, decision });
}
