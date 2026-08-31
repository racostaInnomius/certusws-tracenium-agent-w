// privsvc/linux/src/remote-indicator.ts
//
// Indicador de sesión de control remoto para Linux (ADR-0012, paso 1).
//
// ── Por qué esto existe y no una bandeja ─────────────────────────────
//
//   Windows tiene bandeja (.NET) y macOS app de estado (Swift), y en ambos el
//   indicador es una pieza más de algo que ya vivía en la sesión del usuario.
//   En Linux el paquete instala DOS SERVICIOS DE SISTEMA y nada más: no hay
//   ningún proceso nuestro en la sesión gráfica.
//
//   Construir una bandeja Linux entera —GTK, autostart XDG, empaquetado,
//   detección de sesión— para colgar de ella un solo aviso sería semanas de
//   trabajo y una superficie de despliegue nueva. En vez de eso, PrivSvc lanza
//   el aviso dentro de la sesión gráfica con la MISMA maniobra que ya usa para
//   capturar (ver x11-session.ts), y lo mantiene vivo lo que dure la sesión.
//
// ── La puerta: por qué se espera la confirmación ─────────────────────
//
//   `show()` no vale con lanzar el proceso: espera a que el helper diga
//   {"ok":true}, que solo imprime DESPUÉS de mapear la ventana. Si no llega
//   esa línea, `show()` falla, y quien llama (handleScreenCapture) rechaza la
//   sesión.
//
//   Es el punto entero del ADR: si no podemos decirle a la persona que la
//   están mirando, no la miramos. Lanzar y confiar dejaría el caso peor —
//   pantalla compartida y aviso que nunca apareció— indistinguible del bueno.
//
// ── Alcance real ─────────────────────────────────────────────────────
//
//   X11 solamente, igual que la captura. En Wayland la captura ya falla antes
//   con `wayland_unsupported`, así que esta puerta no cambia nada allí.

import { spawn, type ChildProcess } from "child_process";
import path from "path";
import fs from "fs";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";
import {
  activeGraphicalSession,
  buildRunuserArgs,
  homeForUser,
  resolveXauthority
} from "./x11-session";

/**
 * Cuánto se espera al helper para que confirme que la ventana está en
 * pantalla. Generoso: abrir el display y cargar una fuente en una máquina
 * cargada puede tardar. Pero acotado — sin tope, un helper colgado dejaría la
 * sesión de soporte esperando para siempre sin decir por qué.
 */
const READY_TIMEOUT_MS = 4000;

type Live = { child: ChildProcess; sessionId: string };

/**
 * Un único indicador vivo. Si llega un `show` con otra sesión, el anterior se
 * retira primero: dos bandas superpuestas diciendo cosas distintas es peor que
 * una, y no hay caso legítimo de dos sesiones de pantalla a la vez en el mismo
 * escritorio.
 */
let live: Live | null = null;

function helperPath(): string {
  const override = process.env.TRACENIUM_INDICATOR_HELPER;
  if (override && override.trim()) return override.trim();
  return path.resolve(__dirname, "tracenium-indicator");
}

/** Retira el indicador vivo, si lo hay. Idempotente y no lanza. */
export function hideIndicator(): void {
  const cur = live;
  live = null;
  if (!cur) return;
  try {
    // Cerrar stdin es la vía limpia: el helper sale al ver EOF. El kill es el
    // respaldo por si estuviera atascado antes del bucle de eventos.
    cur.child.stdin?.end();
    cur.child.kill("SIGTERM");
  } catch {
    /* ya murió */
  }
}

export type ShowResult = { ok: true } | { ok: false; code: string; message: string };

/**
 * Enciende el indicador y NO vuelve hasta saber si está en pantalla.
 */
export async function showIndicator(args: {
  sessionId: string;
  text: string;
  button: string;
}): Promise<ShowResult> {
  hideIndicator();

  const helper = helperPath();
  if (!fs.existsSync(helper)) {
    logger.error("indicator_helper_missing", { helper });
    return {
      ok: false,
      code: "indicator_helper_missing",
      message: "Remote session indicator helper not installed"
    };
  }

  const session = await activeGraphicalSession(() =>
    logger.warn("indicator_loginctl_unavailable")
  );
  if (!session) {
    return {
      ok: false,
      code: "no_interactive_desktop",
      message: "No active graphical session to show the remote session indicator on"
    };
  }
  if (session.type === "wayland") {
    return {
      ok: false,
      code: "wayland_unsupported",
      message: "Wayland sessions are not supported for screen sharing in this release"
    };
  }

  const home = await homeForUser(session.user);
  const xauthority = await resolveXauthority(session, home);

  // ⚠️ HOME y USER van EXPLÍCITOS, no se dejan al criterio de runuser.
  //
  // El helper escribe la petición de corte en $HOME/.config/tracenium/. Si HOME
  // fuera el de root —porque runuser preservara el entorno, o porque la
  // distribución tenga otro criterio— el fichero acabaría en /root/.config,
  // donde el agente no lo busca. El botón "detener" no daría error: no haría
  // NADA. Y un control de privacidad que falla en silencio es peor que no
  // tenerlo, porque la persona cree que cortó.
  //
  // El home ya lo resolvimos arriba con getent para buscar la cookie X, así
  // que no cuesta nada pasarlo y deja de ser una suposición.
  const extraEnv: string[] = [`USER=${session.user}`];
  if (home) extraEnv.push(`HOME=${home}`);

  const argv = buildRunuserArgs(
    session,
    xauthority,
    [
      helper,
      "--session-id", args.sessionId,
      "--text", args.text,
      "--button", args.button
    ],
    extraEnv
  );

  let child: ChildProcess;
  try {
    // stdin en 'pipe' NO es decorativo: es la correa. El helper sale al ver
    // EOF, así que si PrivSvc muere el aviso se va con él en vez de quedarse
    // en la pantalla de alguien diciendo que le miran cuando ya nadie mira.
    child = spawn("runuser", argv, { stdio: ["pipe", "pipe", "pipe"] });
  } catch (err: any) {
    return {
      ok: false,
      code: "indicator_spawn_failed",
      message: err?.message || String(err)
    };
  }

  const ready = await waitForReady(child);
  if (!ready.ok) {
    try {
      child.kill("SIGKILL");
    } catch {
      /* ya murió */
    }
    return ready;
  }

  live = { child, sessionId: args.sessionId };

  // Si el helper muere por su cuenta —X se reinicia, el usuario cierra
  // sesión— hay que soltar la referencia. Que se quede apuntando a un proceso
  // muerto haría que el siguiente `show` creyera que ya hay uno vivo.
  child.once("exit", (code) => {
    if (live?.child === child) {
      logger.warn("indicator_exited_unexpectedly", { code, sessionId: args.sessionId });
      live = null;
    }
  });

  return { ok: true };
}

/**
 * Espera la primera línea del helper.
 *
 * Se lee stdout hasta el primer salto de línea. El helper imprime su
 * confirmación DESPUÉS de mapear la ventana, así que esa línea es lo más
 * cerca que se puede estar de "el aviso está delante de la persona" sin
 * volver a leer la pantalla.
 */
function waitForReady(child: ChildProcess): Promise<ShowResult> {
  return new Promise((resolve) => {
    let out = "";
    let settled = false;
    let stderr = "";

    const done = (r: ShowResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(r);
    };

    const timer = setTimeout(() => {
      done({
        ok: false,
        code: "indicator_timeout",
        message: "Indicator helper did not confirm it was on screen in time"
      });
    }, READY_TIMEOUT_MS);

    child.stdout?.on("data", (buf) => {
      out += String(buf);
      const nl = out.indexOf("\n");
      if (nl < 0) return;

      const line = out.slice(0, nl).trim();
      let parsed: any = null;
      try {
        parsed = JSON.parse(line);
      } catch {
        done({
          ok: false,
          code: "indicator_bad_output",
          message: `Indicator helper output was not JSON: ${line.slice(0, 120)}`
        });
        return;
      }

      if (parsed?.ok === true) {
        done({ ok: true });
      } else {
        done({
          ok: false,
          code: String(parsed?.code || "indicator_failed"),
          message: String(parsed?.message || "Indicator helper failed")
        });
      }
    });

    // El stderr se DRENA aunque no se use. Un hijo que llena su tubería de
    // stderr y nadie la vacía se queda bloqueado escribiendo, y el síntoma es
    // un timeout que no explica nada. Ya nos pasó con el helper de captura de
    // Windows.
    child.stderr?.on("data", (buf) => {
      stderr += String(buf);
      if (stderr.length > 8192) stderr = stderr.slice(-8192);
    });

    child.once("error", (err: any) => {
      done({
        ok: false,
        code: "indicator_spawn_failed",
        message: err?.message || String(err)
      });
    });

    child.once("exit", (code) => {
      done({
        ok: false,
        code: "indicator_exited",
        message:
          `Indicator helper exited with code ${code} before confirming` +
          (stderr.trim() ? `: ${stderr.trim().slice(0, 200)}` : "")
      });
    });
  });
}

export async function handleIndicatorShow(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const sessionId = String(req.params?.sessionId || "");
  if (!sessionId) {
    return fail(req.id, "invalid_params", "sessionId is required");
  }

  const r = await showIndicator({
    sessionId,
    text: String(req.params?.text || "A remote operator is viewing this screen"),
    button: String(req.params?.button || "Stop sharing")
  });

  if (!r.ok) {
    logger.warn("indicator_show_failed", { code: r.code, sessionId });
    return fail(req.id, r.code, r.message);
  }

  logger.info("indicator_shown", { sessionId });
  return success(req.id, { ok: true });
}

export async function handleIndicatorHide(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  hideIndicator();
  return success(req.id, { ok: true });
}
