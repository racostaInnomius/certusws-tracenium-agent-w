// privsvc/macos/src/input-injection.ts
//
// RCP — inyección de teclado y ratón en macOS (`input.inject`).
//
// POR QUÉ EXISTE ESTE FICHERO
//
//   Hasta ahora el router de macOS no tenía ruta `input.inject`: el agente
//   mandaba la petición y no la atendía nadie. El operador pulsaba
//   "Controlling", la UI ocultaba su cursor para mostrar el remoto, y no
//   pasaba nada — un fallo silencioso, sin error por ningún lado.
//
//   La inyección la hace el helper, no este proceso, por dos motivos que ya
//   pagamos caros en las otras plataformas:
//
//     · CGEvent se entrega a la sesión de ventanas de quien lo publica, y el
//       privsvc es un LaunchDaemon sin sesión gráfica. Es el mismo error que
//       Windows arrastró durante meses con SendInput desde la Sesión 0.
//     · Accesibilidad es un permiso de TCC, y TCC lo ancla al proceso
//       responsable. Pedirlo desde aquí haría que el usuario viera a "node"
//       pidiendo controlar su equipo — justo lo que el disclaim del helper
//       corrigió para la captura.
//
// PROCESO DE VIDA LARGA
//
//   La captura lanza un proceso por fotograma. Para entrada eso sería
//   inviable: el operador genera decenas de eventos por segundo y cada
//   arranque cuesta launchctl + sudo + spawn. Aquí se mantiene UN helper por
//   sesión de control y se le escriben líneas.

import { spawn, ChildProcess } from "child_process";
import path from "path";
import fs from "fs";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";
import { activeConsoleUser, helperPath } from "./screen-capture";

// Cuánto esperamos la confirmación de un evento. Muy por debajo del
// presupuesto IPC del cliente — invariante que ya nos mordió cinco veces:
// job > cliente IPC > handler. Un evento de entrada que tarda más de esto no
// vale la pena: el operador ya movió el ratón a otro sitio.
const REPLY_TIMEOUT_MS = 2000;

type Helper = {
  proc: ChildProcess;
  uid: number;
  /** Resolvers en orden de llegada. El helper responde una línea por
   *  petición y en orden, así que una cola FIFO basta y evita inventar ids. */
  pending: Array<(line: string | null) => void>;
  buffer: string;
};

let helper: Helper | null = null;

function stopHelper(reason: string): void {
  if (!helper) return;
  logger.info("input_helper_stopped", { reason });
  // Cerrar stdin es la salida ordenada: el helper suelta lo que quedara
  // pulsado y sale por su cuenta. Ver injectReleaseAll() en input.swift —
  // dejar una tecla trabada en el equipo de otra persona es peor que no
  // haber controlado nunca.
  try { helper.proc.stdin?.end(); } catch { /* ya cerrado */ }
  try { helper.proc.kill("SIGTERM"); } catch { /* ya muerto */ }
  for (const resolve of helper.pending) resolve(null);
  helper = null;
}

/** Para el helper de entrada. Lo llama el cierre de la sesión de pantalla. */
export function stopInputHelper(): void {
  stopHelper("session_closed");
}

function startHelper(uid: number, name: string): Helper | null {
  const exe = helperPath();
  if (!fs.existsSync(exe)) return null;

  const proc = spawn(
    "/bin/launchctl",
    ["asuser", String(uid), "sudo", "-n", "-u", name, exe, "--input-serve"],
    { stdio: ["pipe", "pipe", "pipe"] }
  );

  const h: Helper = { proc, uid, pending: [], buffer: "" };

  proc.stdout?.on("data", (chunk: Buffer) => {
    h.buffer += chunk.toString("utf8");
    // Una línea = una respuesta. Se resuelven en orden de llegada.
    let idx: number;
    while ((idx = h.buffer.indexOf("\n")) >= 0) {
      const line = h.buffer.slice(0, idx);
      h.buffer = h.buffer.slice(idx + 1);
      const resolve = h.pending.shift();
      if (resolve) resolve(line);
    }
  });

  // stderr al log, y drenado SIEMPRE: una tubería que nadie lee se llena y
  // bloquea a quien escribe. En Windows ese mismo descuido dejó al helper
  // colgado a mitad de captura y lo vimos como un timeout.
  proc.stderr?.on("data", (chunk: Buffer) => {
    const text = chunk.toString("utf8").trim();
    if (text) logger.warn("input_helper_stderr", { text: text.slice(0, 400) });
  });

  proc.on("exit", (code) => {
    logger.info("input_helper_exited", { code });
    if (helper === h) stopHelper("helper_exited");
  });

  return h;
}

function send(h: Helper, payload: Record<string, unknown>): Promise<string | null> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (line: string | null) => {
      if (settled) return;
      settled = true;
      resolve(line);
    };

    h.pending.push(done);
    try {
      h.proc.stdin?.write(JSON.stringify(payload) + "\n");
    } catch {
      done(null);
      return;
    }
    setTimeout(() => done(null), REPLY_TIMEOUT_MS);
  });
}

/**
 * IPC entry-point de `input.inject`. Devuelve la misma forma que la ruta de
 * Windows para que el agente no tenga que distinguir plataformas.
 */
export async function handleInputInject(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const op = String(req.params?.op ?? "");
  if (!op) return fail(req.id, "input_unknown_op", "missing op");

  const user = await activeConsoleUser();
  if (!user) {
    return fail(
      req.id,
      "no_interactive_desktop",
      "No user is signed in to this Mac right now."
    );
  }

  // Si cambió el usuario de consola, el helper viejo apunta a una sesión que
  // ya no existe y sus eventos irían al vacío.
  if (helper && helper.uid !== user.uid) stopHelper("console_user_changed");
  if (!helper) {
    helper = startHelper(user.uid, user.name);
    if (!helper) {
      return fail(
        req.id,
        "screen_capture_helper_missing",
        "The Tracenium helper isn't installed on this device. Reinstall or upgrade the agent package."
      );
    }
  }

  const line = await send(helper, { ...(req.params || {}), op });
  if (line === null) {
    // Sin respuesta: el helper murió o se colgó. Lo tiramos para que el
    // siguiente evento arranque uno limpio, en vez de arrastrar una tubería
    // desincronizada en la que cada respuesta llegaría a la petición
    // equivocada.
    stopHelper("no_reply");
    return fail(req.id, "input_inject_error", "The input helper did not respond.");
  }

  let parsed: any;
  try {
    parsed = JSON.parse(line);
  } catch {
    return fail(req.id, "input_inject_error", "Malformed reply from the input helper.");
  }

  if (parsed?.ok === true) return success(req.id, { injected: true });

  return fail(
    req.id,
    String(parsed?.code || "input_inject_error"),
    String(parsed?.message || "input injection failed")
  );
}
