// privsvc/linux/src/rcp-pty.ts
//
// `rcp.pty.open` / `rcp.pty.close` — sesión de shell remoto con privilegios en
// Linux.
//
// El QUÉ y el POR QUÉ largos viven en privsvc/linux/helpers/rcp-pty-helper.js.
// Resumen: en Linux el AgentCore corre sin privilegios (correcto), pero eso
// dejaba el remote shell inservible para soporte justo en la plataforma donde
// es el único acceso — un servidor headless no tiene otra vía. Windows lo da
// como LocalSystem y macOS como root; Linux era la desalineada.
//
// Este módulo NO transporta los bytes del pty. Solo lanza el helper y devuelve
// la ruta de su socket: el tráfico interactivo va por ahí, fuera del IPC. Ese
// canal es JSON-por-líneas y en Windows atiende una petición a la vez, así que
// una sesión de shell lo monopolizaría y mataría heartbeats e inventario
// mientras durase.

import { spawn, ChildProcess } from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";
import { PrivSvcRequest, PrivSvcResponse, success, fail } from "./protocol";
import { logger } from "./logger";

/** Donde systemd crea el RuntimeDirectory de privsvc: 0750 root:tracenium. */
const RUNTIME_DIR = "/run/tracenium";

/** Cuánto damos al helper para anunciar READY antes de considerarlo fallido. */
const HELPER_READY_TIMEOUT_MS = 5_000;

/**
 * Un helper por sesión, para poder matarlo en `rcp.pty.close`.
 *
 * Si privsvc se reinicia a media sesión el shell muere con él: los hijos son
 * de este proceso a propósito. Un shell de root que sobreviviera al broker que
 * lo autorizó es exactamente lo que no queremos que quede suelto.
 */
const sessions = new Map<string, ChildProcess>();

function helperPath(): string {
  const override = process.env.TRACENIUM_RCP_PTY_HELPER;
  if (override) return override;
  return path.resolve(__dirname, "tracenium-rcp-pty");
}

/**
 * Node con el que ejecutar el helper.
 *
 * `process.execPath` es el propio node que corre privsvc — el mismo binario
 * que despliega el paquete. Resolverlo así evita depender de que haya un node
 * en el PATH del sistema, que en un servidor mínimo puede no existir.
 */
function nodePath(): string {
  return process.execPath;
}

export async function handleOpen(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const sessionId = String(req.params?.sessionId || "").trim();
  if (!sessionId || !/^[A-Za-z0-9._:-]{1,128}$/.test(sessionId)) {
    return fail(req.id, "bad_request", "sessionId inválido");
  }
  if (sessions.has(sessionId)) {
    return fail(req.id, "already_open", "esa sesión ya tiene un pty abierto");
  }

  const cols = Number(req.params?.cols) || 80;
  const rows = Number(req.params?.rows) || 24;

  // El nombre del socket NO usa el sessionId: ese identificador viaja por la
  // red y podría ser adivinable. Un token aleatorio hace que conocer la sesión
  // no diga nada sobre la ruta del socket.
  const token = crypto.randomBytes(16).toString("hex");
  const socketPath = path.join(RUNTIME_DIR, `rcp-${token}.sock`);

  // gid del proceso = tracenium (la unit declara Group=tracenium justo para
  // esto). El helper hace chown root:<gid> sobre el socket, de modo que solo
  // el agente pueda conectarse.
  const gid = typeof process.getgid === "function" ? process.getgid() : NaN;

  const child = spawn(
    nodePath(),
    [
      helperPath(),
      "--socket", socketPath,
      "--cols", String(cols),
      "--rows", String(rows),
      "--gid", String(gid),
    ],
    { stdio: ["ignore", "pipe", "pipe"] }
  );

  const ready = await new Promise<{ ok: true } | { ok: false; error: string }>((resolve) => {
    let settled = false;
    const done = (r: { ok: true } | { ok: false; error: string }) => {
      if (settled) return;
      settled = true;
      resolve(r);
    };

    let stderr = "";
    child.stdout?.on("data", (d) => {
      if (String(d).includes("READY")) done({ ok: true });
    });
    child.stderr?.on("data", (d) => {
      stderr += String(d);
      if (stderr.length > 4096) stderr = stderr.slice(-4096);
    });
    // 'error' cubre ENOENT/EACCES al ejecutar el helper. Sin listener, Node lo
    // trata como excepción no capturada y se lleva al broker por delante —
    // la misma regresión que costó 364 reinicios en agent-install.
    child.on("error", (err: any) => done({ ok: false, error: err?.message || String(err) }));
    child.on("exit", (code) =>
      done({ ok: false, error: `el helper salió con ${code}: ${stderr.trim() || "sin stderr"}` })
    );

    setTimeout(
      () => done({ ok: false, error: `el helper no anunció READY en ${HELPER_READY_TIMEOUT_MS}ms` }),
      HELPER_READY_TIMEOUT_MS
    ).unref?.();
  });

  if (!ready.ok) {
    try { child.kill(); } catch { /* ya muerto */ }
    logger.error("rcp_pty_open_failed", { sessionId, error: ready.error });
    return fail(req.id, "pty_open_failed", ready.error);
  }

  sessions.set(sessionId, child);
  child.on("exit", () => sessions.delete(sessionId));

  // Auditoría deliberadamente ruidosa: esto concede una shell de ROOT. Debe
  // quedar rastro local aunque el control plane pierda la transcripción.
  logger.info("rcp_pty_opened", {
    sessionId,
    pid: child.pid,
    tenantId: req.meta?.tenantId,
    deviceId: req.meta?.deviceId,
    privileged: true,
  });

  return success(req.id, { socketPath });
}

export async function handleClose(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const sessionId = String(req.params?.sessionId || "").trim();
  const child = sessions.get(sessionId);
  if (!child) {
    // No es un error: el helper se recoge solo cuando el agente cierra el
    // socket, así que llegar tarde es el caso normal.
    return success(req.id, { closed: false, reason: "no_session" });
  }
  sessions.delete(sessionId);
  try { child.kill(); } catch { /* ya muerto */ }
  logger.info("rcp_pty_closed", { sessionId, pid: child.pid });
  return success(req.id, { closed: true });
}
