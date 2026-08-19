#!/usr/bin/env node
//
// tracenium-rcp-pty — helper de sesión de shell remoto para Linux.
//
// POR QUÉ EXISTE
// ----------------------------------------------------------------------------
// En Linux el AgentCore corre como `User=tracenium`: uid sin privilegios, sin
// sudo, con /usr/sbin/nologin y un solo grupo. Eso está BIEN —el resto de
// operaciones privilegiadas van por IPC a privsvc— pero el pty del remote
// shell nunca se enrutó por ahí: `src/plugins/rcp/pty-session.ts` hace
// `nodePty.spawn()` local, así que en Linux el operador recibía un bash que no
// podía reiniciar un servicio, leer /var/log/syslog ni listar /root.
//
// Medido en SRVOC-MainAgent (2026-08-19):
//   systemctl restart ssh → denegado    cat /var/log/syslog → denegado
//   ls /root              → denegado    apt-get -s install  → permitido
//
// Y es justo la plataforma donde el shell más importa, porque un servidor
// headless no tiene otra vía de acceso. En Windows el AgentCore es LocalSystem
// y en macOS es root (LaunchDaemon), así que ahí el shell ya sale con todo:
// Linux era la única desalineada, y la peor para estarlo.
//
// POR QUÉ UN HELPER Y NO EL IPC
// ----------------------------------------------------------------------------
// La alternativa evidente era pasar los bytes del pty por el IPC que ya existe.
// Se descartó a propósito: ese canal es JSON por líneas y en Windows atiende
// UNA petición a la vez (el "carril serial" que ya nos costó cinco incidentes).
// Una sesión interactiva lo monopolizaría mientras dure, matando heartbeats,
// inventario y compliance. Aquí el IPC solo transporta el `open` y el `close`
// —dos mensajes— y todo el tráfico chatty va por un socket dedicado.
//
// Además privsvc se empaqueta con esbuild SIN módulos nativos, así que no
// puede cargar node-pty por sí mismo. Un helper aparte es la única forma de
// tener un pty del lado privilegiado, y ya hay precedente: tracenium-screencap
// vive en este mismo directorio y se resuelve igual.
//
// CONTRATO DEL SOCKET
// ----------------------------------------------------------------------------
// Se habla el MISMO protocolo JSON-por-líneas que el navegador, para que el
// agente sea un proxy casi transparente en vez de un traductor:
//
//   agente → helper : {"type":"stdin","data":"..."}
//                     {"type":"resize","cols":N,"rows":M}
//                     {"type":"close"}
//   helper → agente : {"type":"stdout","data":"..."}
//                     {"type":"exit","code":N}
//
// Una línea JSON nunca contiene un salto de línea crudo (JSON.stringify escapa
// \n como \\n), así que delimitar por \n sobre un stream es seguro.
//
// SUPERFICIE DE SEGURIDAD
// ----------------------------------------------------------------------------
// Este socket ES un shell de root. Lo que lo contiene:
//   * vive en /run/tracenium, que systemd crea 0750 root:tracenium — ningún
//     otro usuario del sistema puede siquiera atravesar el directorio;
//   * el fichero va 0660 root:tracenium;
//   * el nombre lleva un token aleatorio, no el sessionId (que viaja por la
//     red y es adivinable);
//   * acepta UNA sola conexión y deja de escuchar;
//   * si nadie conecta en ACCEPT_TIMEOUT_MS, se va solo sin dejar nada.
//
// Las autorizaciones de más arriba (RBAC ADMIN/OWNER, consentimiento del
// endpoint, transcripción auditada) las aplica el control plane antes de que
// el agente pida siquiera el `open`.

"use strict";

const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");

/** Si el agente no conecta en este plazo, la sesión no llegó: recogemos. */
const ACCEPT_TIMEOUT_MS = 15_000;

/**
 * node-pty es nativo y solo está desplegado bajo el árbol del agente
 * (/usr/lib/tracenium/agent/node_modules). Se resuelve relativo a __dirname
 * para que funcione igual instalado y en desarrollo.
 */
function loadNodePty() {
  const candidates = [
    path.resolve(__dirname, "../agent/node_modules/node-pty"),
    path.resolve(__dirname, "../../agent/node_modules/node-pty"),
    "node-pty",
  ];
  for (const c of candidates) {
    try {
      return require(c);
    } catch {
      /* siguiente candidato */
    }
  }
  throw new Error("node-pty no encontrado: " + candidates.join(", "));
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    const k = String(argv[i] || "").replace(/^--/, "");
    if (k) out[k] = argv[i + 1];
  }
  return out;
}

/**
 * El shell de un shell de soporte en Linux.
 *
 * No se consulta $SHELL: privsvc es un demonio de systemd y no tiene entorno
 * de login, así que siempre valdría undefined y solo añadiría una vía por la
 * que el entorno del servicio decide qué se ejecuta como root.
 */
function pickShell() {
  for (const s of ["/bin/bash", "/usr/bin/bash", "/bin/sh"]) {
    if (fs.existsSync(s)) return s;
  }
  return "/bin/sh";
}

/**
 * Entorno del shell del operador.
 *
 * Espeja redactedEnv() del lado del agente: nada que parezca credencial de
 * servicio. El operador puede inspeccionar el entorno —los auditores lo
 * hacen— pero no sacar de ahí nuestros secretos.
 */
function shellEnv() {
  const blocked = /TOKEN|SECRET|API_KEY|PASSWORD|PRIVSVC|TRACENIUM_/i;
  const out = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined || blocked.test(k)) continue;
    out[k] = v;
  }
  out.TERM = out.TERM || "xterm-color";
  // privsvc arranca sin un HOME util, y bash sin HOME se comporta raro: sin
  // historial, sin ~/.bashrc y con el prompt degradado. No se fija "/root" a
  // pelo porque no es universal —hay sistemas donde root vive en otro sitio, y
  // en macOS ni siquiera existe—; se pregunta al sistema y se cae hacia atras.
  out.HOME = homeDir();
  out.TRACENIUM_REMOTE_SESSION = "1";
  return out;
}

/**
 * El HOME del usuario que corre este helper (root en produccion).
 *
 * Importa que exista de verdad: node-pty recibe este valor como `cwd`, y un
 * cwd inexistente hace fallar el spawn entero — el shell no llegaria a
 * arrancar y el operador veria una sesion que se cierra sola.
 */
function homeDir() {
  const candidates = [];
  try {
    const h = os.userInfo().homedir;
    if (h) candidates.push(h);
  } catch {
    /* userInfo puede fallar si el uid no esta en passwd */
  }
  candidates.push("/root", "/tmp");
  for (const c of candidates) {
    try {
      if (fs.statSync(c).isDirectory()) return c;
    } catch {
      /* siguiente */
    }
  }
  return "/";
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const socketPath = args.socket;
  const cols = Math.min(Math.max(parseInt(args.cols, 10) || 80, 1), 500);
  const rows = Math.min(Math.max(parseInt(args.rows, 10) || 24, 1), 500);
  const gid = parseInt(args.gid, 10);

  if (!socketPath) {
    process.stderr.write("rcp-pty-helper: falta --socket\n");
    process.exit(2);
  }

  const pty = loadNodePty();

  // Un socket residual de una sesión anterior impediría el bind.
  try {
    fs.unlinkSync(socketPath);
  } catch {
    /* no existía */
  }

  let child = null;
  let conn = null;
  let closed = false;

  const cleanup = (code) => {
    if (closed) return;
    closed = true;
    try { child && child.kill(); } catch { /* ya murió */ }
    try { conn && conn.destroy(); } catch { /* ya cerrado */ }
    try { server.close(); } catch { /* ya cerrado */ }
    try { fs.unlinkSync(socketPath); } catch { /* ya borrado */ }
    process.exit(code || 0);
  };

  const server = net.createServer((socket) => {
    // UNA sola conexión: en cuanto llega, dejamos de escuchar y borramos el
    // nodo del filesystem. A partir de aquí el socket no es alcanzable ni
    // siquiera por root — solo existe el fd ya conectado.
    conn = socket;
    try { server.close(); } catch { /* ignore */ }
    try { fs.unlinkSync(socketPath); } catch { /* ignore */ }
    clearTimeout(acceptTimer);

    const shell = pickShell();
    child = pty.spawn(shell, [], {
      name: "xterm-color",
      cols,
      rows,
      cwd: homeDir(),
      env: shellEnv(),
    });

    const send = (obj) => {
      if (!conn || conn.destroyed) return;
      try {
        conn.write(JSON.stringify(obj) + "\n");
      } catch {
        /* el agente se fue; el 'close' del socket recoge */
      }
    };

    child.onData((data) => send({ type: "stdout", data }));
    child.onExit(({ exitCode }) => {
      send({ type: "exit", code: exitCode });
      // Margen para que el último write salga antes de cerrar el fd.
      setTimeout(() => cleanup(0), 50);
    });

    let buf = "";
    socket.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;

        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          continue; // una línea corrupta no debe tumbar la sesión
        }
        if (!msg || typeof msg !== "object") continue;

        if (msg.type === "stdin" && typeof msg.data === "string") {
          try { child.write(msg.data); } catch { /* pty muerto */ }
        } else if (msg.type === "resize") {
          const c = Number(msg.cols);
          const r = Number(msg.rows);
          if (Number.isFinite(c) && Number.isFinite(r) &&
              c >= 1 && r >= 1 && c <= 500 && r <= 500) {
            try { child.resize(c, r); } catch { /* pty muerto */ }
          }
        } else if (msg.type === "close") {
          cleanup(0);
        }
      }
    });

    socket.on("close", () => cleanup(0));
    socket.on("error", () => cleanup(0));
  });

  server.on("error", (err) => {
    process.stderr.write("rcp-pty-helper: server error: " + err.message + "\n");
    cleanup(1);
  });

  server.listen(socketPath, () => {
    // Permisos ANTES de anunciar que está listo. El orden importa: privsvc
    // responde al agente cuando este proceso ya escucha, y no queremos una
    // ventana en la que el socket exista con los permisos por defecto.
    try {
      fs.chmodSync(socketPath, 0o660);
      if (Number.isFinite(gid)) fs.chownSync(socketPath, 0, gid);
    } catch (err) {
      process.stderr.write("rcp-pty-helper: no se pudieron fijar permisos: " + err.message + "\n");
      cleanup(1);
      return;
    }
    // Señal de vida para privsvc: hasta esta línea el socket no es usable.
    process.stdout.write("READY\n");
  });

  const acceptTimer = setTimeout(() => {
    process.stderr.write("rcp-pty-helper: nadie conectó en " + ACCEPT_TIMEOUT_MS + "ms\n");
    cleanup(0);
  }, ACCEPT_TIMEOUT_MS);

  process.on("SIGTERM", () => cleanup(0));
  process.on("SIGINT", () => cleanup(0));
}

main();
