// src/plugins/rcp/pty-session-linux.ts
//
// Sesión de shell remoto en Linux: proxy entre el DataChannel y el pty que
// privsvc abre como root.
//
// POR QUÉ SOLO LINUX
// ----------------------------------------------------------------------------
// En Windows el AgentCore es LocalSystem y en macOS es root (LaunchDaemon), así
// que ahí `nodePty.spawn()` local (pty-session.ts) ya devuelve un shell con
// todo. Linux es la excepción: el agente corre como `User=tracenium`, uid sin
// privilegios y sin sudo. Eso está bien —el resto de lo privilegiado va por
// IPC— pero dejaba al operador con un bash incapaz de reiniciar un servicio,
// leer /var/log/syslog o listar /root, y justo en la plataforma donde el shell
// es el único acceso porque no hay GUI.
//
// POR QUÉ UN SOCKET Y NO EL IPC
// ----------------------------------------------------------------------------
// El IPC de privsvc es JSON-por-líneas y en Windows atiende UNA petición a la
// vez. Meter ahí una sesión interactiva la haría monopolizar el carril mientras
// dure, matando heartbeats, inventario y compliance. Por el IPC solo viajan
// `open` y `close`; los bytes van por un socket dedicado que el helper crea.
//
// La ventaja de contrato: el helper habla el MISMO JSON que el navegador, así
// que esta clase es casi un tubo. No traduce protocolos, solo los empalma.

import * as net from "node:net";
import type { AgentContext } from "../../core/agent-context";

export type PtySessionArgs = {
  sessionId: string;
  ctx: AgentContext;
  send: (text: string) => void;
  onExit: (code: number, reason: string) => void;
};

const DEFAULT_COLS = 80;
const DEFAULT_ROWS = 24;

export class LinuxPrivilegedPtySession {
  private socket: net.Socket | null = null;
  private disposed = false;
  private ready = false;
  /**
   * Lo que el navegador manda antes de que el socket esté listo.
   *
   * El constructor de PtySession es síncrono —peer-session lo crea dentro del
   * handler de apertura del DataChannel— pero abrir este pty requiere una
   * llamada IPC y una conexión. Encolar preserva ese contrato sin tocar el
   * flujo del llamador: las primeras teclas del operador no se pierden.
   */
  private pending: string[] = [];
  private buf = "";
  private cols = DEFAULT_COLS;
  private rows = DEFAULT_ROWS;

  constructor(private readonly args: PtySessionArgs) {
    void this.connect();
  }

  private async connect(): Promise<void> {
    const { ctx, sessionId } = this.args;

    try {
      const res: any = await (ctx.priv as any).call({
        v: 1,
        id: `rcp.pty.open.${sessionId}`,
        method: "rcp.pty.open",
        params: { sessionId, cols: this.cols, rows: this.rows },
      });

      if (this.disposed) {
        // La sesión se cerró mientras privsvc arrancaba el helper. Hay que
        // recogerlo o quedaría un shell de root esperando conexión.
        void this.closeRemote();
        return;
      }

      if (!res?.ok) {
        // Se propaga el código de privsvc en vez de colapsarlo: distinguir
        // "el helper no existe" de "no soy root" es lo que hace diagnosticable
        // esto desde el portal.
        const code = String(res?.error?.code ?? "").trim() || "pty_open_failed";
        const msg = String(res?.error?.message ?? res?.error ?? "no se pudo abrir el pty");
        this.failSession(code, msg);
        return;
      }

      const socketPath = String(res?.result?.socketPath || "");
      if (!socketPath) {
        this.failSession("pty_open_failed", "privsvc no devolvió socketPath");
        return;
      }

      await this.attach(socketPath);
    } catch (err: any) {
      this.failSession("pty_open_failed", err?.message || String(err));
    }
  }

  private attach(socketPath: string): Promise<void> {
    return new Promise<void>((resolve) => {
      const sock = net.createConnection(socketPath);

      sock.on("connect", () => {
        if (this.disposed) {
          try { sock.destroy(); } catch { /* ya cerrado */ }
          resolve();
          return;
        }
        this.socket = sock;
        this.ready = true;

        this.args.ctx.logger?.info?.("[rcp pty] shell privilegiado listo", {
          sessionId: this.args.sessionId,
          privileged: true,
        });

        // Drenar lo que el operador tecleó mientras conectábamos.
        const queued = this.pending;
        this.pending = [];
        for (const line of queued) this.writeLine(line);
        resolve();
      });

      sock.on("data", (chunk) => this.onSocketData(chunk));

      sock.on("error", (err: any) => {
        this.failSession("pty_socket_error", err?.message || String(err));
        resolve();
      });

      sock.on("close", () => {
        // El helper cierra el socket cuando el shell termina. Si el `exit` ya
        // llegó por el canal, esto es redundante y `disposed` lo absorbe.
        if (!this.disposed) {
          this.disposed = true;
          this.args.onExit(0, "shell_exit");
        }
        resolve();
      });
    });
  }

  /**
   * Frames del helper. Vienen ya en el formato que espera el navegador, así
   * que se reenvían literalmente en vez de reconstruirlos.
   */
  private onSocketData(chunk: Buffer | string): void {
    if (this.disposed) return;
    this.buf += typeof chunk === "string" ? chunk : chunk.toString("utf8");

    let nl: number;
    while ((nl = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, nl).trim();
      this.buf = this.buf.slice(nl + 1);
      if (!line) continue;

      let msg: any;
      try {
        msg = JSON.parse(line);
      } catch {
        continue; // una línea corrupta no debe tumbar la sesión
      }

      // El `exit` se reenvía y ADEMÁS cierra: el navegador tiene que verlo
      // antes de que el peer WebRTC desaparezca (mismo orden que pty-session).
      if (msg?.type === "exit") {
        try { this.args.send(line); } catch { /* canal ya caído */ }
        if (!this.disposed) {
          this.disposed = true;
          this.args.onExit(Number(msg.code) || 0, "shell_exit");
        }
        return;
      }

      try { this.args.send(line); } catch { /* canal ya caído */ }
    }
  }

  private writeLine(line: string): void {
    if (!this.socket || this.socket.destroyed) return;
    try {
      this.socket.write(line + "\n");
    } catch (err: any) {
      this.args.ctx.logger?.warn?.("[rcp pty] write al socket falló", {
        sessionId: this.args.sessionId,
        err: err?.message,
      });
    }
  }

  /** Contar al navegador por qué no hay shell, y cerrar como lo haría un exit. */
  private failSession(code: string, message: string): void {
    if (this.disposed) return;
    this.disposed = true;
    this.args.ctx.logger?.error?.("[rcp pty] no se pudo abrir el shell privilegiado", {
      sessionId: this.args.sessionId,
      code,
      message,
    });
    try {
      this.args.send(JSON.stringify({ type: "stdout", data: `\r\n[tracenium] ${code}: ${message}\r\n` }));
      this.args.send(JSON.stringify({ type: "exit", code: 1 }));
    } catch { /* canal ya caído */ }
    this.args.onExit(1, code);
  }

  private async closeRemote(): Promise<void> {
    try {
      await (this.args.ctx.priv as any).call({
        v: 1,
        id: `rcp.pty.close.${this.args.sessionId}`,
        method: "rcp.pty.close",
        params: { sessionId: this.args.sessionId },
      });
    } catch {
      // El helper se recoge solo al cerrarse el socket; esto es solo el
      // camino explícito para cuando ni siquiera llegamos a conectar.
    }
  }

  handleMessage(raw: string): void {
    if (this.disposed) return;

    // Se inspecciona lo mínimo: `resize` para recordar el tamaño (el helper
    // necesita el inicial en el open) y `close` para el apagado ordenado. El
    // resto viaja tal cual.
    let parsed: any;
    try {
      parsed = JSON.parse(raw);
    } catch {
      this.args.ctx.logger?.warn?.("[rcp pty] JSON inválido del navegador", {
        sessionId: this.args.sessionId,
        sample: raw.slice(0, 80),
      });
      return;
    }
    if (!parsed || typeof parsed !== "object") return;

    if (parsed.type === "resize") {
      const c = Number(parsed.cols);
      const r = Number(parsed.rows);
      if (Number.isFinite(c) && Number.isFinite(r) && c >= 1 && r >= 1 && c <= 500 && r <= 500) {
        this.cols = c;
        this.rows = r;
      } else {
        return; // fuera de rango: no se propaga
      }
    }

    if (parsed.type === "close") {
      this.dispose("operator_closed");
      return;
    }

    if (!this.ready) {
      // Cota dura: si el helper nunca conecta, esto no puede crecer sin
      // límite con cada tecla.
      if (this.pending.length < 256) this.pending.push(raw);
      return;
    }
    this.writeLine(raw);
  }

  dispose(reason: string): void {
    if (this.disposed) return;
    this.disposed = true;

    // Cerrar el socket es lo que le dice al helper que termine; el `close`
    // explícito por IPC cubre el caso de que aún no hubiera socket.
    try {
      this.socket?.end(JSON.stringify({ type: "close" }) + "\n");
      this.socket?.destroy();
    } catch { /* ya cerrado */ }
    this.socket = null;

    void this.closeRemote();

    this.args.ctx.logger?.info?.("[rcp pty] sesión privilegiada cerrada", {
      sessionId: this.args.sessionId,
      reason,
    });
  }
}
