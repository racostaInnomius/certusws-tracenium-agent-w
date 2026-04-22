import fs from "fs";
import net from "net";
import { SOCKET_PATH, ensurePrivSvcDirs } from "./paths";
import type { PrivSvcRequest } from "./protocol";
import { fail } from "./protocol";
import { routeRequest } from "./router";
import { logger } from "./logger";

const MAX_LINE_CHARS = 2 * 1024 * 1024;

function writeLine(socket: net.Socket, value: any) {
  socket.write(JSON.stringify(value) + "\n");
}

function pushTo(socket: net.Socket) {
  return (msg: Record<string, any>) => {
    if (socket.destroyed || socket.writable === false) return;
    writeLine(socket, msg);
  };
}

function handleClient(socket: net.Socket) {
  let buffer = "";
  const push = pushTo(socket);

  socket.on("data", async (chunk) => {
    buffer += chunk.toString("utf8");

    if (buffer.length > MAX_LINE_CHARS) {
      writeLine(socket, fail("unknown", "request_too_large", "IPC request exceeds maximum size"));
      socket.destroy();
      return;
    }

    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const raw of lines) {
      const line = raw.replace(/\r$/, "").trim();
      if (!line) continue;

      let req: PrivSvcRequest | null = null;
      try {
        req = JSON.parse(line);
      } catch {
        writeLine(socket, fail("unknown", "bad_json", "Invalid JSON"));
        continue;
      }
      if (!req) continue;

      try {
        const resp = await routeRequest(req, push);
        writeLine(socket, resp);
      } catch (err: any) {
        logger.error("request_failed", {
          id: req?.id,
          method: req?.method,
          error: err?.message || String(err)
        });
        writeLine(socket, fail(req?.id || "unknown", "internal_error", err?.message || String(err)));
      }
    }
  });

  socket.on("error", (err) => {
    logger.warn("client_socket_error", { error: err.message });
  });
}

export function startServer() {
  ensurePrivSvcDirs();

  try {
    if (fs.existsSync(SOCKET_PATH)) fs.unlinkSync(SOCKET_PATH);
  } catch {}

  const server = net.createServer(handleClient);

  server.listen(SOCKET_PATH, () => {
    // Lock the IPC socket down to the root user only. Methods like
    // grpc.connect, crypto.cert.renew and patch.install must never be
    // callable by anyone other than the agent-core daemon (which also
    // runs as root via launchd). The socket mode + owner combination is
    // enforced by the kernel on connect(), so no app-level auth is
    // required, and we don't have to pull in a native FFI module to
    // read SO_PEERCRED.
    let ownerOk = false;
    try {
      // chown before chmod — while the file is still group-writable by
      // the process default group, flipping the owner/group first
      // prevents a short window where a non-root process in wheel
      // could connect.
      if (typeof (fs as any).chownSync === "function") {
        (fs as any).chownSync(SOCKET_PATH, 0, 0); // root:wheel
        ownerOk = true;
      }
    } catch (err: any) {
      logger.warn("socket_chown_failed", { error: err?.message || String(err) });
    }

    try {
      fs.chmodSync(SOCKET_PATH, 0o600);
    } catch (err: any) {
      logger.warn("socket_chmod_failed", { error: err?.message || String(err) });
    }

    let stat: fs.Stats | null = null;
    try { stat = fs.statSync(SOCKET_PATH); } catch {}

    logger.info("privsvc_macos_listening", {
      socket: SOCKET_PATH,
      mode: stat ? (stat.mode & 0o777).toString(8) : "unknown",
      uid: stat?.uid,
      gid: stat?.gid,
      ownerOk
    });
  });

  server.on("error", (err) => {
    logger.error("server_error", { error: err.message });
  });

  const shutdown = () => {
    logger.info("privsvc_macos_shutdown");
    try {
      server.close();
    } catch {}
    try {
      if (fs.existsSync(SOCKET_PATH)) fs.unlinkSync(SOCKET_PATH);
    } catch {}
    process.exit(0);
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);

  return server;
}
