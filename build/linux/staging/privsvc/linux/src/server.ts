// privsvc/linux/src/server.ts
//
// Unix-socket IPC server. Speaks newline-delimited JSON; the agent's
// `src/priv/privsvc-client-linux.ts` is the only intended client.
//
// Permissions model differs from macOS:
//
//   macOS  →  0600 root:wheel   (only root can connect; the agent
//                                 also runs as root via launchd, so
//                                 same uid resolves the gate)
//   Linux  →  0660 root:tracenium  (root + members of the `tracenium`
//                                    group; the agent runs as the
//                                    `tracenium` user which is in that
//                                    group, so a non-root agent
//                                    process can connect without us
//                                    having to read SO_PEERCRED)
//
// The kernel enforces the mode/owner check on connect(), so once the
// chown+chmod succeeds, the daemon doesn't have to do any per-call
// authentication. If the group lookup fails (group not yet created
// during a half-finished install) we fall back to 0600 root-only —
// the agent will get EACCES on connect, which is loud and visible
// rather than silently letting unprivileged callers in.
import fs from "fs";
import net from "net";
import { SOCKET_PATH, ensurePrivSvcDirs, lookupSocketGid, SOCKET_GROUP } from "./paths";
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
          error: err?.message || String(err),
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

  // Drop a stale socket from a previous unclean shutdown. systemd's
  // RuntimeDirectory= cleanup makes this redundant on a managed start
  // (the whole /run/tracenium dir is recreated empty), but a developer
  // run via `node dist/index.js` won't have that, so do it explicitly.
  try {
    if (fs.existsSync(SOCKET_PATH)) fs.unlinkSync(SOCKET_PATH);
  } catch {}

  const server = net.createServer(handleClient);

  server.listen(SOCKET_PATH, () => {
    // Lock down owner/group/mode. The agent process runs as
    // user `tracenium` (configured in tracenium-agent.service);
    // members of the `tracenium` group can connect, root can connect,
    // nobody else can. If the group doesn't exist yet (broken or
    // half-finished install) we fall back to 0600 — agent calls will
    // EACCES and show up loudly in journald, which is preferable to
    // silently allowing unprivileged callers.
    let ownerOk = false;
    let groupOk = false;
    const gid = lookupSocketGid();

    try {
      if (typeof (fs as any).chownSync === "function") {
        // chown BEFORE chmod — while the inode is still 0644 by
        // default, flipping owner/group first prevents a momentary
        // window where a non-root process whose primary group
        // happens to match the umask could connect.
        (fs as any).chownSync(SOCKET_PATH, 0, gid ?? 0);
        ownerOk = true;
        groupOk = gid !== null;
      }
    } catch (err: any) {
      logger.warn("socket_chown_failed", { error: err?.message || String(err) });
    }

    const targetMode = groupOk ? 0o660 : 0o600;
    try {
      fs.chmodSync(SOCKET_PATH, targetMode);
    } catch (err: any) {
      logger.warn("socket_chmod_failed", { error: err?.message || String(err) });
    }

    if (!groupOk) {
      logger.warn("socket_group_unavailable", {
        group: SOCKET_GROUP,
        note: "falling back to 0600 root-only — agent will not be able to connect until /etc/group has the tracenium group",
      });
    }

    let stat: fs.Stats | null = null;
    try { stat = fs.statSync(SOCKET_PATH); } catch {}

    logger.info("privsvc_linux_listening", {
      socket: SOCKET_PATH,
      mode: stat ? (stat.mode & 0o777).toString(8) : "unknown",
      uid: stat?.uid,
      gid: stat?.gid,
      ownerOk,
      groupOk,
      group: SOCKET_GROUP,
    });
  });

  server.on("error", (err) => {
    logger.error("server_error", { error: err.message });
  });

  const shutdown = () => {
    logger.info("privsvc_linux_shutdown");
    try { server.close(); } catch {}
    try {
      if (fs.existsSync(SOCKET_PATH)) fs.unlinkSync(SOCKET_PATH);
    } catch {}
    process.exit(0);
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);

  return server;
}
