// src/diag/wedge-dump.ts
// Best-effort diagnostic dump written just before process.exit(1) from the
// liveness watchdog. The file captures JS stack, pending IPC requests, libuv
// handle state, and memory pressure — the "smoking gun" we need to understand
// why the event loop wedged. Consumed offline by support/engineering.

import * as fs from "fs";
import * as path from "path";

// Structural / duck-typed shape — we accept whatever the caller hands
// us. We do NOT import the real AgentContext type from core/ to keep
// wedge-dump.ts free of internal coupling: if the real AgentContext
// shape grows new required fields, this diagnostic helper should
// continue to compile against any version of it.
//
// `priv` is `any` because we only probe two optional methods on it
// (`getPendingCount`, `getPendingMethods`) added specifically for
// diagnostics. The real IPrivSvcClient interface intentionally
// doesn't include them in its strict surface.
interface AgentContext {
  trayStatus?: { getLastWriteMs?: () => number };
  priv?: any;
}

interface Logger {
  info?: (msg: string, meta?: unknown) => void;
  error?: (msg: string, meta?: unknown) => void;
}

export async function dumpWedgeState(
  ctx: AgentContext | null | undefined,
  log: Logger,
): Promise<string | null> {
  try {
    const logDir =
      process.platform === "win32"
        ? path.join(
            process.env.ProgramFiles || "C:\\Program Files",
            "Tracenium", "AgentCore", "logs",
          )
        : "/var/log/tracenium";

    fs.mkdirSync(logDir, { recursive: true });

    const wedgeFile = path.join(logDir, `wedge-${Date.now()}.json`);

    // process.report.getReport() is available on Node 12+, returns rich state.
    const procAny = process as any;
    const report = procAny.report?.getReport?.() ?? {};

    const lastTrayMs = ctx?.trayStatus?.getLastWriteMs?.() ?? null;
    const data = {
      timestamp: new Date().toISOString(),
      pid: process.pid,
      uptimeSeconds: Math.round(process.uptime()),
      memoryUsage: process.memoryUsage(),

      lastTrayWriteMs: lastTrayMs,
      lastTrayWriteAgoSeconds:
        lastTrayMs !== null ? Math.round((Date.now() - lastTrayMs) / 1000) : null,

      ipc: {
        pendingCount: ctx?.priv?.getPendingCount?.() ?? null,
        pendingMethods: ctx?.priv?.getPendingMethods?.() ?? null,
      },

      // Trim heavy/PII-sensitive parts of process.report
      processReport: {
        platform: report.platform,
        componentVersions: report.componentVersions,
        javascriptStack: report.javascriptStack,
        nativeStack: Array.isArray(report.nativeStack)
          ? report.nativeStack.slice(0, 30)
          : null,
        libuv: report.libuv,
        // intentionally omitted: workers, environmentVariables (PII risk)
      },
    };

    fs.writeFileSync(wedgeFile, JSON.stringify(data, null, 2), "utf8");
    log.info?.("Wedge diagnostics dumped", { wedgeFile });
    return wedgeFile;
  } catch (err: any) {
    log.error?.("Wedge dump failed", { error: err?.message });
    return null;
  }
}
