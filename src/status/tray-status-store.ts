import fs from "fs";
import os from "os";
import type { AgentContext } from "../core/agent-context";
import { ensureAgentStatusDir, getTrayStatusFilePath } from "../bootstrap/paths";
import { loadPmpState } from "../plugins/pmp/state";
import { loadUpdateState } from "../update/update-state";
import type { TrayStatusSnapshot } from "./tray-status-types";

function ensureDir(dir: string) {
  fs.mkdirSync(dir, { recursive: true });
}

export class TrayStatusStore {
  private dir = ensureAgentStatusDir();
  private filePath = getTrayStatusFilePath();

  constructor() {
    ensureDir(this.dir);
  }

  getPath() {
    return this.filePath;
  }

  load(): TrayStatusSnapshot | null {
    if (!fs.existsSync(this.filePath)) {
      return null;
    }

    try {
      return JSON.parse(fs.readFileSync(this.filePath, "utf8")) as TrayStatusSnapshot;
    } catch {
      return null;
    }
  }

  save(snapshot: TrayStatusSnapshot) {
    ensureDir(this.dir);
    const tmp = `${this.filePath}.tmp`;
    // Mode 0o644: world-readable, root-writable. El tray app corre
    // como user UID y necesita leer este archivo. Antes era 0o600 y
    // bloqueaba al tray. El JSON no contiene secretos — solo info
    // operacional (hostname, deviceId, versión, estado gRPC,
    // policy version, job state). Equivalente al log file que
    // también es 0o644 en /Library/Application Support/Tracenium/Logs/.
    fs.writeFileSync(tmp, JSON.stringify(snapshot, null, 2), { encoding: "utf8", mode: 0o644 });
    fs.renameSync(tmp, this.filePath);
  }

  update(
    updater: (current: TrayStatusSnapshot | null) => TrayStatusSnapshot
  ) {
    const current = this.load();
    const next = updater(current);
    next.updatedAtUtc = new Date().toISOString();
    this.save(next);
    return next;
  }

  writeStartupSnapshot(ctx: AgentContext) {
    const updateState = loadUpdateState();
    const patchState = loadPmpState();
    const policySnapshot = ctx.policyRuntime.snapshot();

    const snapshot: TrayStatusSnapshot = {
      updatedAtUtc: new Date().toISOString(),
      agentVersion: ctx.config.agentVersion,
      coreVersion: ctx.config.coreVersion,
      deviceId: ctx.enrollment.deviceId,
      tenantId: ctx.enrollment.tenantId,
      hostname: os.hostname(),
      grpc: {
        connected: false
      },
      policy: {
        version: ctx.policy.getVersion(),
        hash: ctx.policy.getHash(),
        plugins: Array.isArray(policySnapshot?.plugins) ? policySnapshot.plugins : [],
        modules: Array.isArray(policySnapshot?.modules) ? policySnapshot.modules : []
      },
      jobs: {},
      update: {
        status: updateState.status,
        lastCheckedAtUtc: updateState.lastCheckedAtUtc,
        lastCompletedAtUtc: updateState.lastCompletedAtUtc,
        lastError: updateState.lastError
      },
      patch: {
        status: patchState.status,
        lastScanAtUtc: undefined,
        rebootRequired: patchState.rebootRequired,
        lastError: patchState.lastError
      }
    };

    this.save(snapshot);
    return snapshot;
  }

  markGrpcConnected() {
    return this.update((current) => ({
      ...(current || this.emptySnapshot()),
      grpc: {
        ...(current?.grpc || { connected: false }),
        connected: true,
        lastConnectedAtUtc: new Date().toISOString()
      }
    }));
  }

  markGrpcDisconnected() {
    return this.update((current) => ({
      ...(current || this.emptySnapshot()),
      grpc: {
        ...(current?.grpc || { connected: false }),
        connected: false,
        lastDisconnectedAtUtc: new Date().toISOString()
      }
    }));
  }

  markHeartbeat() {
    return this.update((current) => ({
      ...(current || this.emptySnapshot()),
      grpc: {
        ...(current?.grpc || { connected: false }),
        lastHeartbeatAtUtc: new Date().toISOString()
      }
    }));
  }

  markPolicyApplied(ctx: AgentContext) {
    const policySnapshot = ctx.policyRuntime.snapshot();
    return this.update((current) => ({
      ...(current || this.emptySnapshot()),
      policy: {
        version: ctx.policy.getVersion(),
        hash: ctx.policy.getHash(),
        plugins: Array.isArray(policySnapshot?.plugins) ? policySnapshot.plugins : [],
        modules: Array.isArray(policySnapshot?.modules) ? policySnapshot.modules : []
      }
    }));
  }

  markJobStarted(jobType: string) {
    return this.update((current) => ({
      ...(current || this.emptySnapshot()),
      jobs: {
        ...(current?.jobs || {}),
        lastJobType: jobType,
        lastJobStatus: "in_progress",
        lastJobAtUtc: new Date().toISOString()
      }
    }));
  }

  markJobFinished(jobType: string, status: "success" | "retry" | "failed", patch?: Partial<TrayStatusSnapshot["patch"]>) {
    return this.update((current) => ({
      ...(current || this.emptySnapshot()),
      jobs: {
        ...(current?.jobs || {}),
        lastJobType: jobType,
        lastJobStatus: status,
        lastJobAtUtc: new Date().toISOString()
      },
      patch: {
        ...(current?.patch || {}),
        ...(patch || {})
      }
    }));
  }

  private emptySnapshot(): TrayStatusSnapshot {
    return {
      updatedAtUtc: new Date().toISOString(),
      agentVersion: "",
      coreVersion: "",
      deviceId: "",
      tenantId: "",
      hostname: os.hostname(),
      grpc: {
        connected: false
      },
      policy: {
        version: "none",
        hash: null,
        plugins: [],
        modules: []
      },
      jobs: {},
      update: {},
      patch: {}
    };
  }
}
