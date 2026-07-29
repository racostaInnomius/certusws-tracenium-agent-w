import fs from "fs";
import os from "os";
import path from "path";
import si from "systeminformation";
import type { AgentContext } from "../core/agent-context";
import {
  ensureAgentStatusDir,
  getTrayStatusFilePath,
  getLegacyAgentStatusDir,
} from "../bootstrap/paths";
import { loadPmpState } from "../plugins/pmp/state";
import { loadUpdateState } from "../update/update-state";
import type { TrayDeviceInfo, TrayStatusSnapshot } from "./tray-status-types";

const TRAY_STATUS_FILE_NAME = "tray-status.json";

// ── Device info collection (support widget) ────────────────────────────────
//
// Gathers the static identity fields the "Device Info" tab/flyout shows to
// end users during support calls. All sources are `systeminformation`
// queries the agent already uses elsewhere (device-facts-builder); this is
// a slim, tray-purposed subset. Runs once per process start — model,
// serial, MAC, CPU etc. don't change while the service runs, and the tray
// re-reads the JSON on its own 5s timer anyway.
//
// Deliberately NOT collected here (the tray fills these locally from the
// user session): logged-in user, screen resolution. See TrayDeviceInfo.
async function collectDeviceInfo(): Promise<TrayDeviceInfo> {
  const device: TrayDeviceInfo = {};

  try {
    const osInfo = await si.osInfo();
    device.hostname = osInfo.hostname || os.hostname();
    device.fqdn = osInfo.fqdn || undefined;
    device.osName = [osInfo.distro, osInfo.codename].filter(Boolean).join(" ") || osInfo.platform;
    device.osVersion = osInfo.release || undefined;
    device.osBuild = osInfo.build || undefined;
    // Domain: prefer the DNS suffix from the FQDN. USERDOMAIN is useless
    // here — the service runs as SYSTEM, so it holds the machine name.
    if (osInfo.fqdn && osInfo.hostname && osInfo.fqdn.length > osInfo.hostname.length) {
      device.domain = osInfo.fqdn.slice(osInfo.hostname.length).replace(/^\./, "") || undefined;
    }
  } catch { /* best-effort — leave fields undefined */ }

  try {
    const system = await si.system();
    device.manufacturer = system.manufacturer || undefined;
    device.model = system.model || undefined;
    device.serial = system.serial || undefined;
  } catch { /* best-effort */ }

  try {
    const cpu = await si.cpu();
    const brand = [cpu.manufacturer, cpu.brand].filter(Boolean).join(" ").trim();
    if (brand) device.cpu = cpu.cores ? `${brand} (${cpu.cores} cores)` : brand;
  } catch { /* best-effort */ }

  try {
    const mem = await si.mem();
    if (mem.total > 0) device.memoryGb = Math.round((mem.total / 1024 ** 3) * 10) / 10;
  } catch { /* best-effort */ }

  try {
    // Same selection logic as device-facts-builder: prefer the default
    // route's interface; fall back to the first non-internal one with an
    // IPv4. That's the address support actually wants ("your IP").
    const [ifaces, defaultIface] = await Promise.all([
      si.networkInterfaces(),
      si.networkInterfaceDefault()
    ]);
    const list = Array.isArray(ifaces) ? ifaces : [ifaces];
    const pick =
      list.find((i) => i.iface === defaultIface && i.ip4) ||
      list.find((i) => !i.internal && !i.virtual && i.ip4) ||
      list.find((i) => !i.internal && i.ip4);
    if (pick) {
      device.ipv4 = pick.ip4 || undefined;
      device.ipv6 = pick.ip6 || undefined;
      device.mac = pick.mac || undefined;
    }
  } catch { /* best-effort */ }

  return device;
}

function ensureDir(dir: string) {
  fs.mkdirSync(dir, { recursive: true });
}

/**
 * Best-effort cleanup of a stale tray-status.json from the pre-fix
 * Windows path. Without this, an operator inspecting
 * C:\ProgramData\Tracenium\status\ would still see the old zombie
 * JSON (last written by an earlier release) and second-guess whether
 * the tray is reading from the right place.
 *
 * Failure modes (file in use, perms denied, dir missing) are all
 * silently swallowed — the file is just informational debris, never
 * required for correctness.
 */
function purgeLegacyStatusFile() {
  const legacyDir = getLegacyAgentStatusDir();
  if (!legacyDir) return;
  const legacyFile = path.join(legacyDir, TRAY_STATUS_FILE_NAME);
  try {
    if (fs.existsSync(legacyFile)) {
      fs.unlinkSync(legacyFile);
    }
  } catch {
    // ignore — leftover zombie at most, not a correctness issue.
  }
}

export class TrayStatusStore {
  private dir = ensureAgentStatusDir();
  private filePath = getTrayStatusFilePath();

  // Wall-clock of the most recent successful save(). Read by the
  // process-level liveness watchdog (see service.ts) which exits the
  // process if no writes have happened in N minutes — the canonical
  // signal that the event loop is wedged. Normal operation writes
  // this on every heartbeat (~60s), every reconnect attempt, every
  // job event, and every policy change, so going > 5 min without an
  // update means SOMETHING is stuck in an unrecoverable await.
  //
  // We initialize to now() so the watchdog has a finite starting
  // reference even before the first write — otherwise a slow startup
  // could fire it spuriously.
  private lastWriteAtMs: number = Date.now();

  constructor() {
    ensureDir(this.dir);
    purgeLegacyStatusFile();
  }

  getPath() {
    return this.filePath;
  }

  /**
   * Returns the wall-clock ms of the most recent successful save().
   * Watchdog reads this; do not use for anything else (e.g. don't
   * make user-visible decisions on it — it doesn't represent any
   * semantic state, just I/O liveness).
   */
  getLastWriteMs() {
    return this.lastWriteAtMs;
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
    // Stamp AFTER the rename succeeds — a failed write should not
    // refresh the liveness clock, or the watchdog could be fooled by a
    // disk-full / perms / EBUSY loop that keeps throwing in the same
    // place every tick. We want the watchdog to actually exit in that
    // case so launchd restarts us with fresh fd state.
    this.lastWriteAtMs = Date.now();
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
        modules: Array.isArray(policySnapshot?.modules) ? policySnapshot.modules : [],
        features: {
          deviceInfoWidget: Boolean(policySnapshot?.features?.deviceInfoWidget)
        }
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

  /**
   * Collects device identity (async, ~1-2s of si.* queries) and merges it
   * into the snapshot. Fire-and-forget from service startup — failures
   * leave `device` absent and the tray simply shows "—" placeholders.
   * update() spreads `current`, so the block persists across all later
   * mark*() writes without them having to know about it.
   */
  async refreshDeviceInfo() {
    const device = await collectDeviceInfo();
    return this.update((current) => ({
      ...(current || this.emptySnapshot()),
      device
    }));
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
        modules: Array.isArray(policySnapshot?.modules) ? policySnapshot.modules : [],
        features: {
          deviceInfoWidget: Boolean(policySnapshot?.features?.deviceInfoWidget)
        }
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
