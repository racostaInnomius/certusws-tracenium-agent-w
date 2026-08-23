// src/plugins/cdp/index.ts
//
// CDP — Crypto Discovery Plugin. Inventories the X.509 certificates
// installed in the OS stores and reports metadata (never key material)
// to the control plane as the `cdp` facts namespace.
//
// Wire contract (schema 1.0): first successful scan sends the full
// items[] baseline; subsequent scans send a delta computed against the
// local SQLite baseline. `hasChanges` drives the scheduler's enqueue
// decision, mirroring the AMP delta pattern.
//
// Design: certusws-tracenium/docs/adr/ADR-0004-crypto-inventory-to-pqc-migration.md

import os from "os";
import type { AgentContext } from "../../core/agent-context";
import type { CdpCertItem, CdpNamespace, CdpStoreInfo } from "../../domain/cdp-types";
import { commitCdpBaseline, computeCdpDelta } from "../../domain/cdp-baseline-repo";
import { collectWindowsCdp } from "./providers/windows";
import { collectMacosCdp } from "./providers/macos";
import { collectLinuxCdp } from "./providers/linux";
import { collectJavaStores } from "./providers/java-stores";

// Defensive cap: a pathological host (mass-imported cert farm) must not
// produce a payload the outbox rejects (>2MB). Priority keeps the certs
// an operator actually cares about.
const MAX_ITEMS = 2000;

type ProviderResult = {
  items: CdpCertItem[];
  stores: CdpStoreInfo[];
  parseFailures: number;
};

function itemPriority(item: CdpCertItem): number {
  if (item.hasPrivateKey) return 0;
  if (item.store.scope !== "system-roots" && !item.isCA) return 1;
  if (item.store.scope !== "system-roots") return 2;
  return 3;
}

function applyCap(items: CdpCertItem[]): { items: CdpCertItem[]; truncated: boolean } {
  if (items.length <= MAX_ITEMS) {
    return { items, truncated: false };
  }
  const prioritized = [...items].sort((a, b) => itemPriority(a) - itemPriority(b));
  return { items: prioritized.slice(0, MAX_ITEMS), truncated: true };
}

export type CollectCdpOptions = {
  /**
   * Send the COMPLETE inventory instead of a delta.
   *
   * The scheduled scan is incremental by design: after the first run it
   * ships only what changed. That is right for a 12h heartbeat and wrong
   * for an operator who just asked for a scan — a delta of zero would
   * answer "nothing changed" when the question was "what is on this
   * device?", and an on-demand snapshot that says nothing is
   * indistinguishable from one that failed.
   *
   * Skipping the diff also makes the forced scan idempotent: the payload
   * is a full picture, so re-running it cannot leave the control plane
   * in a state that depends on how many times it was asked.
   */
  full?: boolean;
};

/**
 * Serialization lane for CDP scans.
 *
 * `collectOnce` commits the SQLite baseline, and the delta it computes is
 * only meaningful against the baseline as it stood when the scan started.
 * Two overlapping scans therefore corrupt each other: the second diffs
 * against a baseline the first has already replaced, so genuinely new
 * certificates read as unchanged and vanish from the wire until something
 * else about them moves.
 *
 * Until now the only caller was the scheduler, which held its own
 * `cdpRunning` mutex — the invariant was real but enforced by the caller.
 * On-demand collection adds a second entrance, so the guard moves to the
 * thing that owns the baseline. Any future caller gets it for free rather
 * than having to know it exists.
 *
 * Queue, don't share: a caller that asked for `full` must not be handed a
 * delta produced by whoever happened to be running. Waiting costs a
 * second scan; sharing would silently break the contract.
 */
let cdpLane: Promise<void> = Promise.resolve();

export function collectCDP(
  ctx: AgentContext,
  options?: CollectCdpOptions
): Promise<CdpNamespace> {
  const result = cdpLane.then(() => collectOnce(ctx, options));
  // The lane must never reject, or every later scan inherits the failure.
  cdpLane = result.then(
    () => undefined,
    () => undefined
  );
  return result;
}

async function collectOnce(
  ctx: AgentContext,
  options?: CollectCdpOptions
): Promise<CdpNamespace> {
  const platform = os.platform();
  const base: Pick<CdpNamespace, "schemaVersion" | "collector" | "collectedAt"> = {
    schemaVersion: "1.0",
    collector: { plugin: "cdp", version: ctx.config.agentVersion },
    collectedAt: new Date().toISOString()
  };

  let result: ProviderResult;

  try {
    if (platform === "win32") {
      result = await collectWindowsCdp(ctx);
    } else if (platform === "darwin") {
      result = await collectMacosCdp();
    } else if (platform === "linux") {
      result = await collectLinuxCdp();
    } else {
      return {
        ...base,
        hasChanges: true,
        truncated: false,
        stores: [],
        certificates: { count: 0 },
        collectorError: {
          message: `CDP collector is not implemented for platform ${platform}`,
          phase: "platform_unsupported"
        }
      };
    }
  } catch (err: any) {
    // Collector failure → diagnostic block, no items. The backend keeps
    // the device's last good projection (same stale-preservation
    // contract as SCP): a broken scan must never look like "all
    // certificates were removed".
    return {
      ...base,
      hasChanges: true,
      truncated: false,
      stores: [],
      certificates: { count: 0 },
      collectorError: {
        message: err?.message || String(err),
        phase: "collect"
      }
    };
  }

  // Java keystores (JVM cacerts + operator-configured JKS/PKCS12) are
  // platform-independent and additive. Fail-soft: a broken keytool or
  // corrupt keystore must never take down the OS-store scan that just
  // succeeded — per-store failures are already surfaced as storeErrors
  // inside the collector, and a total failure only costs the java view.
  try {
    const java = await collectJavaStores(ctx);
    result.items.push(...java.items);
    result.stores.push(...java.stores);
    result.parseFailures += java.parseFailures;
  } catch (err: any) {
    ctx.logger?.warn?.("CDP: java store collection failed (non-fatal)", {
      error: err?.message || String(err)
    });
  }

  // Certificates that live as files on disk. Opt-in via policy: an empty
  // path list means the feature is off, and there is no default set —
  // see the collector for why. Fail-soft like the Java stores: a bad
  // path must never cost us the store scan that just succeeded.
  const certFileRoots = ctx.policyRuntime.getCdpCertFilePaths();
  if (certFileRoots.length > 0) {
    try {
      const { collectCertFiles } = await import("./providers/cert-files");
      const files = await collectCertFiles(certFileRoots);
      result.items.push(...files.items);
      result.stores.push(...files.stores);
      result.parseFailures += files.parseFailures;
      if (files.capped || files.unreadable > 0) {
        ctx.logger?.warn?.("CDP: cert file scan incomplete", {
          filesScanned: files.filesScanned,
          unreadable: files.unreadable,
          capped: files.capped
        });
      }
    } catch (err: any) {
      ctx.logger?.warn?.("CDP: cert file scan failed (non-fatal)", {
        error: err?.message || String(err)
      });
    }
  }

  // TLS listeners — opt-in, loopback-only, and the only collector that
  // opens sockets. Same fail-soft contract as the Java stores: a probe
  // that misbehaves must never cost us the store scan that just
  // succeeded.
  if (ctx.policyRuntime.getCdpScanTlsListeners()) {
    try {
      const { collectTlsListeners } = await import("./providers/tls-listeners");
      const listeners = await collectTlsListeners(ctx);
      result.items.push(...listeners.items);
      result.stores.push(...listeners.stores);
      result.parseFailures += listeners.parseFailures;
    } catch (err: any) {
      ctx.logger?.warn?.("CDP: TLS listener scan failed (non-fatal)", {
        error: err?.message || String(err)
      });
    }
  }

  const { items, truncated } = applyCap(result.items);

  if (result.parseFailures > 0) {
    ctx.logger?.warn?.("CDP: some certificates failed to parse", {
      parseFailures: result.parseFailures,
      parsed: items.length
    });
  }

  // Delta vs the local baseline. null → first run → full items[].
  //
  // A forced scan takes the same route as a first run: no diff, full
  // items[]. That is not a special case bolted on — "send everything you
  // have" is exactly what the baseline path already means, so `full`
  // reuses it instead of introducing a third shape on the wire.
  const delta = options?.full ? null : computeCdpDelta(items);

  // A capped scan cannot claim anything was removed.
  //
  // `applyCap` drops the lowest-priority certificates when a host has
  // more than MAX_ITEMS. Those are missing from `items` while being
  // perfectly present on the device, so the diff below sees them as
  // deletions — and would re-report them as deletions on every scan, on
  // exactly the hosts with the largest certificate estates.
  //
  // The control plane refuses to act on removals from a truncated
  // payload as well, but the agent is where the incompleteness is KNOWN,
  // so it should not make the claim in the first place: an assertion
  // nobody downstream is allowed to trust has no business on the wire.
  if (truncated && delta) {
    delta.removed = [];
  }
  const isBaselineSend = delta === null;
  const hasChanges = isBaselineSend
    ? true
    : delta.added.length > 0 || delta.removed.length > 0 || delta.updated.length > 0;

  // Commit AFTER diffing so `removed` is computed against the previous
  // scan. Committing here (vs after enqueue) mirrors AMP: the outbox is
  // local SQLite and its enqueue effectively cannot fail.
  if (hasChanges) {
    commitCdpBaseline(items);
  }

  return {
    ...base,
    hasChanges,
    truncated,
    stores: result.stores,
    certificates: {
      count: items.length,
      ...(isBaselineSend ? { items } : {}),
      ...(!isBaselineSend && hasChanges ? { delta } : {})
    }
  };
}
