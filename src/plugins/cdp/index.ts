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
import type {
  CdpAdcsReport,
  CdpAnchorPinReport,
  CdpCertItem,
  CdpNamespace,
  CdpStoreInfo,
  CdpUnreadableStore
} from "../../domain/cdp-types";
import {
  cdpAnchorDigestChanged,
  commitCdpAnchorDigest,
  commitCdpBaseline,
  computeCdpDelta,
  hashCdpAnchorState,
  loadCdpBaselineItemsByStore
} from "../../domain/cdp-baseline-repo";
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

  // ── Escaneo parcial ───────────────────────────────────────────────
  //
  // Cada colector es fail-soft: un keystore Java bloqueado, una base NSS
  // abierta por Firefox o un login keychain de otro usuario no pueden
  // costar el escaneo del sistema operativo que acaba de funcionar. Pero
  // «no lo pude leer» y «ya no esta» son cosas distintas, y hasta ahora
  // llegaban iguales al diff: los certificados del almacen ilegible
  // faltaban de `items` y salian como BAJAS — el control plane los
  // marcaba retirados y las alertas de desaparicion se disparaban por
  // certificados que seguian en disco. Se llamo «baja fantasma».
  //
  // Ahora cada colector nombra los almacenes que existen y no leyo
  // (`unreadable`), y un colector que falla entero sin poder nombrar los
  // suyos deja una razon en `unscoped`. Con eso: las bajas de esos
  // almacenes no viajan y su baseline se arrastra; con `unscoped` no
  // viaja NINGUNA baja (misma regla que el recorte). Y el bloque
  // `partial` va al cable para que el baseline completo tampoco las
  // afirme en el control plane.
  const unreadable: CdpUnreadableStore[] = [];
  const unscoped: string[] = [];

  try {
    if (platform === "win32") {
      result = await collectWindowsCdp(ctx);
      const win = result as any;
      if (win.userStoresUnavailable) {
        unreadable.push({ id: "user/", name: "CurrentUser\\", reason: String(win.userStoresUnavailable), prefix: true });
      }
    } else if (platform === "darwin") {
      result = await collectMacosCdp();
      unreadable.push(...(((result as any).unreadable ?? []) as CdpUnreadableStore[]));
      // Que el sintoma llegue al log y no se quede en el tipo. Si root
      // no pudiera leer los login keychains de otros usuarios —el caso
      // de produccion, que no se ha podido verificar en un Mac de un
      // solo perfil— esto lo dice en vez de devolver cero en silencio.
      {
        const lk = (result as any).loginKeychains;
        if (lk && lk.discovered > 0 && lk.read < lk.discovered) {
          ctx.logger?.warn?.("CDP: login keychains encontrados pero no leidos", {
            discovered: lk.discovered,
            read: lk.read
          });
        }
      }
    } else if (platform === "linux") {
      result = await collectLinuxCdp();
      unreadable.push(...(((result as any).unreadable ?? []) as CdpUnreadableStore[]));
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
    unreadable.push(...(java.unreadable ?? []));
  } catch (err: any) {
    ctx.logger?.warn?.("CDP: java store collection failed (non-fatal)", {
      error: err?.message || String(err)
    });
    unscoped.push(`java-store: ${err?.message || String(err)}`);
  }

  // Almacenes NSS (Firefox, Thunderbird). Fallo blando como los
  // anteriores: Firefox tiene su PROPIO almacén de confianza, así que
  // una CA importada ahí es invisible para todo lo demás — pero una
  // base bloqueada no puede costar el escaneo del sistema operativo que
  // acaba de funcionar.
  try {
    const { collectNssStores } = await import("./providers/nss");
    const nss = await collectNssStores();
    result.items.push(...nss.items);
    result.stores.push(...nss.stores);
    result.parseFailures += nss.parseFailures;
    unreadable.push(...(nss.unreadableStores ?? []));
    if (nss.unreadable.length > 0) {
      // Se DICE. Un cert8.db heredado o una base bloqueada significan un
      // almacen de confianza que no estamos mirando, y el silencio ahi
      // seria el cuarto punto ciego de este plugin.
      ctx.logger?.warn?.("CDP: bases NSS no leidas", { unreadable: nss.unreadable });
    }
  } catch (err: any) {
    ctx.logger?.warn?.("CDP: coleccion NSS fallo (no fatal)", {
      error: err?.message || String(err)
    });
    unscoped.push(`nss: ${err?.message || String(err)}`);
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
      for (const f of files.unreadableFiles ?? []) {
        unreadable.push({ id: `file:${f}`, name: f, reason: "unreadable" });
      }
      // Un directorio que existe y no se lista, o el tope de ficheros,
      // esconden almacenes que no se pueden nombrar.
      if ((files.unreadableDirs ?? []).length > 0) {
        unscoped.push(`file: unreadable directories: ${files.unreadableDirs.slice(0, 5).join(", ")}`);
      }
      if (files.capped) unscoped.push("file: scan capped at MAX_FILES");
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
      unscoped.push(`file: ${err?.message || String(err)}`);
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
      unscoped.push(`listener: ${err?.message || String(err)}`);
    }
  }

  // Rol Probe (fase 2): objetivos TLS remotos que el operador escribio
  // en la policy. Sin objetivos no abre un solo socket. Fallo blando como
  // todo lo anterior: una sonda que cuelga no puede costar el inventario
  // del propio equipo.
  // Llamada opcional a proposito: un runtime que no conozca el metodo —una
  // policy vieja, o un doble de test— equivale a «sin objetivos», y eso no
  // puede tumbar el escaneo del propio equipo, que ya termino bien.
  if ((ctx.policyRuntime.getCdpProbeTargets?.() ?? []).length > 0) {
    try {
      const { collectTlsProbes } = await import("./providers/tls-probes");
      const probes = await collectTlsProbes(ctx);
      result.items.push(...probes.items);
      result.stores.push(...probes.stores);
      result.parseFailures += probes.parseFailures;
    } catch (err: any) {
      ctx.logger?.warn?.("CDP: sondas TLS remotas fallaron (no fatal)", {
        error: err?.message || String(err)
      });
      unscoped.push(`probe: ${err?.message || String(err)}`);
    }
  }

  // Conector AD CS (fase 4): solo en Windows, solo si la policy lo pide,
  // y en un bloque propio del namespace — lo emitido por una CA no esta
  // EN este equipo. Fallo blando.
  let adcs: CdpAdcsReport | undefined;
  if (platform === "win32" && ctx.policyRuntime.getCdpAdcs?.()?.enabled) {
    try {
      const { collectAdcs } = await import("./providers/adcs");
      adcs = await collectAdcs(ctx);
    } catch (err: any) {
      ctx.logger?.warn?.("CDP/ADCS: conector fallo (no fatal)", { error: err?.message || String(err) });
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

  // Escaneo parcial (ver arriba). Con almacenes nombrados, solo SUS bajas
  // se retiran del delta y su ultimo contenido conocido se arrastra en
  // la baseline; sin poder nombrarlos, ninguna baja viaja.
  const partial = unreadable.length > 0 || unscoped.length > 0 ? { unreadableStores: unreadable, unscoped } : undefined;
  let carried: CdpCertItem[] = [];
  if (partial) {
    if (unscoped.length > 0 && delta) {
      delta.removed = [];
    } else if (unreadable.length > 0) {
      const match = (storeId: string) => unreadable.some((u) => (u.prefix ? storeId.startsWith(u.id) : storeId === u.id));
      carried = loadCdpBaselineItemsByStore(match, new Set(items.map((i) => i.id)));
      if (delta && carried.length > 0) {
        const keep = new Set(carried.map((i) => i.id));
        delta.removed = delta.removed.filter((r) => !keep.has(r.id));
      }
    }
    ctx.logger?.warn?.("CDP: escaneo parcial — no se afirman bajas de los almacenes no leidos", {
      unreadable: unreadable.map((u) => `${u.id}${u.prefix ? "*" : ""}: ${u.reason}`),
      unscoped,
      carried: carried.length
    });
  }

  // ADR-0011 fase 0, paso 1 — el estado del pin de anclas viaja con el
  // inventario de criptografía, que es donde un operador ya mira.
  //
  // Fallo blando como el resto de colectores: un PrivSvc antiguo
  // responde `not_supported` y eso NO puede costar el escaneo que acaba
  // de funcionar. Ausente ≠ «sin anclas»; el backend lo distingue.
  const anchorPin = await collectAnchorPin(ctx);

  const isBaselineSend = delta === null;
  const anchorChanged = anchorPin
    ? cdpAnchorDigestChanged(hashCdpAnchorState(anchorPin))
    : false;
  // Emisiones nuevas de la CA cuentan como cambio: si no, el planificador
  // descartaria el namespace entero y el bloque `adcs` no viajaria nunca
  // en una CA cuyo propio almacen no cambia (la trampa de `hasChanges`).
  const adcsChanged = (adcs?.issued.length ?? 0) > 0;
  // Los DOS disparadores de las ramas fusionadas: el pin de anclas (main)
  // y las emisiones de AD CS (Agent-Fixes). Quedarse con uno solo dejaria
  // su bloque sin viajar cuando el almacen local no cambia.
  const hasChanges = isBaselineSend
    ? true
    : anchorChanged ||
      adcsChanged ||
      delta.added.length > 0 ||
      delta.removed.length > 0 ||
      delta.updated.length > 0;

  // Commit AFTER diffing so `removed` is computed against the previous
  // scan. Committing here (vs after enqueue) mirrors AMP: the outbox is
  // local SQLite and its enqueue effectively cannot fail.
  if (hasChanges) {
    // Los arrastrados siguen en la baseline: cuando el almacen vuelva a
    // leerse, lo que siga igual no sera alta y lo que falte si sera baja.
    commitCdpBaseline(carried.length > 0 ? [...items, ...carried] : items);
    // El digest se confirma junto a la línea base y solo cuando de
    // verdad se va a enviar: adelantarlo haría que un envío descartado
    // aguas arriba se diera por reportado, y el cambio de pin se
    // perdería para siempre.
    if (anchorPin) commitCdpAnchorDigest(hashCdpAnchorState(anchorPin));
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
    },
    ...(anchorPin ? { anchorPin } : {}),
    ...(partial ? { partial } : {}),
    ...(adcs ? { adcs } : {})
  };
}

/**
 * Pide al PrivSvc el estado del pin de anclas.
 *
 * ⚠️ Va por IPC y no leyendo el fichero: en macOS `CERT_DIR` es 0700 de
 * root, y el repo evita a propósito una superficie de privilegio
 * parcial. El método es de solo lectura y aun así exige root, igual que
 * el resto de `cdp.*`.
 */
async function collectAnchorPin(ctx: AgentContext): Promise<CdpAnchorPinReport | undefined> {
  try {
    const resp = await ctx.priv.call({
      v: 1,
      id: `cdpanchorstate_${Date.now()}`,
      method: "cdp.anchor.state",
      params: {},
      meta: {
        tenantId: ctx.enrollment?.tenantId,
        deviceId: ctx.enrollment?.deviceId
      }
    });
    if (!resp?.ok) {
      // `not_supported` es lo esperado en un PrivSvc anterior a esto, y
      // no merece un warn en cada ciclo de toda la flota.
      if (resp?.error?.code !== "not_supported") {
        ctx.logger?.warn?.("CDP: estado del pin de anclas no disponible", {
          code: resp?.error?.code,
          message: resp?.error?.message
        });
      }
      return undefined;
    }
    return resp.result as CdpAnchorPinReport;
  } catch (err: any) {
    ctx.logger?.warn?.("CDP: fallo pidiendo el estado del pin de anclas (no fatal)", {
      error: err?.message || String(err)
    });
    return undefined;
  }
}
