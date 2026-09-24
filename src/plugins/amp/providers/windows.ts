// src/plugins/amp/providers/windows.ts
import os from "os";
import si from "systeminformation";
import type { AgentContext } from "../../../core/agent-context";
import { normalizeApp } from "../../../domain/normalize-app";
import { installedOnFromWindowsRegistry } from "../../../domain/install-date";
import { computeSoftwareDelta, toBaselineOps } from "../../../domain/software-inventory-delta";
import { loadSoftwareBaseline, upsertSoftwareBaseline, deleteSoftwareByIds } from "../../../domain/software-baseline-repo";
import type { AmpNamespace } from "../../../domain/amp-types";
import { readBootTime } from "../../../domain/boot-time";
import type { SoftwareApplication } from "../../../domain/normalize-app";
import { collectWindowsPrinters } from "./printers-windows";
import {
  buildPrinterInventoryWithBaseline,
  emptyPrinterInventory
} from "./printers-pipeline";
import { collectBrowserExtensionInventory } from "./browser-extensions-pipeline";
import { enforceExtensionPolicy, type PolicyListResult } from "./extension-policy-enforcer";
import { loadOwnedEntries, saveOwnedEntries } from "../../../domain/extension-policy-owned-repo";

// Verbose inventory diagnostics (raw counts, delta summaries, payload
// size estimates) — useful during development, noisy in production.
// Gate behind DEBUG_INVENTORY=1 so the default stdout stays readable.
const INVENTORY_DEBUG =
  process.env.DEBUG_INVENTORY === "1" || process.env.DEBUG_INVENTORY === "true";

function invDebug(...args: any[]) {
  if (INVENTORY_DEBUG) console.log(...args);
}

// Lo que el PrivSvc devuelve por IPC. Es un `as RawApp[]` sobre JSON crudo, así
// que este tipo no valida nada: describe lo que ESPERAMOS. Un campo que el
// colector manda y que no esté declarado aquí es invisible para el resto del
// fichero — la tercera de las tres listas que hay que tocar para que un campo
// nuevo del inventario llegue de verdad al backend.
type RawApp = {
  name?: string | null;
  version?: string | null;
  publisher?: string | null;
  installLocation?: string | null;
  packageFamilyName?: string | null;
  source?: string | null;

  // ADR-0019 F0 — sólo los emite `win32-registry`.
  uninstallString?: string | null;
  quietUninstallString?: string | null;
  productCode?: string | null;
  uninstallKeyPath?: string | null;

  // Crudo: "yyyyMMdd", "yyyy-MM-dd", un DWORD con epoch o basura. Se
  // interpreta abajo con installedOnFromWindowsRegistry.
  installDate?: string | number | null;
};

/**
 * L2: device + hardware (non-privileged reads via systeminformation)
 */
async function collectWindowsDeviceAndHardware(): Promise<
  Pick<AmpNamespace, "hardware">
> {
  const [osInfo, system, cpu, mem, diskLayout, fsSize] = await Promise.all([
    si.osInfo(),
    si.system(),
    si.cpu(),
    si.mem(),
    si.diskLayout().catch(() => [] as any[]),
    si.fsSize().catch(() => [] as any[])
  ]);

  return {
    hardware: {
      static: {
        system: {
          manufacturer: system.manufacturer || undefined,
          model: system.model || undefined,
          version: system.version || undefined,
          serial: system.serial || undefined,
          uuid: system.uuid || undefined,
          virtual: Boolean((system as any).virtual)
        } as any,
        cpu: {
          manufacturer: cpu.manufacturer || undefined,
          brand: cpu.brand || undefined,
          cores: cpu.cores || undefined,
          physicalCores: cpu.physicalCores || undefined
        } as any,
        memLayout: undefined,
        diskLayout: diskLayout || undefined
      } as any,
      runtime: {
        mem: mem ? { total: mem.total } : undefined,
        fsSize: fsSize || undefined,
        // Cuando arrancó el sistema. `os.uptime()` no abre ningún proceso; ver
        // boot-time.ts para por qué viajan las DOS cifras y no una sola.
        ...readBootTime({ nowMs: Date.now(), uptimeSeconds: os.uptime() })
      } as any
    }
  };
}

/**
 * L2: security posture should come from PrivSvc (admin boundary).
 * For now we attempt a call if implemented; otherwise default to "unknown".
 */
async function collectWindowsSecurity(ctx: AgentContext): Promise<AmpNamespace["security"]> {
  const unknown: AmpNamespace["security"] = {
    bitlocker: { status: "unknown" },
    defender: { status: "unknown" },
    firewall: { status: "unknown" }
  };

  // If PrivSvc isn't available yet (or method not implemented), keep unknown.
  try {
    const resp = await ctx.priv.call({
      v: 1,
      id: `sec_${Date.now()}`,
      method: "security.compliance",
      params: { includeBitlocker: true, includeDefender: true, includeFirewall: true },
      meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
    });

    if (!resp.ok) return unknown;

    const r = resp.result || {};
    return {
      bitlocker: r.bitlocker ?? unknown.bitlocker,
      defender: r.defender ?? unknown.defender,
      firewall: r.firewall ?? unknown.firewall
    };
  } catch {
    return unknown;
  }
}

export async function collectWindowsSoftwareInventory(ctx: AgentContext) {
  const resp = await ctx.priv.call({
    v: 1,
    id: `inv_${Date.now()}`,
    method: "software.inventory",
    params: { includeStoreApps: true },
    meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
  });

  // FIX: support both "apps" (old contract) and "items" (current PrivSvc contract)
  const apps = (resp.result?.items ?? resp.result?.apps ?? []) as RawApp[];

  invDebug("[WINDOWS] RAW INVENTORY", {
    hasItems: Array.isArray(resp.result?.items),
    hasApps: Array.isArray(resp.result?.apps),
    countItems: resp.result?.items?.length,
    countApps: resp.result?.apps?.length
  });

  if (!resp.ok) {
    throw new Error(
      `PrivSvc inventory failed: ${resp.error?.code} ${resp.error?.message}`
    );
  }

  const normalized = apps
    .map((a) =>
      normalizeApp({
        name: a.name ?? null,
        version: a.version ?? null,
        publisher: a.publisher ?? null,
        installLocation: a.installLocation ?? null,
        packageFamilyName: a.packageFamilyName ?? null,
        source: a.source ?? "win32-registry",

        // ── ADR-0019 F0 ────────────────────────────────────────────
        //
        // ⚠️ ESTE OBJETO SE ARMA CAMPO A CAMPO, así que es un filtro: lo
        // que no se nombre aquí NO llega, aunque el PrivSvc lo mande y
        // aunque el backend tenga columna para guardarlo.
        //
        // Fue exactamente lo que pasó: `SoftwareInventory.cs` emitía los
        // cuatro desde 1.1.65, y con 52 equipos ya en esa versión las
        // cuatro columnas seguían en cero — se caían aquí.
        uninstallString: a.uninstallString ?? null,
        quietUninstallString: a.quietUninstallString ?? null,
        productCode: a.productCode ?? null,
        uninstallKeyPath: a.uninstallKeyPath ?? null,

        // ⚠️ Mismo filtro: sin esta línea la fecha se lee en el PrivSvc y
        // muere aquí.
        installedOn: installedOnFromWindowsRegistry(a.installDate) ?? null
      })
    )
    .filter((x) => x && x.name);

  invDebug("[WINDOWS] NORMALIZED INVENTORY", {
    inputCount: apps.length,
    normalizedCount: normalized.length
  });

  return {
    count: normalized.length,
    apps: normalized
  };
}

export const windowsProvider = {
  async collect(ctx: AgentContext): Promise<AmpNamespace> {
    if (os.platform() !== "win32") {
      throw new Error("windowsProvider.collect() called on non-Windows platform");
    }

    // Device + hardware should be reliable even if PrivSvc is down.
    const base = await collectWindowsDeviceAndHardware();

    // Security + software rely on PrivSvc; degrade gracefully.
    let security: AmpNamespace["security"] = {
      bitlocker: { status: "unknown" },
      defender: { status: "unknown" },
      firewall: { status: "unknown" }
    };

    let software: AmpNamespace["software"] = {
      count: 0,
      items: undefined,
      delta: null,
      hasChanges: false
    };

    try {
      security = await collectWindowsSecurity(ctx);
    } catch {
      // keep unknown
    }

    // ⚠️ Las impresoras se recogen AQUÍ, ANTES del software, y no después.
    //
    // El bloque de software de abajo tiene un `return` temprano cuando no hay
    // cambios —el caso normal en una flota estable—, así que con las
    // impresoras detrás la función salía sin ellas y el colector NI SIQUIERA
    // se ejecutaba. Medido el 07-sep: CERO equipos Windows con impresoras en
    // los cuatro tenants, con agentes 1.1.54 a 1.1.61, mientras los macOS del
    // mismo tenant y la misma versión sí las reportaban. Los tres `return` de
    // este colector las llevan ahora.
    //
    // macOS y Linux ya lo hacían así, y el comentario que lo explica lleva
    // meses en macos.ts. Esta es la misma lección, aprendida dos veces.
    //
    // Su propio try/catch: un fallo leyendo impresoras no puede envenenar el
    // resto del namespace AMP.
    let printers = emptyPrinterInventory();
    try {
      const lectura = await collectWindowsPrinters(ctx);
      printers = buildPrinterInventoryWithBaseline(lectura.printers, {
        machineScope: lectura.machineScope,
        userScope: lectura.userScope
      });
    } catch (err: any) {
      // ⚠️ Y se DECLARA que no se pudo mirar, en vez de mandar un cero que
      // se lee como un hecho sobre el equipo.
      ctx.logger?.warn?.("[printers] collection failed, scope unavailable", {
        error: err?.message || String(err)
      });
      printers = { ...printers, machineScope: "unavailable", userScope: "unavailable" };
    }

    // Gobierno de extensiones ANTES de leerlas: el mismo FACTS lleva lo que se
    // aplicó. Nunca lanza; un fallo por lista queda en su resultado.
    let extensionPolicy: PolicyListResult[] = [];
    try {
      // Sin bloque en la política no se toca el registro (ni para retirar).
      extensionPolicy = await enforceExtensionPolicy({
        priv: ctx.priv,
        policy: ctx.policyRuntime.browserExtensionPolicy(),
        owned: { load: loadOwnedEntries, save: saveOwnedEntries },
      });
    } catch (err: any) {
      ctx.logger?.warn?.("[extensionPolicy] enforcement failed", { error: err?.message || String(err) });
    }

    // Extensiones de navegador: mismo lugar que las impresoras, y por lo mismo.
    const browserExtensions = {
      ...collectBrowserExtensionInventory("win32", (m, meta) => ctx.logger?.warn?.(m, meta)),
      ...(extensionPolicy.length > 0 ? { policy: extensionPolicy } : {}),
    };

    try {
      const result = await collectWindowsSoftwareInventory(ctx);
      // ensure typing
      const apps: SoftwareApplication[] = result.apps as SoftwareApplication[];

      if (!apps || apps.length === 0) {
        console.warn("[AGENT] EMPTY INVENTORY RECEIVED — CLEARING BASELINE");

        const previous: SoftwareApplication[] = loadSoftwareBaseline() ?? [];
        const ids = previous
          .map(x => x.installId)
          .filter((id): id is string => Boolean(id));
        deleteSoftwareByIds(ids);

        return {
          hardware: base.hardware,
          security,
          printers,
          browserExtensions,
          software: {
            count: 0,
            items: [],
            delta: null,
            hasChanges: true
          }
        };
      }

      invDebug("[AGENT] INVENTORY BEFORE BASELINE", {
        count: apps.length,
        //sample: apps.slice(0, 3)
      });

      // Ensure deterministic ordering before delta + hashing
      apps.sort((a: SoftwareApplication, b: SoftwareApplication) =>
        (a.installId ?? "").localeCompare(b.installId ?? "")
      );

      const previous: SoftwareApplication[] = loadSoftwareBaseline() ?? [];
      const isFirstRun = previous.length === 0;

      if (isFirstRun) {
        invDebug("[AGENT] SOFTWARE BASELINE (first run)", {
          count: apps.length
        });

        software = {
          count: apps.length,
          items: apps,
          delta: null,
          hasChanges: true
        };

        upsertSoftwareBaseline(apps);

      } else {
        const deltaResult = computeSoftwareDelta(apps, previous);

        if (deltaResult.hasChanges) {
          invDebug("[AGENT] SOFTWARE DELTA", {
            added: deltaResult.delta?.added?.length ?? 0,
            removed: deltaResult.delta?.removed?.length ?? 0,
            updated: deltaResult.delta?.updated?.length ?? 0
          });

          const { upserts, deletes } = toBaselineOps(deltaResult.delta);

          if (upserts.length > 0) {
            upsertSoftwareBaseline(upserts);
          }

          if (deletes.length > 0) {
            deleteSoftwareByIds(deletes);
          }

          // ── Phase B: drop items[] when sending a delta ─────────
          //
          // The backend's `software_current_app` projection
          // (modules/db/migrations/20260514_software_current_app.sql)
          // is maintained incrementally from delta.added / removed /
          // updated. With that path live, re-sending the full apps[]
          // on every change wastes bandwidth: a typical Windows host
          // with 40 apps reships ~5 KB of identical metadata for a
          // single 1-app delta. The audit said 99% of software_
          // inventory rows pre-Phase-B were full snapshots, 76% of
          // which were duplicates of the prior row.
          //
          // DEPLOY ORDER REQUIREMENT: the matching backend (which
          // ALSO landed in this release) must be deployed BEFORE
          // agents running this code start phoning home. An older
          // backend that doesn't know about software_current_app
          // and only reads software_payload->'items' would render
          // empty inventory for these devices. The backend ships
          // first in the rollout sequence; this code only takes
          // effect when the bundled-agent version updates.
          //
          // Note (Aug 2025 / pre-Phase-B comment): the previous code
          // had a "CRITICAL: NEVER drop items" comment here, which
          // documented the OLD invariant (server reconstructed
          // current state from the latest snapshot's items[]). That
          // invariant no longer holds — current state lives in
          // software_current_app, server-side, maintained
          // incrementally.
          software = {
            count: deltaResult.currentCount,
            items: undefined,
            delta: deltaResult.delta,
            hasChanges: true
          };
        } else {
          invDebug("[AGENT] SOFTWARE NO CHANGES — SKIP PAYLOAD");

          software = {
            count: deltaResult.currentCount,
            items: undefined, // avoid affecting baseline hash / payload
            delta: null,
            hasChanges: false
          };

          // Do not update baseline, do not trigger downstream send
          return {
            hardware: base.hardware,
            security,
            software,
            printers,
            browserExtensions
          };
        }
      }

      invDebug("[AGENT] software payload ready", {
        count: software.count,
        hasItems: !!software.items,
        items: software.items?.length,
        hasDelta: !!software.delta
      });

      invDebug("[AGENT] payload size estimate (software only)", {
        approxBytes: JSON.stringify(software).length
      });

    } catch {
      // keep empty
    }

    return {
      hardware: base.hardware,
      security,
      software,
      printers,
      browserExtensions
    };
  }
};
