// src/plugins/cdp/providers/windows.ts
//
// Windows CDP collector. Certificate stores are enumerated by PrivSvc
// (C# X509Store — native, no PowerShell spawn) via the `cdp.certs.read`
// IPC method. PrivSvc returns raw DER (base64) + store context +
// hasPrivateKey flag per cert; parsing happens here with the shared
// parse-cert helper so all three platforms produce identical items.
//
// PrivSvc NEVER exports key material — hasPrivateKey is the
// X509Certificate2.HasPrivateKey attribute, nothing more.

import type { AgentContext } from "../../../core/agent-context";
import type { CdpCertItem, CdpStoreInfo } from "../../../domain/cdp-types";
import { parseCertToItem } from "../parse-cert";

// LocalMachine stores scanned in Phase A. CurrentUser stores need
// per-session enumeration and are deferred to Phase C.
const MACHINE_STORES = ["My", "WebHosting", "CA", "TrustedPeople", "TrustedPublisher"];
const ROOT_STORES = ["Root", "AuthRoot"];

export type WindowsCdpResult = {
  items: CdpCertItem[];
  stores: CdpStoreInfo[];
  parseFailures: number;
};

export async function collectWindowsCdp(ctx: AgentContext): Promise<WindowsCdpResult> {
  const resp = await ctx.priv.call({
    v: 1,
    id: `cdp_${Date.now()}`,
    method: "cdp.certs.read",
    params: {
      stores: [...MACHINE_STORES, ...ROOT_STORES]
    },
    meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
  });

  if (!resp?.ok) {
    throw new Error(resp?.error?.message || "cdp.certs.read failed");
  }

  // A scan that ran out of its handler budget is a FAILED scan, not a
  // short one. PrivSvc still returns what it managed to read, but that
  // payload must never reach the projection: a CDP baseline reconciles,
  // so every certificate missing from a truncated list would be marked
  // removed — turning a slow host into a fleet of phantom deletions.
  // Throwing puts us on the collectorError path, where the control plane
  // keeps the last good projection. The count and elapsed time ride along
  // because "stopped at 412 certs after 45s" is a diagnosis and
  // "timeout" is not.
  if (resp.result?.budgetExceeded === true) {
    const seen = Array.isArray(resp.result?.certificates)
      ? resp.result.certificates.length
      : 0;
    throw new Error(
      `cdp.certs.read exceeded its handler budget: stopped after ${seen} ` +
        `certificate(s) in ${resp.result?.elapsedMs ?? "?"}ms`
    );
  }

  const rawCerts: Array<{
    store?: string;
    rawDerBase64?: string;
    hasPrivateKey?: boolean;
  }> = Array.isArray(resp.result?.certificates) ? resp.result.certificates : [];

  const items: CdpCertItem[] = [];
  const storesSeen = new Map<string, CdpStoreInfo>();
  let parseFailures = 0;

  for (const raw of rawCerts) {
    const storeName = String(raw?.store || "Unknown");
    const isRootStore = ROOT_STORES.includes(storeName);

    const store: CdpStoreInfo = {
      id: `lm/${storeName.toLowerCase()}`,
      name: `LocalMachine\\${storeName}`,
      scope: isRootStore ? "system-roots" : "machine"
    };
    storesSeen.set(store.id, store);

    if (!raw?.rawDerBase64) {
      parseFailures += 1;
      continue;
    }

    const item = parseCertToItem(Buffer.from(raw.rawDerBase64, "base64"), {
      store,
      hasPrivateKey: raw.hasPrivateKey === true
    });

    if (item) {
      items.push(item);
    } else {
      parseFailures += 1;
    }
  }

  // ── Stores por usuario ────────────────────────────────────────────
  //
  // Fallo blando y deliberado. Este metodo IPC es nuevo: un agente
  // actualizado contra un PrivSvc antiguo recibe `not_supported`, y eso
  // NO puede costar el escaneo de maquina que acaba de funcionar. Lo
  // mismo vale para cualquier otro fallo — los certificados de usuario
  // son un anadido, no un requisito.
  try {
    const userResp = await ctx.priv.call({
      v: 1,
      id: `cdpu_${Date.now()}`,
      method: "cdp.certs.readUser",
      params: {},
      meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
    });

    if (userResp?.ok && userResp.result?.budgetExceeded !== true) {
      const userCerts: Array<{ store?: string; userSid?: string; rawDerBase64?: string }> =
        Array.isArray(userResp.result?.certificates) ? userResp.result.certificates : [];

      for (const raw of userCerts) {
        if (!raw?.rawDerBase64) {
          parseFailures += 1;
          continue;
        }
        const storeName = String(raw?.store || "Unknown");
        const sid = String(raw?.userSid || "unknown");
        // El SID forma parte de la identidad del store: el mismo
        // certificado en el Personal de dos usuarios son dos
        // ubicaciones, no una.
        const store: CdpStoreInfo = {
          id: `user/${sid}/${storeName.toLowerCase()}`,
          name: `CurrentUser\\${storeName} (${sid})`,
          scope: "user"
        };
        storesSeen.set(store.id, store);

        const item = parseCertToItem(Buffer.from(raw.rawDerBase64, "base64"), {
          store,
          hasPrivateKey: false
        });
        if (item) items.push(item);
        else parseFailures += 1;
      }
    }
  } catch {
    // PrivSvc antiguo, o cualquier otro fallo. El escaneo de maquina ya
    // esta hecho y se entrega igual.
  }

  return { items, stores: [...storesSeen.values()], parseFailures };
}
