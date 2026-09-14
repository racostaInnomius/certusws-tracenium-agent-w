// src/plugins/amp/providers/extension-policy-enforcer.ts
//
// Lleva las listas de extensiones de Chrome y Edge del registro a lo que pide
// la política. Se ejecuta en cada ciclo de inventario de Windows, ANTES de
// leer las extensiones: así el mismo FACTS lleva el resultado y, en cuanto el
// navegador aplica la directiva, la extensión bloqueada desaparece del
// inventario — que es la confirmación que ve el operador.
//
// Cada ciclo re-lee y re-planifica, así que también repara: si una GPO o una
// persona borra la clave, la siguiente pasada vuelve a poner lo nuestro.
//
// Por lista (navegador × blocklist/allowlist), independiente: un fallo en una
// no impide las otras.

import type { IPrivSvcClient } from "../../../core/agent-context";
import {
  CHROMIUM_BROWSERS,
  POLICY_LISTS,
  planPolicyList,
  type ChromiumBrowser,
  type ExtensionPolicy,
  type PolicyListKind,
} from "../../../domain/extension-policy";

export type PolicyListResult = {
  browser: ChromiumBrowser;
  list: PolicyListKind;
  /** written | unchanged | conflict | error */
  status: "written" | "unchanged" | "conflict" | "error";
  /** Ids que la política pide y quedan en la lista. */
  present: string[];
  /** Entradas que no son nuestras (GPO u otra herramienta). */
  foreign: number;
  error?: string;
};

export type OwnedStore = {
  load(browser: ChromiumBrowser, list: PolicyListKind): string[];
  save(browser: ChromiumBrowser, list: PolicyListKind, owned: string[], nowUtc: string): void;
};

async function call(priv: IPrivSvcClient, method: string, params: Record<string, unknown>): Promise<any> {
  const resp = await priv.call({ method, params });
  if (!resp?.ok) throw new Error(resp?.error?.code ? `${resp.error.code}: ${resp.error.message ?? ""}`.trim() : "privsvc call failed");
  return resp.result;
}

export async function enforceExtensionPolicy(opts: {
  priv: IPrivSvcClient;
  policy: ExtensionPolicy;
  owned: OwnedStore;
  now?: () => string;
}): Promise<PolicyListResult[]> {
  const now = opts.now ?? (() => new Date().toISOString());
  const results: PolicyListResult[] = [];

  for (const browser of CHROMIUM_BROWSERS) {
    for (const list of POLICY_LISTS) {
      const desired = opts.policy[browser][list];
      const owned = opts.owned.load(browser, list);
      // Nada que pedir y nada nuestro que retirar: ni se lee el registro.
      if (desired.length === 0 && owned.length === 0) continue;

      try {
        const read = await call(opts.priv, "browser.policy_list.read", { browser, list });
        const current: string[] = Array.isArray(read?.entries) ? read.entries.filter((x: unknown): x is string => typeof x === "string") : [];
        const plan = planPolicyList(current, desired, owned);

        if (!plan.changed) {
          opts.owned.save(browser, list, plan.owned, now());
          results.push({ browser, list, status: "unchanged", present: desired.filter((id) => plan.next.includes(id)), foreign: plan.foreign.length });
          continue;
        }

        const written = await call(opts.priv, "browser.policy_list.write", { browser, list, expected: current, entries: plan.next });
        if (written?.status === "conflict") {
          // Alguien la tocó entre la lectura y la escritura: no se anota nada.
          results.push({ browser, list, status: "conflict", present: [], foreign: plan.foreign.length });
          continue;
        }
        opts.owned.save(browser, list, plan.owned, now());
        const after: string[] = Array.isArray(written?.entries) ? written.entries : plan.next;
        results.push({
          browser,
          list,
          status: written?.status === "unchanged" ? "unchanged" : "written",
          present: desired.filter((id) => after.includes(id)),
          foreign: plan.foreign.length,
        });
      } catch (err: any) {
        results.push({ browser, list, status: "error", present: [], foreign: 0, error: String(err?.message || err).slice(0, 200) });
      }
    }
  }
  return results;
}
