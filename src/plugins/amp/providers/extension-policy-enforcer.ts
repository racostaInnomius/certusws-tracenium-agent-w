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
import type { PrivSvcMethod } from "../../../priv/ipc-types";
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

/**
 * ⚠️ `v` e `id` iban sin poner, y esto NO se cayó por un detalle del otro lado.
 *
 * El DTO de C# declara `public int Version { get; set; } = 1`, así que en
 * Windows una petición sin `v` se acepta con el valor por defecto. Los routers
 * de Linux y macOS son TypeScript y comparan `req.v !== 1` contra un
 * `undefined`: la rechazan con `bad_version`. Este enforcer solo corre en
 * Windows (`amp/providers/windows.ts`), que es la única razón por la que
 * funciona — 108 acuses en T111 lo confirman.
 *
 * O sea: un latente, no un fallo vivo. Pero el día que esto se llame desde
 * macOS o Linux dejaría de aplicar la política **en silencio**, porque el
 * llamador captura la excepción y solo deja un `warn` en el equipo. Es
 * exactamente cómo se perdió el indicador de pantalla de Linux durante 24 días.
 *
 * `id` lo rellena el cliente si falta; `v` no lo rellena nadie.
 */
async function call(
  priv: IPrivSvcClient,
  method: Extract<PrivSvcMethod, `browser.policy_list.${string}`>,
  params: Record<string, unknown>
): Promise<any> {
  const resp = await priv.call({ v: 1, id: `${method}.${Date.now()}`, method, params });
  if (!resp?.ok) throw new Error(resp?.error?.code ? `${resp.error.code}: ${resp.error.message ?? ""}`.trim() : "privsvc call failed");
  return resp.result;
}

export async function enforceExtensionPolicy(opts: {
  priv: IPrivSvcClient;
  /** null = la política no trae el bloque: no se toca nada (ver parseExtensionPolicy). */
  policy: ExtensionPolicy | null;
  owned: OwnedStore;
  now?: () => string;
}): Promise<PolicyListResult[]> {
  const now = opts.now ?? (() => new Date().toISOString());
  const results: PolicyListResult[] = [];
  const policy = opts.policy;
  if (!policy) return results;

  for (const browser of CHROMIUM_BROWSERS) {
    for (const list of POLICY_LISTS) {
      const desired = policy[browser][list];
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
