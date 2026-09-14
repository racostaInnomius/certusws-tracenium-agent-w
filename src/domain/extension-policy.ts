// src/domain/extension-policy.ts
//
// Gobierno de extensiones de Chrome y Edge por directiva de máquina.
//
// ── Qué pide el control plane ────────────────────────────────────────
//
//   policy.browserExtensions = {
//     chrome: { blocklist: ["<id>", "*"], allowlist: ["<id>"] },
//     edge:   { blocklist: [...],        allowlist: [...] }
//   }
//
// `*` en la blocklist es "bloquear todo lo que no esté en la allowlist".
//
// ── Cómo lo lee el navegador, y por qué esto no es el escritor genérico ─
//
// Chromium lee una directiva de LISTA como valores numerados bajo su clave:
// `HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist` con
// "1" = id, "2" = id… Escribir "el valor X" no sirve: hay que AÑADIR a lo
// que ya haya (una GPO, otra herramienta) y, al retirar, COMPACTAR para no
// dejar huecos en la numeración. Eso es leer-planificar-escribir, y el plan
// es este fichero, puro y con tests.
//
// ── Lo que es nuestro y lo que no ────────────────────────────────────
//
// El agente recuerda qué ids AÑADIÓ él (`owned`). Al retirar una regla sólo
// quita esos: un id que ya estaba puesto por una GPO se queda aunque el
// portal deje de pedirlo, porque no lo pusimos nosotros.

export type ChromiumBrowser = "chrome" | "edge";
export type PolicyListKind = "blocklist" | "allowlist";

export const CHROMIUM_BROWSERS: readonly ChromiumBrowser[] = ["chrome", "edge"];
export const POLICY_LISTS: readonly PolicyListKind[] = ["blocklist", "allowlist"];

export type ExtensionPolicy = Record<ChromiumBrowser, Record<PolicyListKind, string[]>>;

/** Tope por lista: Chromium no tiene uno, pero un bloque así sería un error. */
export const MAX_POLICY_ENTRIES = 1000;

const EXTENSION_ID = /^[a-p]{32}$/;

export function emptyExtensionPolicy(): ExtensionPolicy {
  return { chrome: { blocklist: [], allowlist: [] }, edge: { blocklist: [], allowlist: [] } };
}

/**
 * El bloque tal y como llega, validado y FALLANDO CERRADO en lo que no se
 * entiende: una entrada inválida se descarta, nunca se escribe. `*` sólo
 * vale en la blocklist (en la allowlist permitiría todo, que es no tener
 * directiva).
 */
export function parseExtensionPolicy(raw: unknown): ExtensionPolicy {
  const out = emptyExtensionPolicy();
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
  for (const browser of CHROMIUM_BROWSERS) {
    const b = (raw as any)[browser];
    if (!b || typeof b !== "object" || Array.isArray(b)) continue;
    for (const list of POLICY_LISTS) {
      const values = Array.isArray(b[list]) ? b[list] : [];
      const seen = new Set<string>();
      for (const v of values) {
        if (typeof v !== "string") continue;
        const id = v.trim();
        const ok = EXTENSION_ID.test(id) || (list === "blocklist" && id === "*");
        if (ok && !seen.has(id)) seen.add(id);
        if (seen.size >= MAX_POLICY_ENTRIES) break;
      }
      out[browser][list] = [...seen];
    }
  }
  // Un id no puede estar en las dos: gana el bloqueo, que es lo seguro.
  for (const browser of CHROMIUM_BROWSERS) {
    const blocked = new Set(out[browser].blocklist);
    out[browser].allowlist = out[browser].allowlist.filter((id) => !blocked.has(id));
  }
  return out;
}

export type PolicyListPlan = {
  /** La lista entera a escribir, en orden, como "1".."N". */
  next: string[];
  changed: boolean;
  /** Ids que este plan añade y que pasan a ser nuestros. */
  added: string[];
  /** Ids nuestros que el portal ya no pide y este plan quita. */
  removed: string[];
  /** Lo que queda anotado como nuestro tras aplicar el plan. */
  owned: string[];
  /** Entradas que ya estaban y no son nuestras (GPO u otra herramienta). */
  foreign: string[];
};

/**
 * `current` es la lista tal y como está en el registro (valores "1".."N" en
 * orden). `desired`, lo que pide la política. `owned`, lo que añadimos en
 * pasadas anteriores.
 */
export function planPolicyList(current: string[], desired: string[], owned: string[]): PolicyListPlan {
  const want = new Set(desired);
  const mine = new Set(owned);
  const next: string[] = [];
  const removed: string[] = [];
  const present = new Set<string>();

  for (const id of current) {
    if (present.has(id)) continue; // duplicados en el registro: se compactan
    if (mine.has(id) && !want.has(id)) {
      removed.push(id);
      continue;
    }
    next.push(id);
    present.add(id);
  }

  const added: string[] = [];
  for (const id of desired) {
    if (present.has(id)) continue;
    next.push(id);
    present.add(id);
    added.push(id);
  }

  const newOwned = desired.filter((id) => present.has(id) && (mine.has(id) || added.includes(id)));
  const foreign = next.filter((id) => !newOwned.includes(id));
  const changed = next.length !== current.length || next.some((v, i) => v !== current[i]);
  return { next, changed, added, removed, owned: newOwned, foreign };
}
