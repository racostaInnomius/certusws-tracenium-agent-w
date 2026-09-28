// privsvc/macos/src/generic-config.ts
//
// `macos.config.set_value` — la remediación genérica de macOS. El backend
// (modules/patch-management/desired-state-macos.ts) decide qué escribir y lo
// simula contra el check; aquí se valida OTRA vez contra las mismas listas
// cerradas y se aplica con los comandos de CIS:
//
//   macpref   /usr/bin/defaults write|delete /Library/Preferences/<dominio>
//             (por cfprefsd: nunca se edita el plist a mano, que cfprefsd
//             tiene en caché y reescribiría)
//   pmset     /usr/bin/pmset -a <clave> <valor>
//   launchd   /bin/launchctl enable|disable system/<label> + bootstrap|bootout
//
// ⚠️ Sólo las claves que macOS respeta en /Library/Preferences. Las que
// sólo cumple un perfil (applicationaccess, Siri…) NO se escriben nunca:
// pondrían el check en verde sin cambiar nada. El backend las exporta como
// .mobileconfig.
//
// ── Estado ───────────────────────────────────────────────────────────
//
// Por escritura: qué hay en /Library/Preferences (para el revert) y qué ve
// una aplicación — NSUserDefaults, igual que la sonda —, y si lo impone un
// perfil. Si un perfil del cliente fija esa clave a otro valor, el valor
// local no sirve de nada: el job lo dice en vez de dar un «aplicado» que el
// siguiente escaneo desmentiría.

import { buildPrefScript, parsePmsetCustom, parsePrefResult, parseLaunchctlList } from "./macos-probes";

// ── Listas cerradas (espejo de desired-state-macos.ts) ───────────────

export const LOCAL_PREFS: Readonly<Record<string, ReadonlySet<string>>> = Object.freeze({
  "com.apple.SoftwareUpdate": new Set([
    "AutomaticCheckEnabled", "AutomaticDownload", "AutomaticallyInstallMacOSUpdates",
    "AutomaticallyInstallAppUpdates", "ConfigDataInstall", "CriticalUpdateInstall",
  ]),
  "com.apple.commerce": new Set(["AutoUpdate"]),
  "com.apple.loginwindow": new Set(["SHOWFULLNAME", "RetriesUntilHint", "autoLoginUser"]),
  "com.apple.mDNSResponder": new Set(["NoMulticastAdvertisements"]),
  "com.apple.locationmenu": new Set(["ShowSystemServices"]),
});

export const PMSET_KEYS: ReadonlySet<string> = new Set(["womp", "powernap"]);

/** Servicio → la guarda si DESACTIVARLO deja a alguien sin algo. */
export const LAUNCHD_SERVICES: Readonly<Record<string, string | null>> = Object.freeze({
  "com.apple.auditd": null,
  "org.apache.httpd": null,
  "com.apple.ODSAgent": null,
  "com.apple.smbd": "turns off File Sharing",
  "com.apple.screensharing": "turns off Screen Sharing",
});

export type MacWrite =
  | { kind: "macpref"; domain: string; key: string; value: boolean | number | string | null }
  | { kind: "pmset"; key: string; value: number }
  | { kind: "launchd"; label: string; enabled: boolean };

export type Check<T> = { ok: true; value: T } | { ok: false; message: string };

const isObj = (v: unknown): v is Record<string, any> => !!v && typeof v === "object" && !Array.isArray(v);
const SAFE_STRING = /^[\x20-\x7e]{0,256}$/;

export function parseWrites(params: unknown): Check<MacWrite[]> {
  const raw = isObj(params) ? params.writes : undefined;
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > 64) return { ok: false, message: "params.writes must be a list of 1–64 writes" };
  const out: MacWrite[] = [];
  for (const [i, w] of raw.entries()) {
    const at = `writes[${i}]`;
    if (!isObj(w)) return { ok: false, message: `${at} is not an object` };
    if (w.kind === "macpref") {
      if (typeof w.domain !== "string" || typeof w.key !== "string" || !LOCAL_PREFS[w.domain]?.has(w.key)) {
        return { ok: false, message: `${at}: not a /Library/Preferences key Tracenium may write` };
      }
      const v = w.value;
      const okType = v === null || typeof v === "boolean" || (typeof v === "number" && Number.isInteger(v)) || (typeof v === "string" && SAFE_STRING.test(v));
      if (!okType) return { ok: false, message: `${at}: invalid value` };
      out.push({ kind: "macpref", domain: w.domain, key: w.key, value: v });
    } else if (w.kind === "pmset") {
      if (typeof w.key !== "string" || !PMSET_KEYS.has(w.key) || !Number.isInteger(w.value) || w.value < 0 || w.value > 1) {
        return { ok: false, message: `${at}: not a pmset setting Tracenium may change` };
      }
      out.push({ kind: "pmset", key: w.key, value: w.value });
    } else if (w.kind === "launchd") {
      if (typeof w.label !== "string" || !Object.prototype.hasOwnProperty.call(LAUNCHD_SERVICES, w.label) || typeof w.enabled !== "boolean") {
        return { ok: false, message: `${at}: not a service Tracenium may load or unload` };
      }
      // Desactivar lo que alguien usa es la guarda; volver a activarlo (el
      // revert) no.
      const guard = w.enabled ? null : LAUNCHD_SERVICES[w.label];
      if (guard) return { ok: false, message: `${at}: guarded (${guard})` };
      out.push({ kind: "launchd", label: w.label, enabled: w.enabled });
    } else {
      return { ok: false, message: `${at}: unknown kind` };
    }
  }
  return { ok: true, value: out };
}

// ── Dependencias ─────────────────────────────────────────────────────

export type ExecFn = (bin: string, args: string[], timeoutMs?: number) => Promise<{ stdout: string; stderr: string; code: number }>;

export interface MacGenericDeps {
  exec: ExecFn;
  exists(p: string): boolean;
  copyFile(src: string, dst: string): void;
}

// ── Estado ───────────────────────────────────────────────────────────

export type StateEntry =
  | { kind: "macpref"; domain: string; key: string; present: boolean; value: unknown; effective: unknown; forced: boolean }
  | { kind: "pmset"; key: string; value: number | null }
  | { kind: "launchd"; label: string; loaded: boolean };

/** `defaults read-type` → cómo convertir la salida de `defaults read`. */
function typedDefault(type: string, raw: string): unknown {
  const t = raw.trim();
  if (/boolean/i.test(type)) return t === "1" || /^true$/i.test(t);
  if (/integer/i.test(type)) return Number(t);
  if (/float|real/i.test(type)) return Number(t);
  if (/string/i.test(type)) return t;
  return t; // arrays/dicts: se devuelven como texto (el revert los rechaza)
}

async function readLocalPref(domain: string, key: string, deps: MacGenericDeps): Promise<{ present: boolean; value: unknown }> {
  const file = `/Library/Preferences/${domain}`;
  const type = await deps.exec("/usr/bin/defaults", ["read-type", file, key]);
  if (type.code !== 0) return { present: false, value: null };
  const r = await deps.exec("/usr/bin/defaults", ["read", file, key]);
  return r.code === 0 ? { present: true, value: typedDefault(type.stdout, r.stdout) } : { present: false, value: null };
}

export async function readEntries(writes: MacWrite[], deps: MacGenericDeps): Promise<StateEntry[]> {
  const prefs = writes.filter((w): w is Extract<MacWrite, { kind: "macpref" }> => w.kind === "macpref");
  let effective: ReturnType<typeof parsePrefResult> = { values: {}, forced: {} };
  if (prefs.length) {
    const r = await deps.exec("/usr/bin/osascript", ["-l", "JavaScript", "-e", buildPrefScript(prefs.map((p) => ({ suite: p.domain, key: p.key })))]);
    effective = parsePrefResult(r.stdout);
  }
  let pmset: Record<string, number | string> | null = null;
  let loaded: Set<string> | null = null;
  const out: StateEntry[] = [];
  for (const w of writes) {
    if (w.kind === "macpref") {
      const local = await readLocalPref(w.domain, w.key, deps);
      const id = `${w.domain}:${w.key}`;
      out.push({ kind: "macpref", domain: w.domain, key: w.key, ...local, effective: effective.values[id] ?? null, forced: effective.forced[id] === true });
    } else if (w.kind === "pmset") {
      pmset ??= parsePmsetCustom((await deps.exec("/usr/bin/pmset", ["-g", "custom"])).stdout);
      const v = pmset[w.key];
      out.push({ kind: "pmset", key: w.key, value: typeof v === "number" ? v : null });
    } else {
      loaded ??= parseLaunchctlList((await deps.exec("/bin/launchctl", ["list"])).stdout);
      out.push({ kind: "launchd", label: w.label, loaded: loaded.has(w.label) });
    }
  }
  return out;
}

const sameValue = (a: unknown, b: unknown) =>
  a === b || (typeof a === "boolean" && (b === (a ? 1 : 0))) || (typeof b === "boolean" && (a === (b ? 1 : 0)));

export function satisfied(w: MacWrite, e: StateEntry): { ok: boolean; why: string | null } {
  if (w.kind === "macpref" && e.kind === "macpref") {
    if (w.value === null) return e.present ? { ok: false, why: `${w.domain} ${w.key} is still set` } : { ok: true, why: null };
    if (!e.present || !sameValue(w.value, e.value)) return { ok: false, why: `${w.domain} ${w.key} is not set to ${JSON.stringify(w.value)}` };
    if (e.forced && !sameValue(w.value, e.effective)) {
      return { ok: false, why: `a configuration profile sets ${w.domain} ${w.key} to ${JSON.stringify(e.effective)}; the local value is ignored` };
    }
    return { ok: true, why: null };
  }
  if (w.kind === "pmset" && e.kind === "pmset") {
    return e.value === w.value ? { ok: true, why: null } : { ok: false, why: `pmset ${w.key} is ${e.value ?? "absent"}, expected ${w.value}` };
  }
  if (w.kind === "launchd" && e.kind === "launchd") {
    return e.loaded === w.enabled ? { ok: true, why: null } : { ok: false, why: `${w.label} is ${e.loaded ? "still loaded" : "not loaded"}` };
  }
  return { ok: false, why: "state does not match the write" };
}

export async function readGenericState(params: unknown, deps: MacGenericDeps): Promise<Check<{ state: { writes: StateEntry[] }; isCompliant: boolean }>> {
  const parsed = parseWrites(params);
  if (!parsed.ok) return parsed;
  const entries = await readEntries(parsed.value, deps);
  return { ok: true, value: { state: { writes: entries }, isCompliant: parsed.value.every((w, i) => satisfied(w, entries[i]).ok) } };
}

// ── Aplicar ──────────────────────────────────────────────────────────

export type GenericOutcome = { exitCode: number; stderrExcerpt?: string; durationMs: number; requiresReboot: boolean; changesApplied: string[] };

const AUDIT_CONTROL = "/etc/security/audit_control";

export async function applyGeneric(params: unknown, deps: MacGenericDeps): Promise<Check<GenericOutcome>> {
  const t0 = Date.now();
  const parsed = parseWrites(params);
  if (!parsed.ok) return parsed;
  const changes: string[] = [];
  const problems: string[] = [];
  const note = (r: { code: number; stderr: string; stdout: string }, what: string) => {
    if (r.code === 0) changes.push(what);
    else problems.push(`${what} failed: ${(r.stderr || r.stdout).trim().slice(0, 160)}`);
  };

  for (const w of parsed.value) {
    if (w.kind === "macpref") {
      const file = `/Library/Preferences/${w.domain}`;
      if (w.value === null) {
        const r = await deps.exec("/usr/bin/defaults", ["delete", file, w.key]);
        // Borrar lo que no existe es el estado pedido.
        if (r.code === 0) changes.push(`deleted ${w.domain} ${w.key}`);
      } else {
        const typed = typeof w.value === "boolean" ? ["-bool", String(w.value)] : typeof w.value === "number" ? ["-int", String(w.value)] : ["-string", w.value];
        note(await deps.exec("/usr/bin/defaults", ["write", file, w.key, ...typed]), `${w.domain} ${w.key}=${w.value}`);
      }
    } else if (w.kind === "pmset") {
      note(await deps.exec("/usr/bin/pmset", ["-a", w.key, String(w.value)]), `pmset ${w.key} ${w.value}`);
    } else if (w.enabled) {
      // CIS 3.1: auditd necesita su audit_control; sin él no arranca.
      if (w.label === "com.apple.auditd" && !deps.exists(AUDIT_CONTROL) && deps.exists(`${AUDIT_CONTROL}.example`)) {
        deps.copyFile(`${AUDIT_CONTROL}.example`, AUDIT_CONTROL);
        changes.push(`created ${AUDIT_CONTROL} from the example`);
      }
      note(await deps.exec("/bin/launchctl", ["enable", `system/${w.label}`]), `enabled ${w.label}`);
      // Ya cargado → bootstrap falla con «service already loaded»: no es un error.
      const r = await deps.exec("/bin/launchctl", ["bootstrap", "system", `/System/Library/LaunchDaemons/${w.label}.plist`]);
      if (r.code === 0) changes.push(`loaded ${w.label}`);
    } else {
      note(await deps.exec("/bin/launchctl", ["disable", `system/${w.label}`]), `disabled ${w.label}`);
      const r = await deps.exec("/bin/launchctl", ["bootout", `system/${w.label}`]);
      if (r.code === 0) changes.push(`unloaded ${w.label}`);
    }
  }

  // Releer como la sonda.
  const after = await readEntries(parsed.value, deps);
  parsed.value.forEach((w, i) => {
    const s = satisfied(w, after[i]);
    if (!s.ok && s.why) problems.push(s.why);
  });
  return {
    ok: true,
    value: {
      exitCode: problems.length ? 1 : 0,
      stderrExcerpt: problems.length ? problems.join("; ").slice(0, 1024) : undefined,
      durationMs: Date.now() - t0,
      requiresReboot: false,
      changesApplied: changes,
    },
  };
}
