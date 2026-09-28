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
//   authdb    security authorizationdb read → shared=false → write (stdin),
//             como CIS 2.6.8; sólo los derechos de system.preferences*
//   asl_install  /etc/asl/com.apple.install: ttl=365 y sin all_max (CIS 3.x),
//             con copia, y HUP a syslogd
//   pwhint_clear  dscl . -delete /Users/<u> hint para cada cuenta con pista
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

import { buildPrefScript, parseAuthdb, parsePmsetCustom, parsePrefResult, parseLaunchctlList } from "./macos-probes";
import { parseHints } from "./macos-system-probes";

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

export const AUTHDB_RIGHTS: ReadonlySet<string> = new Set([
  "system.preferences",
  "system.preferences.energysaver",
  "system.preferences.network",
  "system.preferences.printing",
  "system.preferences.sharing",
  "system.preferences.softwareupdate",
  "system.preferences.startupdisk",
  "system.preferences.timemachine",
]);

export const ASL_INSTALL = "/etc/asl/com.apple.install";

export type MacWrite =
  | { kind: "macpref"; domain: string; key: string; value: boolean | number | string | null }
  | { kind: "pmset"; key: string; value: number }
  | { kind: "launchd"; label: string; enabled: boolean }
  | { kind: "authdb"; right: string; shared: boolean }
  | { kind: "asl_install"; restore?: string }
  | { kind: "pwhint_clear" };

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
    } else if (w.kind === "authdb") {
      if (typeof w.right !== "string" || !AUTHDB_RIGHTS.has(w.right) || typeof w.shared !== "boolean") return { ok: false, message: `${at}: not an authorization right Tracenium may change` };
      out.push({ kind: "authdb", right: w.right, shared: w.shared });
    } else if (w.kind === "asl_install") {
      if (w.restore !== undefined && (typeof w.restore !== "string" || w.restore.length > 16384 || w.restore.includes("\0"))) return { ok: false, message: `${at}: invalid restore text` };
      out.push(w.restore !== undefined ? { kind: "asl_install", restore: w.restore } : { kind: "asl_install" });
    } else if (w.kind === "pwhint_clear") {
      out.push({ kind: "pwhint_clear" });
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
  /** Lo mismo con stdin (security authorizationdb write lee el plist de ahí). */
  execInput(bin: string, args: string[], input: string, timeoutMs?: number): Promise<{ stdout: string; stderr: string; code: number }>;
  exists(p: string): boolean;
  copyFile(src: string, dst: string): void;
  readFile(p: string): string | null;
  /** Escritura atómica (temporal + rename) con ese modo. */
  writeFile(p: string, content: string, mode: number): void;
  now(): Date;
}

/** La línea de install.log con ttl=365 y sin all_max (CIS: «retained for 365 days and no maximum size»). */
export function editAslInstall(text: string): string {
  return text
    .split("\n")
    .map((l) => (/\bfile\s+\/var\/log\/install\.log\b/.test(l) ? l.replace(/\s+all_max=\S+/g, "").replace(/\s+ttl=\d+/g, "").replace(/\s*$/, "") + " ttl=365" : l))
    .join("\n");
}

/** `shared` del derecho a false (o true), en el plist que imprime `security authorizationdb read`. */
export function setAuthdbShared(plist: string, shared: boolean): string | null {
  const tag = shared ? "<true/>" : "<false/>";
  if (/<key>shared<\/key>\s*<(true|false)\/>/.test(plist)) return plist.replace(/(<key>shared<\/key>\s*)<(true|false)\/>/, `$1${tag}`);
  // Sin la clave: se añade en el diccionario raíz.
  const i = plist.indexOf("<dict>");
  return i < 0 ? null : plist.slice(0, i + 6) + `\n\t<key>shared</key>\n\t${tag}` + plist.slice(i + 6);
}

const USER_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

// ── Estado ───────────────────────────────────────────────────────────

export type StateEntry =
  | { kind: "macpref"; domain: string; key: string; present: boolean; value: unknown; effective: unknown; forced: boolean }
  | { kind: "pmset"; key: string; value: number | null }
  | { kind: "launchd"; label: string; loaded: boolean }
  | { kind: "authdb"; right: string; shared: boolean | null }
  | { kind: "asl_install"; content: string | null }
  // Sólo los NOMBRES: la pista puede delatar la contraseña y no sale del equipo.
  | { kind: "pwhint_clear"; usersWithHint: string[] };

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
    } else if (w.kind === "launchd") {
      loaded ??= parseLaunchctlList((await deps.exec("/bin/launchctl", ["list"])).stdout);
      out.push({ kind: "launchd", label: w.label, loaded: loaded.has(w.label) });
    } else if (w.kind === "authdb") {
      const r = await deps.exec("/usr/bin/security", ["authorizationdb", "read", w.right]);
      out.push({ kind: "authdb", right: w.right, shared: r.code === 0 ? parseAuthdb(r.stdout).shared : null });
    } else if (w.kind === "asl_install") {
      out.push({ kind: "asl_install", content: deps.readFile(ASL_INSTALL) });
    } else {
      out.push({ kind: "pwhint_clear", usersWithHint: parseHints((await deps.exec("/usr/bin/dscl", [".", "-list", "/Users", "hint"])).stdout) });
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
  if (w.kind === "authdb" && e.kind === "authdb") {
    return e.shared === w.shared ? { ok: true, why: null } : { ok: false, why: `${w.right} is shared=${e.shared}` };
  }
  if (w.kind === "asl_install" && e.kind === "asl_install") {
    if (w.restore !== undefined) return e.content === w.restore ? { ok: true, why: null } : { ok: false, why: `${ASL_INSTALL} is not back to its previous content` };
    const line = (e.content ?? "").split("\n").find((l) => /\bfile\s+\/var\/log\/install\.log\b/.test(l)) ?? "";
    return /\bttl=(3[6-9]\d|[4-9]\d\d|\d{4,})\b/.test(line) && !/all_max=/.test(line) ? { ok: true, why: null } : { ok: false, why: `${ASL_INSTALL} still lacks ttl=365 or keeps all_max` };
  }
  if (w.kind === "pwhint_clear" && e.kind === "pwhint_clear") {
    return e.usersWithHint.length === 0 ? { ok: true, why: null } : { ok: false, why: `accounts with a password hint: ${e.usersWithHint.join(", ")}` };
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
    } else if (w.kind === "authdb") {
      const r = await deps.exec("/usr/bin/security", ["authorizationdb", "read", w.right]);
      if (r.code !== 0) { problems.push(`security authorizationdb read ${w.right} failed: ${(r.stderr || r.stdout).trim().slice(0, 160)}`); continue; }
      if (parseAuthdb(r.stdout).shared === w.shared) continue;
      const next = setAuthdbShared(r.stdout, w.shared);
      if (!next) { problems.push(`${w.right}: unexpected authorizationdb output`); continue; }
      note(await deps.execInput("/usr/bin/security", ["authorizationdb", "write", w.right], next), `${w.right} shared=${w.shared}`);
    } else if (w.kind === "asl_install") {
      const before = deps.readFile(ASL_INSTALL);
      if (before === null) { problems.push(`${ASL_INSTALL} does not exist`); continue; }
      const next = w.restore !== undefined ? w.restore : editAslInstall(before);
      if (next === before) continue;
      deps.copyFile(ASL_INSTALL, `${ASL_INSTALL}.tracenium.${deps.now().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "").replace("T", "-")}.bak`);
      deps.writeFile(ASL_INSTALL, next, 0o644);
      changes.push(`wrote ${ASL_INSTALL}`);
      // syslogd relee su configuración con HUP.
      await deps.exec("/usr/bin/killall", ["-HUP", "syslogd"]);
    } else if (w.kind === "pwhint_clear") {
      const users = parseHints((await deps.exec("/usr/bin/dscl", [".", "-list", "/Users", "hint"])).stdout).filter((u) => USER_NAME.test(u));
      for (const u of users) note(await deps.exec("/usr/bin/dscl", [".", "-delete", `/Users/${u}`, "hint"]), `removed the password hint of ${u}`);
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
