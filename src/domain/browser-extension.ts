// src/domain/browser-extension.ts
//
// Extensiones de navegador instaladas en el equipo, leídas del DISCO — no
// desde el navegador. Una extensión con permiso para leer y cambiar todos
// los sitios es la forma más barata de sacar sesiones y datos de una
// empresa, y el administrador no tiene hoy manera de saber cuáles hay en su
// flota sin comprar la consola de cada fabricante.
//
// ── Qué se lee y qué NO ──────────────────────────────────────────────
//
//   Chrome / Edge   `<perfil>/Secure Preferences` y `Preferences` →
//                   `extensions.settings.<id>` (dónde se instaló, si está
//                   deshabilitada, permisos CONCEDIDOS), y el manifest.json
//                   de `<perfil>/Extensions/<id>/<versión>` para el nombre.
//   Firefox         `<perfil>/extensions.json` → `addons[]`.
//
// Esos ficheros traen mucho más (Preferences lleva preferencias del usuario;
// extensions.json, rutas locales). Se parsean EN MEMORIA y de aquí sólo sale
// lo que declara `BrowserExtension`: ni historial, ni URLs visitadas, ni
// contenido de la extensión. El nombre del usuario del sistema sí sale — el
// inventario de usuarios del equipo ya lo lleva.
//
// ── Qué NO es inventario ─────────────────────────────────────────────
//
// Las extensiones de COMPONENTE (visor PDF de Chrome, "Form Autofill" de
// Firefox) vienen con el navegador y no se pueden quitar: listarlas sería
// ruido idéntico en todos los equipos. Los temas tampoco: no piden permisos.
//
// La PUNTUACIÓN de riesgo no se calcula aquí: se manda el dato crudo y la
// calcula el control plane. Así cambiar el criterio es desplegar backend, no
// esperar días a que la flota se auto-actualice.

export type BrowserFamily = "chrome" | "edge" | "firefox";

/**
 * De dónde vino la extensión.
 *   store      tienda oficial (Chrome Web Store, Edge Add-ons, AMO)
 *   policy     forzada por directiva (ExtensionInstallForcelist, policies.json)
 *   default    preinstalada por el fabricante del navegador o del equipo
 *   sideloaded instalada por OTRO software (registro, preferencias externas,
 *              carpeta de sistema) — la vía clásica del adware
 *   unpacked   cargada desde una carpeta en modo desarrollador
 *   unknown    no se pudo determinar
 */
export type ExtensionInstallSource = "store" | "policy" | "default" | "sideloaded" | "unpacked" | "unknown";

export interface BrowserExtension {
  /** `${browser}|${osUser}|${profile}|${extensionId}` — la misma extensión en dos perfiles son dos filas. */
  installId: string;
  browser: BrowserFamily;
  extensionId: string;
  name: string;
  version: string | null;
  /** Usuario del sistema dueño del perfil (nombre de la carpeta personal). */
  osUser: string;
  /** Carpeta del perfil: "Default", "Profile 1", "abcd1234.default-release". */
  profile: string;
  /** null = el fichero no lo dice. */
  enabled: boolean | null;
  installSource: ExtensionInstallSource;
  /** Permisos de API concedidos, únicos y ordenados ("tabs", "cookies", "debugger"). */
  permissions: string[];
  /** Patrones de sitio a los que tiene acceso ("<all_urls>", "https://*.example.com/*"). */
  hostPermissions: string[];
  manifestVersion: number | null;
  updateUrl: string | null;
  installedAtUtc: string | null;
  detectedAtUtc: string;
}

/** Tope de filas por equipo: un perfil corrupto no puede inflar el FACTS. */
export const MAX_EXTENSIONS_PER_DEVICE = 2000;
const MAX_PERMISSIONS = 200;

export function extensionInstallId(browser: BrowserFamily, osUser: string, profile: string, extensionId: string): string {
  return `${browser}|${osUser}|${profile}|${extensionId}`;
}

// ── Utilidades comunes ───────────────────────────────────────────────

const HOST_PATTERN = /^(<all_urls>|\*:\/\/|https?:\/\/|wss?:\/\/|ftp:\/\/|file:\/\/|urn:)/i;

export function isHostPattern(p: string): boolean {
  return HOST_PATTERN.test(p);
}

function uniqSorted(values: Iterable<string>): string[] {
  const set = new Set<string>();
  for (const v of values) {
    const s = typeof v === "string" ? v.trim() : "";
    if (s) set.add(s);
    if (set.size >= MAX_PERMISSIONS) break;
  }
  return [...set].sort();
}

/**
 * Una entrada de permisos de Chromium puede ser una cadena o un objeto con
 * parámetros (`{"socket": ["tcp-connect"]}`, `{"usbDevices": [...]}`): el
 * permiso es la clave.
 */
function permissionName(p: unknown): string | null {
  if (typeof p === "string") return p;
  if (p && typeof p === "object" && !Array.isArray(p)) {
    const keys = Object.keys(p as object);
    return keys.length === 1 ? keys[0] : null;
  }
  return null;
}

function splitPermissions(entries: unknown[]): { api: string[]; hosts: string[] } {
  const api: string[] = [];
  const hosts: string[] = [];
  for (const e of entries) {
    const name = permissionName(e);
    if (!name) continue;
    (isHostPattern(name) ? hosts : api).push(name);
  }
  return { api, hosts };
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v.trim() : null;
}

// ── Chromium (Chrome, Edge) ──────────────────────────────────────────

/**
 * `ManifestLocation` de Chromium (extensions/common/mojom/manifest.mojom).
 * Estable desde hace más de una década; el número se guarda en Preferences.
 */
const LOCATION = {
  INTERNAL: 1,
  EXTERNAL_PREF: 2,
  EXTERNAL_REGISTRY: 3,
  UNPACKED: 4,
  COMPONENT: 5,
  EXTERNAL_PREF_DOWNLOAD: 6,
  EXTERNAL_POLICY_DOWNLOAD: 7,
  COMMAND_LINE: 8,
  EXTERNAL_POLICY: 9,
  EXTERNAL_COMPONENT: 10,
} as const;

/**
 * Chromium guarda instantes como MICROsegundos desde 1601-01-01 UTC, en
 * cadena. null si no parece uno.
 */
export function chromiumTimeToIso(v: unknown): string | null {
  const s = typeof v === "string" ? v.trim() : typeof v === "number" ? String(Math.trunc(v)) : "";
  if (!/^\d{15,18}$/.test(s)) return null;
  const ms = Number(BigInt(s) / 1000n) - 11_644_473_600_000;
  if (!Number.isFinite(ms) || ms <= 0) return null;
  return new Date(ms).toISOString();
}

/** `__MSG_appName__` → la cadena del idioma por defecto. */
export function resolveManifestMessage(value: unknown, messages: Record<string, any> | null): string | null {
  const raw = str(value);
  if (!raw) return null;
  const m = /^__MSG_(.+)__$/.exec(raw);
  if (!m) return raw;
  if (!messages) return null;
  const key = m[1].toLowerCase();
  for (const [k, entry] of Object.entries(messages)) {
    if (k.toLowerCase() === key) return str((entry as any)?.message);
  }
  return null;
}

export type ChromiumProfileInput = {
  browser: "chrome" | "edge";
  osUser: string;
  profile: string;
  /** JSON de `Preferences` y `Secure Preferences` (null si no se pudo leer). */
  preferences: any | null;
  securePreferences: any | null;
  /**
   * El manifest de una extensión instalada: recibe el `path` de Preferences
   * (relativo a `<perfil>/Extensions`, o absoluto si es desempaquetada) y el
   * id. Devuelve el manifest y los mensajes del idioma por defecto.
   */
  readManifest: (id: string, prefPath: string | null) => { manifest: any; messages: Record<string, any> | null } | null;
  detectedAtUtc: string;
};

function chromiumDisabled(s: any): boolean | null {
  const reasons = s?.disable_reasons;
  if (Array.isArray(reasons)) return reasons.length > 0;
  if (typeof reasons === "number") return reasons !== 0;
  if (s?.state === 0) return true;
  if (s?.state === 1) return false;
  return null;
}

function chromiumSource(s: any, manifest: any): ExtensionInstallSource {
  const loc = Number(s?.location);
  if (loc === LOCATION.EXTERNAL_POLICY || loc === LOCATION.EXTERNAL_POLICY_DOWNLOAD) return "policy";
  if (loc === LOCATION.UNPACKED || loc === LOCATION.COMMAND_LINE) return "unpacked";
  if (s?.was_installed_by_default === true || s?.was_installed_by_oem === true) return "default";
  if (loc === LOCATION.EXTERNAL_PREF || loc === LOCATION.EXTERNAL_REGISTRY || loc === LOCATION.EXTERNAL_PREF_DOWNLOAD) return "sideloaded";
  if (loc === LOCATION.INTERNAL) {
    const update = String(manifest?.update_url ?? "");
    if (s?.from_webstore === true || /clients2\.google\.com\/service\/update2\/crx|edge\.microsoft\.com\/extensionwebstorebase/i.test(update)) {
      return "store";
    }
    return "sideloaded";
  }
  return "unknown";
}

export function parseChromiumProfile(input: ChromiumProfileInput): { extensions: BrowserExtension[]; skipped: number } {
  const settings: Record<string, any> = {
    ...(input.preferences?.extensions?.settings ?? {}),
    // Secure Preferences es la fuente protegida por MAC en Windows y macOS;
    // si las dos traen la misma extensión, gana ésta.
    ...(input.securePreferences?.extensions?.settings ?? {}),
  };
  const out: BrowserExtension[] = [];
  let skipped = 0;

  for (const [id, s] of Object.entries(settings)) {
    if (!/^[a-p]{32}$/.test(id) || !s || typeof s !== "object") continue;
    const loc = Number(s.location);
    if (loc === LOCATION.COMPONENT || loc === LOCATION.EXTERNAL_COMPONENT) continue;

    let manifest = s.manifest && typeof s.manifest === "object" ? s.manifest : null;
    let messages: Record<string, any> | null = null;
    const read = input.readManifest(id, str(s.path));
    if (read?.manifest) {
      manifest = read.manifest;
      messages = read.messages;
    }
    // Sin manifest no hay extensión en disco: restos de una desinstalada o
    // de una bloqueada por directiva antes de descargarse. No se inventa.
    if (!manifest) {
      skipped++;
      continue;
    }
    if (manifest.theme) continue;

    const active = s.active_permissions;
    let api: string[];
    let hosts: string[];
    if (active && typeof active === "object") {
      api = asArray(active.api).map(permissionName).filter((x): x is string => Boolean(x));
      hosts = [...asArray(active.explicit_host), ...asArray(active.scriptable_host)].filter((x): x is string => typeof x === "string");
      // Los permisos de manifiesto (p. ej. "devtools_page") también viajan.
      api.push(...asArray(active.manifest_permissions).map(permissionName).filter((x): x is string => Boolean(x)));
    } else {
      const fromManifest = splitPermissions(asArray(manifest.permissions));
      api = fromManifest.api;
      hosts = [
        ...fromManifest.hosts,
        ...asArray(manifest.host_permissions).filter((x): x is string => typeof x === "string"),
        ...asArray(manifest.content_scripts).flatMap((cs: any) => asArray(cs?.matches)).filter((x): x is string => typeof x === "string"),
      ];
    }

    const name = resolveManifestMessage(manifest.name, messages) ?? id;
    const mv = Number(manifest.manifest_version);
    out.push({
      installId: extensionInstallId(input.browser, input.osUser, input.profile, id),
      browser: input.browser,
      extensionId: id,
      name: name.slice(0, 256),
      version: str(manifest.version),
      osUser: input.osUser,
      profile: input.profile,
      enabled: (() => {
        const d = chromiumDisabled(s);
        return d === null ? null : !d;
      })(),
      installSource: chromiumSource(s, manifest),
      permissions: uniqSorted(api),
      hostPermissions: uniqSorted(hosts),
      manifestVersion: Number.isInteger(mv) ? mv : null,
      updateUrl: str(manifest.update_url),
      installedAtUtc: chromiumTimeToIso(s.first_install_time ?? s.install_time),
      detectedAtUtc: input.detectedAtUtc,
    });
  }
  return { extensions: out, skipped };
}

// ── Firefox ──────────────────────────────────────────────────────────

/** Ubicaciones de complementos que vienen con el propio Firefox. */
const FIREFOX_BUILTIN_LOCATIONS = new Set(["app-builtin", "app-system-defaults", "app-system-addons", "app-temporary"]);
/** Instalados por otro software en carpetas del sistema o por registro. */
const FIREFOX_SIDELOAD_LOCATIONS = /^(app-system-(share|local|user)|winreg-app-(global|user))$/;

function firefoxSource(a: any): ExtensionInstallSource {
  const loc = String(a?.location ?? "");
  if (FIREFOX_SIDELOAD_LOCATIONS.test(loc)) return "sideloaded";
  const src = String(a?.installTelemetryInfo?.source ?? "");
  if (src === "enterprise-policy") return "policy";
  if (src === "amo" || /^https:\/\/addons\.mozilla\.org\//i.test(String(a?.sourceURI ?? ""))) return "store";
  if (src === "distribution") return "default";
  if (src === "file-url") return "sideloaded";
  if (src === "about:debugging" || src === "temporary-addon") return "unpacked";
  return "unknown";
}

export function parseFirefoxProfile(input: {
  osUser: string;
  profile: string;
  extensionsJson: any | null;
  detectedAtUtc: string;
}): BrowserExtension[] {
  const out: BrowserExtension[] = [];
  for (const a of asArray(input.extensionsJson?.addons)) {
    const addon = a as any;
    if (!addon || addon.type !== "extension") continue;
    const id = str(addon.id);
    if (!id) continue;
    if (FIREFOX_BUILTIN_LOCATIONS.has(String(addon.location ?? ""))) continue;
    // Complementos del sistema que Mozilla marca como ocultos.
    if (addon.hidden === true && addon.location !== "app-profile") continue;

    const perms = addon.userPermissions ?? {};
    const enabled =
      typeof addon.active === "boolean"
        ? addon.active
        : addon.userDisabled === true || addon.appDisabled === true || addon.softDisabled === true
          ? false
          : null;
    const installedMs = Number(addon.installDate);
    const mv = Number(addon.manifestVersion);
    out.push({
      installId: extensionInstallId("firefox", input.osUser, input.profile, id),
      browser: "firefox",
      extensionId: id.slice(0, 256),
      name: (str(addon.defaultLocale?.name) ?? id).slice(0, 256),
      version: str(addon.version),
      osUser: input.osUser,
      profile: input.profile,
      enabled,
      installSource: firefoxSource(addon),
      permissions: uniqSorted(asArray(perms.permissions).filter((x): x is string => typeof x === "string")),
      hostPermissions: uniqSorted(asArray(perms.origins).filter((x): x is string => typeof x === "string")),
      manifestVersion: Number.isInteger(mv) ? mv : null,
      updateUrl: str(addon.updateURL),
      installedAtUtc: Number.isFinite(installedMs) && installedMs > 0 ? new Date(installedMs).toISOString() : null,
      detectedAtUtc: input.detectedAtUtc,
    });
  }
  return out;
}

/** Rutas `Path=` de profiles.ini, relativas a la raíz de Firefox cuando IsRelative=1. */
export function parseFirefoxProfilesIni(text: string): Array<{ path: string; relative: boolean }> {
  const out: Array<{ path: string; relative: boolean }> = [];
  let current: { path?: string; relative: boolean } | null = null;
  const flush = () => {
    if (current?.path) out.push({ path: current.path, relative: current.relative });
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("[")) {
      flush();
      current = /^\[Profile\d+\]$/i.test(line) ? { relative: true } : null;
      continue;
    }
    if (!current) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const k = line.slice(0, eq).trim().toLowerCase();
    const v = line.slice(eq + 1).trim();
    if (k === "path") current.path = v;
    else if (k === "isrelative") current.relative = v !== "0";
  }
  flush();
  return out;
}
