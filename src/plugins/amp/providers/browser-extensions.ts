// src/plugins/amp/providers/browser-extensions.ts
//
// Recorre los perfiles de Chrome, Edge y Firefox de TODOS los usuarios del
// equipo y devuelve sus extensiones (ver domain/browser-extension.ts para
// qué se extrae de cada fichero).
//
// ── Por qué desde el proceso del agente y no desde el PrivSvc ────────
//
// En Windows AgentCore corre como LocalSystem y en macOS como LaunchDaemon
// de root: los dos pueden leer las carpetas de todos los usuarios, y los
// ficheros son JSON — mejor parsearlos una vez, en TypeScript, con tests,
// que duplicar el parser en C#.
//
// ── Linux: NO se lee, y a propósito ──────────────────────────────────
//
// Allí el agente corre como `tracenium` sin acceso a /home, y el perfil
// AppArmor del PrivSvc termina en `deny /home/** rw`: la garantía escrita es
// que ni un daemon comprometido lee las carpetas personales. En AppArmor un
// deny gana a cualquier allow, así que abrir los perfiles del navegador
// exige debilitar esa garantía, y eso lo decide el dueño del producto, no
// este colector. Hasta entonces el alcance es `unsupported`, que el portal
// puede decir tal cual en vez de pintar "sin extensiones".
//
// ── Nunca escribe ────────────────────────────────────────────────────
//
// Sólo lecturas de ficheros cerrados; nada de abrir bases del perfil ni
// tocar bloqueos del navegador en marcha. Un fichero a medio escribir
// falla el JSON.parse y ese perfil cuenta como error, sin más.

import fs from "fs";
import path from "path";
import {
  BrowserExtension,
  MAX_EXTENSIONS_PER_DEVICE,
  parseChromiumProfile,
  parseFirefoxProfile,
  parseFirefoxProfilesIni,
} from "../../../domain/browser-extension";

/**
 * Por qué la lista está como está.
 *   collected    se miró (puede no haber ninguna extensión: es un dato)
 *   unsupported  esta plataforma no se lee (Linux, ver cabecera)
 *   unavailable  no se pudo ni listar las carpetas de usuario
 */
export type ExtensionScope = "collected" | "unsupported" | "unavailable";

export type ExtensionScanResult = {
  extensions: BrowserExtension[];
  scope: ExtensionScope;
  /** Perfiles de navegador leídos, y los que fallaron (JSON roto, permisos). */
  profiles: number;
  profileErrors: number;
};

export type ExtensionScanFs = {
  readdir(p: string): string[];
  isDirectory(p: string): boolean;
  /** Contenido del fichero, o null si no existe, no se puede leer o pasa de `maxBytes`. */
  readText(p: string, maxBytes: number): string | null;
};

const PREFERENCES_MAX_BYTES = 32 * 1024 * 1024;
const MANIFEST_MAX_BYTES = 1024 * 1024;
const FIREFOX_JSON_MAX_BYTES = 16 * 1024 * 1024;
const MAX_PROFILES_PER_BROWSER = 64;

/** Carpetas bajo C:\Users o /Users que no son de una persona. */
const NOT_A_PERSON = new Set(["public", "default", "default user", "all users", "defaultuser0", "shared", "guest"]);

export const realFs: ExtensionScanFs = {
  readdir: (p) => fs.readdirSync(p),
  isDirectory: (p) => {
    try {
      const st = fs.lstatSync(p);
      return st.isDirectory() && !st.isSymbolicLink();
    } catch {
      return false;
    }
  },
  readText: (p, maxBytes) => {
    try {
      const st = fs.statSync(p);
      if (!st.isFile() || st.size > maxBytes) return null;
      return fs.readFileSync(p, "utf8");
    } catch {
      return null;
    }
  },
};

type BrowserRoots = { chrome: string[]; edge: string[]; firefox: string[] };

export function browserRootsFor(platform: NodeJS.Platform, home: string): BrowserRoots | null {
  if (platform === "win32") {
    return {
      chrome: [path.win32.join(home, "AppData", "Local", "Google", "Chrome", "User Data")],
      edge: [path.win32.join(home, "AppData", "Local", "Microsoft", "Edge", "User Data")],
      firefox: [path.win32.join(home, "AppData", "Roaming", "Mozilla", "Firefox")],
    };
  }
  if (platform === "darwin") {
    return {
      chrome: [path.posix.join(home, "Library", "Application Support", "Google", "Chrome")],
      edge: [path.posix.join(home, "Library", "Application Support", "Microsoft Edge")],
      firefox: [path.posix.join(home, "Library", "Application Support", "Firefox")],
    };
  }
  return null;
}

function parseJson(text: string | null): any | null {
  if (text === null) return null;
  try {
    return JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
  } catch {
    return null;
  }
}

function newestVersionDir(io: ExtensionScanFs, pathApi: typeof path.posix, extRoot: string): string | null {
  let names: string[];
  try {
    names = io.readdir(extRoot).filter((n) => io.isDirectory(pathApi.join(extRoot, n)));
  } catch {
    return null;
  }
  if (names.length === 0) return null;
  names.sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  return pathApi.join(extRoot, names[names.length - 1]);
}

export function scanBrowserExtensions(opts: {
  platform: NodeJS.Platform;
  usersRoot: string;
  io?: ExtensionScanFs;
  now?: () => string;
}): ExtensionScanResult {
  const io = opts.io ?? realFs;
  const detectedAtUtc = (opts.now ?? (() => new Date().toISOString()))();
  const pathApi = opts.platform === "win32" ? path.win32 : path.posix;

  if (opts.platform !== "win32" && opts.platform !== "darwin") {
    return { extensions: [], scope: "unsupported", profiles: 0, profileErrors: 0 };
  }

  let users: string[];
  try {
    users = io
      .readdir(opts.usersRoot)
      .filter((n) => !n.startsWith(".") && !NOT_A_PERSON.has(n.toLowerCase()))
      .filter((n) => io.isDirectory(pathApi.join(opts.usersRoot, n)));
  } catch {
    return { extensions: [], scope: "unavailable", profiles: 0, profileErrors: 0 };
  }

  const extensions: BrowserExtension[] = [];
  let profiles = 0;
  let profileErrors = 0;
  const full = () => extensions.length >= MAX_EXTENSIONS_PER_DEVICE;

  for (const user of users) {
    const home = pathApi.join(opts.usersRoot, user);
    const roots = browserRootsFor(opts.platform, home);
    if (!roots) continue;

    for (const browser of ["chrome", "edge"] as const) {
      for (const root of roots[browser]) {
        let dirs: string[];
        try {
          dirs = io.readdir(root);
        } catch {
          continue; // ese navegador no está para este usuario
        }
        const profileDirs = dirs
          .filter((n) => /^(Default|Profile \d+)$/.test(n))
          .filter((n) => io.isDirectory(pathApi.join(root, n)))
          .slice(0, MAX_PROFILES_PER_BROWSER);
        for (const profile of profileDirs) {
          if (full()) break;
          const profileDir = pathApi.join(root, profile);
          const preferences = parseJson(io.readText(pathApi.join(profileDir, "Preferences"), PREFERENCES_MAX_BYTES));
          const securePreferences = parseJson(io.readText(pathApi.join(profileDir, "Secure Preferences"), PREFERENCES_MAX_BYTES));
          if (!preferences && !securePreferences) {
            profileErrors++;
            continue;
          }
          profiles++;
          const { extensions: found } = parseChromiumProfile({
            browser,
            osUser: user,
            profile,
            preferences,
            securePreferences,
            detectedAtUtc,
            readManifest: (id, prefPath) => {
              let dir: string | null = null;
              if (prefPath && pathApi.isAbsolute(prefPath)) dir = prefPath;
              else if (prefPath && !prefPath.includes("..")) dir = pathApi.join(profileDir, "Extensions", prefPath);
              if (!dir || !io.isDirectory(dir)) dir = newestVersionDir(io, pathApi, pathApi.join(profileDir, "Extensions", id));
              if (!dir) return null;
              const manifest = parseJson(io.readText(pathApi.join(dir, "manifest.json"), MANIFEST_MAX_BYTES));
              if (!manifest) return null;
              const locale = typeof manifest.default_locale === "string" && /^[A-Za-z0-9_-]{1,16}$/.test(manifest.default_locale) ? manifest.default_locale : null;
              const messages = locale ? parseJson(io.readText(pathApi.join(dir, "_locales", locale, "messages.json"), MANIFEST_MAX_BYTES)) : null;
              return { manifest, messages };
            },
          });
          extensions.push(...found.slice(0, MAX_EXTENSIONS_PER_DEVICE - extensions.length));
        }
      }
    }

    for (const root of roots.firefox) {
      if (full()) break;
      const ini = io.readText(pathApi.join(root, "profiles.ini"), 1024 * 1024);
      let candidates: string[] = [];
      if (ini !== null) {
        candidates = parseFirefoxProfilesIni(ini)
          .filter((p) => p.relative && !p.path.includes(".."))
          .map((p) => pathApi.join(root, ...p.path.split(/[\\/]/)));
      } else {
        try {
          const base = pathApi.join(root, "Profiles");
          candidates = io.readdir(base).map((n) => pathApi.join(base, n));
        } catch {
          continue;
        }
      }
      for (const profileDir of candidates.slice(0, MAX_PROFILES_PER_BROWSER)) {
        if (full()) break;
        if (!io.isDirectory(profileDir)) continue;
        const text = io.readText(pathApi.join(profileDir, "extensions.json"), FIREFOX_JSON_MAX_BYTES);
        if (text === null) continue; // perfil creado y nunca abierto
        const json = parseJson(text);
        if (!json) {
          profileErrors++;
          continue;
        }
        profiles++;
        const found = parseFirefoxProfile({ osUser: user, profile: pathApi.basename(profileDir), extensionsJson: json, detectedAtUtc });
        extensions.push(...found.slice(0, MAX_EXTENSIONS_PER_DEVICE - extensions.length));
      }
    }
  }

  return { extensions, scope: "collected", profiles, profileErrors };
}

/** Raíz de las carpetas personales en esta plataforma. */
export function defaultUsersRoot(platform: NodeJS.Platform): string {
  if (platform === "win32") return path.win32.join(process.env.SystemDrive || "C:", "\\Users");
  if (platform === "darwin") return "/Users";
  return "/home";
}
