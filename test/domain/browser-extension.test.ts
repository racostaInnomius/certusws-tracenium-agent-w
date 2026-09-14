// Parsers de extensiones: lo que se saca de Preferences / manifest.json de
// Chromium y de extensions.json de Firefox. Fixtures con la forma real de
// esos ficheros (Chrome 13x, Edge 13x, Firefox 14x), recortada.
import { describe, it, expect } from "vitest";
import {
  chromiumTimeToIso,
  isHostPattern,
  parseChromiumProfile,
  parseFirefoxProfile,
  parseFirefoxProfilesIni,
  resolveManifestMessage,
} from "../../src/domain/browser-extension";

const NOW = "2026-09-14T10:00:00.000Z";
const UBLOCK = "cjpalhdlnbpafiamejdnhcphjbkeiagm";
const PDF_VIEWER = "mhjfbmdgcfjbbpaeojofohoefgiehjai";
const SIDELOAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const POLICY = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GHOST = "cccccccccccccccccccccccccccccccc";
const THEME = "dddddddddddddddddddddddddddddddd";
const UNPACKED = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

const manifests: Record<string, any> = {
  [UBLOCK]: {
    manifest: { name: "__MSG_extName__", version: "1.60.0", manifest_version: 2, default_locale: "en", update_url: "https://clients2.google.com/service/update2/crx", permissions: ["storage", "tabs", "<all_urls>"] },
    messages: { extname: { message: "uBlock Origin" } },
  },
  [SIDELOAD]: {
    manifest: { name: "Deals Finder", version: "3.1", manifest_version: 3, permissions: ["cookies", { socket: ["tcp-connect"] }], host_permissions: ["https://*/*"], content_scripts: [{ matches: ["http://*/*"] }] },
    messages: null,
  },
  [POLICY]: { manifest: { name: "Corp SSO", version: "2.0", manifest_version: 3, permissions: ["identity"] }, messages: null },
  [THEME]: { manifest: { name: "Dark", version: "1", theme: { colors: {} } }, messages: null },
  [UNPACKED]: { manifest: { name: "Dev tool", version: "0.1", manifest_version: 3, permissions: ["debugger"] }, messages: null },
};

function chrome(securePreferences: any, preferences: any = null) {
  return parseChromiumProfile({
    browser: "chrome",
    osUser: "jdoe",
    profile: "Default",
    preferences,
    securePreferences,
    detectedAtUtc: NOW,
    readManifest: (id) => manifests[id] ?? null,
  });
}

describe("Chromium — Secure Preferences + manifest", () => {
  const secure = {
    extensions: {
      settings: {
        [UBLOCK]: { location: 1, from_webstore: true, path: `${UBLOCK}/1.60.0_0`, disable_reasons: [], first_install_time: "13370000000000000",
          active_permissions: { api: ["storage", "tabs"], explicit_host: ["<all_urls>"], scriptable_host: ["http://*/*"], manifest_permissions: [] } },
        [PDF_VIEWER]: { location: 5, manifest: { name: "Chrome PDF Viewer", version: "1" } },
        [SIDELOAD]: { location: 3, disable_reasons: 1 },
        [POLICY]: { location: 7, state: 1 },
        [GHOST]: { location: 1, state: 0 },
        [THEME]: { location: 1, from_webstore: true },
        [UNPACKED]: { location: 4, path: "/Users/jdoe/dev/tool" },
        "not-an-id": { location: 1 },
      },
    },
  };

  it("componentes, temas, restos sin manifest e ids inválidos no son inventario", () => {
    const { extensions, skipped } = chrome(secure);
    expect(extensions.map((e) => e.extensionId).sort()).toEqual([UBLOCK, SIDELOAD, POLICY, UNPACKED].sort());
    expect(skipped).toBe(1); // GHOST
  });

  it("nombre desde _locales, permisos CONCEDIDOS (active_permissions) y tienda", () => {
    const u = chrome(secure).extensions.find((e) => e.extensionId === UBLOCK)!;
    expect(u).toMatchObject({
      installId: `chrome|jdoe|Default|${UBLOCK}`,
      name: "uBlock Origin",
      version: "1.60.0",
      enabled: true,
      installSource: "store",
      permissions: ["storage", "tabs"],
      hostPermissions: ["<all_urls>", "http://*/*"],
      manifestVersion: 2,
    });
    expect(u.installedAtUtc).toBe(chromiumTimeToIso("13370000000000000"));
  });

  it("sin active_permissions cae al manifest: permissions con objetos, host_permissions y content_scripts", () => {
    const s = chrome(secure).extensions.find((e) => e.extensionId === SIDELOAD)!;
    expect(s.permissions).toEqual(["cookies", "socket"]);
    expect(s.hostPermissions).toEqual(["http://*/*", "https://*/*"]);
    expect(s.installSource).toBe("sideloaded");
    expect(s.enabled).toBe(false); // disable_reasons: 1
  });

  it("directiva, desempaquetada y estado heredado `state`", () => {
    const list = chrome(secure).extensions;
    expect(list.find((e) => e.extensionId === POLICY)).toMatchObject({ installSource: "policy", enabled: true });
    expect(list.find((e) => e.extensionId === UNPACKED)).toMatchObject({ installSource: "unpacked", permissions: ["debugger"], enabled: null });
  });

  it("Secure Preferences gana a Preferences para la misma extensión", () => {
    const prefs = { extensions: { settings: { [POLICY]: { location: 1, from_webstore: true, state: 0 } } } };
    const r = chrome({ extensions: { settings: { [POLICY]: { location: 9, state: 1 } } } }, prefs);
    expect(r.extensions[0]).toMatchObject({ installSource: "policy", enabled: true });
  });

  it("instalada internamente sin marca de tienda ni update_url oficial = otro software la metió", () => {
    manifests[GHOST] = { manifest: { name: "Toolbar", version: "1", manifest_version: 3, update_url: "https://evil.example/update.xml" }, messages: null };
    try {
      const r = chrome({ extensions: { settings: { [GHOST]: { location: 1 } } } });
      expect(r.extensions[0].installSource).toBe("sideloaded");
    } finally {
      delete manifests[GHOST];
    }
  });
});

describe("utilidades", () => {
  it("tiempo de Chromium: microsegundos desde 1601", () => {
    // 2024-01-01T00:00:00Z = 13348540800000000 µs desde 1601
    expect(chromiumTimeToIso("13348540800000000")).toBe("2024-01-01T00:00:00.000Z");
    expect(chromiumTimeToIso("0")).toBeNull();
    expect(chromiumTimeToIso("junk")).toBeNull();
  });
  it("mensajes de manifest sin distinguir mayúsculas; literal tal cual; clave ausente = null", () => {
    expect(resolveManifestMessage("__MSG_AppName__", { appname: { message: "X" } })).toBe("X");
    expect(resolveManifestMessage("Plain", null)).toBe("Plain");
    expect(resolveManifestMessage("__MSG_missing__", {})).toBeNull();
  });
  it("patrones de host", () => {
    for (const h of ["<all_urls>", "*://*/*", "https://a.com/*", "file:///*"]) expect(isHostPattern(h)).toBe(true);
    for (const p of ["tabs", "webRequest", "chrome://favicon/"]) expect(isHostPattern(p)).toBe(false);
  });
});

describe("Firefox — extensions.json", () => {
  const json = {
    schemaVersion: 36,
    addons: [
      { id: "uBlock0@raymondhill.net", type: "extension", location: "app-profile", version: "1.60.0", active: true, defaultLocale: { name: "uBlock Origin" },
        installTelemetryInfo: { source: "amo" }, userPermissions: { permissions: ["storage", "webRequest", "webRequestBlocking"], origins: ["<all_urls>"] }, manifestVersion: 2, installDate: 1700000000000 },
      { id: "formautofill@mozilla.org", type: "extension", location: "app-builtin", active: true, defaultLocale: { name: "Form Autofill" } },
      { id: "default-theme@mozilla.org", type: "theme", location: "app-builtin" },
      { id: "corp@example.com", type: "extension", location: "app-profile", active: false, userDisabled: true, installTelemetryInfo: { source: "enterprise-policy" }, defaultLocale: { name: "Corp" } },
      { id: "adware@example.com", type: "extension", location: "app-system-share", active: true, defaultLocale: { name: "Coupons" } },
      { id: "dict@example.com", type: "dictionary", location: "app-profile" },
    ],
  };
  const list = parseFirefoxProfile({ osUser: "jdoe", profile: "abcd.default-release", extensionsJson: json, detectedAtUtc: NOW });

  it("sólo extensiones que no vienen con Firefox", () => {
    expect(list.map((e) => e.extensionId)).toEqual(["uBlock0@raymondhill.net", "corp@example.com", "adware@example.com"]);
  });
  it("tienda, directiva y carpeta de sistema; permisos y origins", () => {
    expect(list[0]).toMatchObject({ installSource: "store", enabled: true, name: "uBlock Origin", permissions: ["storage", "webRequest", "webRequestBlocking"], hostPermissions: ["<all_urls>"], installedAtUtc: new Date(1700000000000).toISOString() });
    expect(list[1]).toMatchObject({ installSource: "policy", enabled: false });
    expect(list[2]).toMatchObject({ installSource: "sideloaded" });
  });
  it("profiles.ini: rutas relativas y absolutas", () => {
    const ini = "[General]\nStartWithLastProfile=1\n\n[Profile1]\nName=default\nIsRelative=1\nPath=Profiles/abcd.default\n\n[Profile0]\nName=work\nIsRelative=0\nPath=D:\\ff\\work\n\n[Install308046B0AF4A39CB]\nDefault=Profiles/abcd.default\n";
    expect(parseFirefoxProfilesIni(ini)).toEqual([{ path: "Profiles/abcd.default", relative: true }, { path: "D:\\ff\\work", relative: false }]);
  });
});
