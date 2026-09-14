// El recorrido de perfiles sobre un árbol REAL de ficheros (tmpdir con la
// estructura de macOS) y sobre uno en memoria con rutas de Windows.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { scanBrowserExtensions, type ExtensionScanFs } from "../../src/plugins/amp/providers/browser-extensions";

const ID = "cjpalhdlnbpafiamejdnhcphjbkeiagm";
const ID2 = "gighmmpiobklfepjocnamgkkbiglidom";
let root: string;

function write(p: string, content: string | object) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, typeof content === "string" ? content : JSON.stringify(content));
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "ext-scan-"));
  const chrome = path.join(root, "jdoe", "Library", "Application Support", "Google", "Chrome");
  // Perfil con la extensión en Secure Preferences y el manifest en disco (versión más nueva gana).
  write(path.join(chrome, "Default", "Secure Preferences"), { extensions: { settings: { [ID]: { location: 1, from_webstore: true } } } });
  write(path.join(chrome, "Default", "Extensions", ID, "1.9.0_0", "manifest.json"), { name: "Old", version: "1.9.0", manifest_version: 3 });
  write(path.join(chrome, "Default", "Extensions", ID, "1.10.0_0", "manifest.json"), { name: "uBlock Origin Lite", version: "1.10.0", manifest_version: 3, permissions: ["declarativeNetRequest"] });
  // Perfil con Preferences roto → error de perfil, no excepción.
  write(path.join(chrome, "Profile 2", "Preferences"), "{not json");
  // Carpetas que no son perfiles.
  write(path.join(chrome, "System Profile", "Preferences"), { extensions: { settings: { [ID2]: { location: 1 } } } });
  write(path.join(chrome, "Local State"), {});
  // Firefox con profiles.ini.
  const ff = path.join(root, "jdoe", "Library", "Application Support", "Firefox");
  write(path.join(ff, "profiles.ini"), "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/x1.default-release\n");
  write(path.join(ff, "Profiles", "x1.default-release", "extensions.json"), { addons: [{ id: "a@b", type: "extension", location: "app-profile", active: true, defaultLocale: { name: "A" } }] });
  // "Shared" no es una persona aunque tenga Chrome.
  write(path.join(root, "Shared", "Library", "Application Support", "Google", "Chrome", "Default", "Preferences"), { extensions: { settings: { [ID2]: { location: 1 } } } });
});

afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

describe("scanBrowserExtensions — macOS sobre disco real", () => {
  it("lee Chrome y Firefox de cada usuario, cuenta perfiles rotos y salta lo que no es perfil", () => {
    const r = scanBrowserExtensions({ platform: "darwin", usersRoot: root, now: () => "2026-09-14T00:00:00.000Z" });
    expect(r.scope).toBe("collected");
    expect(r.profiles).toBe(2);
    expect(r.profileErrors).toBe(1);
    expect(r.extensions.map((e) => e.installId).sort()).toEqual([`chrome|jdoe|Default|${ID}`, "firefox|jdoe|x1.default-release|a@b"]);
    expect(r.extensions.find((e) => e.browser === "chrome")).toMatchObject({ name: "uBlock Origin Lite", version: "1.10.0", permissions: ["declarativeNetRequest"] });
  });

  it("sin poder listar las carpetas de usuario el alcance es unavailable, no una lista vacía", () => {
    const r = scanBrowserExtensions({ platform: "darwin", usersRoot: path.join(root, "no-existe") });
    expect(r).toEqual({ extensions: [], scope: "unavailable", profiles: 0, profileErrors: 0 });
  });

  it("Linux se declara unsupported sin tocar el disco", () => {
    const io: ExtensionScanFs = { readdir: () => { throw new Error("no debería leer"); }, isDirectory: () => false, readText: () => null };
    expect(scanBrowserExtensions({ platform: "linux", usersRoot: "/home", io }).scope).toBe("unsupported");
  });
});

describe("scanBrowserExtensions — rutas de Windows", () => {
  const files: Record<string, string> = {
    "C:\\Users\\ana\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Secure Preferences": JSON.stringify({
      extensions: { settings: { [ID2]: { location: 1, path: `${ID2}\\2.0_0` } } },
    }),
    [`C:\\Users\\ana\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Extensions\\${ID2}\\2.0_0\\manifest.json`]: JSON.stringify({
      name: "Password Helper", version: "2.0", manifest_version: 3, update_url: "https://edge.microsoft.com/extensionwebstorebase/v1/crx", host_permissions: ["<all_urls>"],
    }),
  };
  const dirs = new Set<string>();
  for (const f of Object.keys(files)) {
    let d = path.win32.dirname(f);
    while (d.length > 3) { dirs.add(d); d = path.win32.dirname(d); }
  }
  dirs.add("C:\\Users\\Public");
  const io: ExtensionScanFs = {
    readdir: (p) => {
      const kids = new Set<string>();
      for (const x of [...dirs, ...Object.keys(files)]) if (path.win32.dirname(x) === p) kids.add(path.win32.basename(x));
      if (kids.size === 0 && !dirs.has(p)) throw new Error("ENOENT");
      return [...kids];
    },
    isDirectory: (p) => dirs.has(p),
    readText: (p) => files[p] ?? null,
  };

  it("Edge con el path relativo de Preferences y tienda de Edge", () => {
    const r = scanBrowserExtensions({ platform: "win32", usersRoot: "C:\\Users", io, now: () => "2026-09-14T00:00:00.000Z" });
    expect(r.scope).toBe("collected");
    expect(r.extensions).toHaveLength(1);
    expect(r.extensions[0]).toMatchObject({ installId: `edge|ana|Default|${ID2}`, name: "Password Helper", installSource: "store", hostPermissions: ["<all_urls>"] });
  });
});
