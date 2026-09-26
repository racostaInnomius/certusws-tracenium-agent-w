// test/privsvc/acme-http01.test.ts
//
// ADR-0033 F2b — `cdp.acme.http01` en macOS y Linux, contra un directorio
// temporal DE VERDAD: lo que importa aquí es el disco (enlaces, O_NOFOLLOW,
// ruta real), y un fs falso no lo ejercitaría.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { handleHttp01, isValidKeyAuthorization, isUnderAllowedRoot, parseExtraRoots } from "../../privsvc/shared/acme-http01";

const TOKEN = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
const KEYAUTH = `${TOKEN}.${"a".repeat(43)}`;

let base: string;
let root: string;
let webroot: string;
let outside: string;
let extraFile: string;

beforeEach(() => {
  base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "acme-http01-")));
  root = path.join(base, "www");
  webroot = path.join(root, "site");
  outside = path.join(base, "etc");
  extraFile = path.join(base, "acme-webroots");
  fs.mkdirSync(webroot, { recursive: true });
  fs.mkdirSync(outside);
});

afterEach(() => fs.rmSync(base, { recursive: true, force: true }));

const deps = () => ({ roots: [root], extraRootsFile: extraFile });
const publish = (over: Record<string, unknown> = {}) =>
  handleHttp01({ action: "publish", webroot, token: TOKEN, keyAuthorization: KEYAUTH, ...over }, deps());

describe("publicar", () => {
  it("⭐ escribe token.huella en .well-known/acme-challenge/<token>, legible por el servidor web", () => {
    const r = publish();
    expect(r).toMatchObject({ ok: true, result: { published: true } });
    const file = path.join(webroot, ".well-known", "acme-challenge", TOKEN);
    expect(fs.readFileSync(file, "utf8")).toBe(KEYAUTH);
    expect(fs.statSync(file).mode & 0o777).toBe(0o644);
  });

  it("⭐ el contenido tiene forma fija: no sirve para plantar una página", () => {
    expect(publish({ keyAuthorization: "<?php system($_GET['c']); ?>" })).toMatchObject({ ok: false, code: "bad_request" });
    expect(isValidKeyAuthorization(TOKEN, `other_token_12345678.${"a".repeat(43)}`)).toBe(false);
  });

  it("⭐ el nombre es el token: nada de rutas", () => {
    expect(publish({ token: "../../../etc/passwd-xxxxxxxx", keyAuthorization: `../../../etc/passwd-xxxxxxxx.${"a".repeat(43)}` })).toMatchObject({
      ok: false,
      code: "bad_request",
    });
  });

  it("⭐ fuera de las raíces permitidas, no; y `..` no ayuda", () => {
    expect(publish({ webroot: outside })).toMatchObject({ ok: false, code: "webroot_not_allowed" });
    expect(publish({ webroot: path.join(root, "..", "etc") })).toMatchObject({ ok: false, code: "webroot_not_allowed" });
    expect(isUnderAllowedRoot(`${root}-evil`, [root])).toBe(false);
  });

  it("⭐ un webroot que es un enlace a otro sitio: la ruta REAL manda", () => {
    const link = path.join(root, "linked");
    fs.symlinkSync(outside, link);
    expect(publish({ webroot: link })).toMatchObject({ ok: false, code: "path_is_link" });
    expect(fs.readdirSync(outside)).toEqual([]);
  });

  it("⭐ un .well-known enlazado fuera no se sigue", () => {
    fs.symlinkSync(outside, path.join(webroot, ".well-known"));
    expect(publish()).toMatchObject({ ok: false, code: "path_is_link" });
    expect(fs.readdirSync(outside)).toEqual([]);
  });

  it("⭐ un enlace con el nombre del token no se sigue (O_NOFOLLOW)", () => {
    const dir = path.join(webroot, ".well-known", "acme-challenge");
    fs.mkdirSync(dir, { recursive: true });
    const victim = path.join(outside, "victim");
    fs.writeFileSync(victim, "intacto");
    fs.symlinkSync(victim, path.join(dir, TOKEN));
    expect(publish()).toMatchObject({ ok: false, code: "path_is_link" });
    expect(fs.readFileSync(victim, "utf8")).toBe("intacto");
  });

  it("un webroot que no existe se dice, no se crea", () => {
    expect(publish({ webroot: path.join(root, "nope") })).toMatchObject({ ok: false, code: "webroot_missing" });
  });

  it("⭐ las raíces extra salen SOLO del fichero local del administrador", () => {
    expect(publish({ webroot: outside })).toMatchObject({ ok: false, code: "webroot_not_allowed" });
    fs.writeFileSync(extraFile, `# sitios de la app\n${outside}\nrelativa/no\n`);
    expect(publish({ webroot: outside })).toMatchObject({ ok: true });
    expect(parseExtraRoots("relative\n# c\n/abs/ok")).toEqual(["/abs/ok"]);
  });
});

describe("retirar", () => {
  it("borra el fichero publicado", () => {
    publish();
    const r = handleHttp01({ action: "remove", webroot, token: TOKEN }, deps());
    expect(r).toMatchObject({ ok: true, result: { removed: true } });
    expect(fs.existsSync(path.join(webroot, ".well-known", "acme-challenge", TOKEN))).toBe(false);
  });

  it("⭐ sólo borra un FICHERO normal: un enlace con ese nombre se deja (y su destino, intacto)", () => {
    const dir = path.join(webroot, ".well-known", "acme-challenge");
    fs.mkdirSync(dir, { recursive: true });
    const victim = path.join(outside, "victim");
    fs.writeFileSync(victim, "intacto");
    fs.symlinkSync(victim, path.join(dir, TOKEN));
    expect(handleHttp01({ action: "remove", webroot, token: TOKEN }, deps())).toMatchObject({ ok: true });
    expect(fs.readFileSync(victim, "utf8")).toBe("intacto");
  });

  it("retirar lo que no está no es un error", () => {
    expect(handleHttp01({ action: "remove", webroot, token: TOKEN }, deps())).toMatchObject({ ok: true });
  });
});
