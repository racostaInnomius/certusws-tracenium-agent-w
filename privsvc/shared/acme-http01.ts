// privsvc/shared/acme-http01.ts
//
// ADR-0033 F2b — `cdp.acme.http01` en macOS y Linux: publicar y retirar el
// desafío HTTP-01 en el webroot de un servidor web. Gemelo de
// AcmeHttp01Shape.cs + AcmeHttp01.cs (Windows); la misma regla, paralela a
// propósito.
//
// Es una primitiva de ESCRITURA como root, así que se estrecha todo lo
// posible (el adversario que modela ADR-0011 es un control plane
// comprometido):
//
//   · nombre = token de la CA (base64url, 16-256);
//   · contenido = `token.huella` (huella SHA-256 de 43 caracteres): no sirve
//     para plantar un script ni una página;
//   · directorio = siempre `<webroot>/.well-known/acme-challenge`;
//   · el webroot, bajo una raíz permitida; las raíces extra sólo las pone el
//     administrador del equipo en un fichero LOCAL que el control plane no
//     escribe;
//   · nada se sigue por enlace simbólico: la ruta real de cada tramo tiene que
//     ser la esperada, y el fichero se abre con O_NOFOLLOW.

import fs from "fs";
import path from "path";

const TOKEN_RE = /^[A-Za-z0-9_-]{16,256}$/;
const THUMB_RE = /^[A-Za-z0-9_-]{43}$/;

export const LINUX_DEFAULT_ROOTS = ["/var/www", "/srv/www", "/srv/http", "/usr/share/nginx/html", "/var/lib/letsencrypt"];
export const MACOS_DEFAULT_ROOTS = ["/Library/WebServer/Documents", "/usr/local/var/www", "/opt/homebrew/var/www"];

export function isValidToken(token: unknown): token is string {
  return typeof token === "string" && TOKEN_RE.test(token);
}

/** `token.huella`, y el token tiene que ser EL MISMO que da nombre al fichero. */
export function isValidKeyAuthorization(token: unknown, keyAuthorization: unknown): boolean {
  if (!isValidToken(token) || typeof keyAuthorization !== "string") return false;
  const prefix = `${token}.`;
  return keyAuthorization.startsWith(prefix) && THUMB_RE.test(keyAuthorization.slice(prefix.length));
}

/** Una ruta absoluta por línea; `#` comenta. Lo demás se ignora. */
export function parseExtraRoots(content: string | null | undefined): string[] {
  if (!content) return [];
  return content
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#") && path.isAbsolute(l))
    .map((l) => path.resolve(l));
}

/** Normalizada sin tocar el disco. `null` si no es absoluta. */
export function normalizeWebroot(webroot: unknown): string | null {
  if (typeof webroot !== "string" || !webroot.trim() || webroot.includes("\0")) return null;
  const w = webroot.trim();
  if (!path.isAbsolute(w)) return null;
  return path.resolve(w);
}

/** Bajo una raíz, con separador: `/var/www-evil` no pasa por ser prefijo de `/var/www`. */
export function isUnderAllowedRoot(normalized: string, roots: string[]): boolean {
  return roots.some((r) => {
    const root = path.resolve(r);
    return normalized === root || normalized.startsWith(root + path.sep);
  });
}

export type Http01Outcome =
  | { ok: true; result: { published?: true; removed?: true; path: string } }
  | { ok: false; code: string; message: string };

export type Http01Deps = {
  roots: string[];
  /** Fichero LOCAL con raíces extra (lo escribe el administrador). */
  extraRootsFile: string;
  fsImpl?: typeof fs;
};

/**
 * Publica o retira. `params` es lo que llega por IPC: `{ action, webroot,
 * token, keyAuthorization? }`.
 */
export function handleHttp01(params: any, deps: Http01Deps): Http01Outcome {
  const f = deps.fsImpl ?? fs;
  const action = params?.action;
  const token = params?.token;
  if (action !== "publish" && action !== "remove") return { ok: false, code: "bad_request", message: "action must be publish or remove" };
  if (!isValidToken(token)) return { ok: false, code: "bad_request", message: "invalid token" };
  if (action === "publish" && !isValidKeyAuthorization(token, params?.keyAuthorization)) {
    return { ok: false, code: "bad_request", message: "invalid keyAuthorization (expected token.thumbprint)" };
  }
  const webroot = normalizeWebroot(params?.webroot);
  if (!webroot) return { ok: false, code: "bad_request", message: "webroot must be an absolute path" };

  let roots = [...deps.roots];
  try {
    if (f.existsSync(deps.extraRootsFile)) roots = roots.concat(parseExtraRoots(f.readFileSync(deps.extraRootsFile, "utf8")));
  } catch {
    // Un fichero ilegible no amplía nada.
  }
  if (!isUnderAllowedRoot(webroot, roots)) {
    return { ok: false, code: "webroot_not_allowed", message: `${webroot} is not under an allowed root; the device administrator can add it to ${deps.extraRootsFile}` };
  }

  try {
    const st = f.lstatSync(webroot, { throwIfNoEntry: false } as any) as fs.Stats | undefined;
    if (!st) return { ok: false, code: "webroot_missing", message: `${webroot} does not exist` };
    // La RUTA REAL también tiene que estar bajo una raíz: un tramo intermedio
    // enlazado a /etc haría que una ruta permitida acabara escribiendo allí.
    const real = f.realpathSync(webroot);
    if (!isUnderAllowedRoot(real, roots)) return { ok: false, code: "path_is_link", message: `${webroot} resolves to ${real}, outside the allowed roots` };
    if (!f.statSync(real).isDirectory()) return { ok: false, code: "webroot_missing", message: `${webroot} is not a directory` };

    const wellKnown = path.join(real, ".well-known");
    const dir = path.join(wellKnown, "acme-challenge");
    const file = path.join(dir, token);

    if (action === "remove") {
      const fst = f.lstatSync(file, { throwIfNoEntry: false } as any) as fs.Stats | undefined;
      if (fst?.isFile()) f.unlinkSync(file);
      return { ok: true, result: { removed: true, path: file } };
    }

    for (const d of [wellKnown, dir]) {
      const dst = f.lstatSync(d, { throwIfNoEntry: false } as any) as fs.Stats | undefined;
      if (!dst) f.mkdirSync(d, { mode: 0o755 });
      else if (!dst.isDirectory() || dst.isSymbolicLink()) return { ok: false, code: "path_is_link", message: `${d} is not a plain directory` };
    }
    // O_NOFOLLOW: si alguien dejó un enlace con el nombre del token, falla en
    // vez de escribir donde apunte. 0644 para que el servidor web lo lea.
    const fd = f.openSync(file, f.constants.O_WRONLY | f.constants.O_CREAT | f.constants.O_TRUNC | f.constants.O_NOFOLLOW, 0o644);
    try {
      f.writeSync(fd, String(params.keyAuthorization));
    } finally {
      f.closeSync(fd);
    }
    // Se relee: «no lanzó» no es «está publicado».
    if (f.readFileSync(file, "utf8") !== params.keyAuthorization) {
      return { ok: false, code: "write_mismatch", message: "the published file does not hold the expected content" };
    }
    return { ok: true, result: { published: true, path: file } };
  } catch (err: any) {
    if (err?.code === "ELOOP") return { ok: false, code: "path_is_link", message: "refusing to follow a symlink" };
    return { ok: false, code: "io_error", message: String(err?.message ?? err) };
  }
}
