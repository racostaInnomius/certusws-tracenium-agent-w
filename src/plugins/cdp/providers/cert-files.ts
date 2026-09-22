// src/plugins/cdp/providers/cert-files.ts
//
// Certificates, keystores and loose private keys that live as FILES on
// disk, outside any OS store.
//
// This is where most server certificates actually are. nginx, HAProxy,
// Apache, Postgres, a Tomcat keystore, a Docker bind-mount — none of them
// read the OS trust store; they are pointed at a path in a config file.
// On Linux the gap was total: CDP saw the distro trust bundle and nothing
// else, so the certificate a service was actually serving existed for us
// only if the TLS listener probe happened to be switched on.
//
// It also completes the listener probe. That one answers "process X
// serves certificate Y"; this one answers "and Y is the file at Z",
// which is the half an operator needs in order to go and replace it.
//
// ── Por defecto, no opt-in (ola 1.1, 2026-09) ────────────────────────
//
// Hasta la ola 1 esto solo corría con `cdp.certFilePaths` configurado, y
// en los tres tenants la lista estaba vacía: la función existía y no
// inventariaba nada. Ahora `cdp.fileDiscovery` decide:
//   default    — raíces por SO (defaultFileDiscoveryRoots) + las del operador;
//   configured — solo `cdp.certFilePaths` (el comportamiento anterior);
//   off        — nada.
// Lo que hace aceptable recorrer /etc, /opt o %ProgramFiles% en toda la
// flota son los límites de abajo: tiempo, número de ficheros, tamaño,
// profundidad, lista de exclusiones, y una caché (tamaño, mtime) para no
// releer lo que no cambió.
//
// ── What this deliberately does NOT do ───────────────────────────────
//
// **It never collects private key material.** A loose key is reported
// by PRESENCE only (../private-key-info.ts): path, algorithm and size
// when the PUBLIC half says so, encrypted or not, and which certificate
// it belongs to by public-key hash. Encrypted keys are never decrypted.
// A PEM that holds a private key yields no certificates from this file —
// `server.pem` with both halves is reported as a key, and its
// certificate is not parsed out of it: partial handling of a file that
// carries a secret is how key material ends up somewhere it should not.
// A PKCS#12 (`.p12`/`.pfx`, detected by structure, not by name) is opened
// with the EMPTY password only (see ../pkcs12.ts): its certificates are
// read, its key bags are never decrypted — only their localKeyId
// attribute is looked at, to set `hasPrivateKey`. JKS/JCEKS need no
// password for their certificates and their key blobs are skipped
// unread (../jks.ts). A keystore we cannot open is reported as an
// UNREADABLE store with the reason, never as an empty file, and never
// prompted for or brute-forced.
//
// **It is bounded in every direction.** Roots reach a recursive walk
// running as root/LocalSystem (macOS/Windows) or as the unprivileged
// `tracenium` user (Linux): an explicit root list (no scanning `/`), a
// depth cap, a candidate-file cap, a WALL-CLOCK budget, a per-file size
// cap, an extension allowlist, and skip lists. A walk that hits a budget
// SAYS so (`truncated` + `incompleteRoots`) instead of stopping silently:
// what was not visited cannot be reported as removed.

import fs from "fs";
import path from "path";
import type { CdpCertItem, CdpStoreInfo } from "../../../domain/cdp-types";
import { parseCertToItem } from "../parse-cert";
import { looksLikePkcs12, readPkcs12Certificates, Pkcs12Error } from "../pkcs12";
import { looksLikeJceks, looksLikeJks, parseJks } from "../jks";
import { describePrivateKeys, type KeyFacts } from "../private-key-info";

/** Extensions worth opening as certificates / containers. */
const CERT_EXTENSIONS = new Set([".crt", ".cer", ".pem", ".der", ".p12", ".pfx"]);
/** Java-style keystores. Detected by magic bytes once opened; the name only decides whether to open. */
const KEYSTORE_EXTENSIONS = new Set([".jks", ".jceks", ".keystore", ".ks", ".truststore"]);
/** Loose private keys. Presence only. */
const KEY_EXTENSIONS = new Set([".key", ".p8", ".pk8"]);
/** Keystores that conventionally have no extension (Tomcat's `~/.keystore`, `conf/keystore`). */
const KEYSTORE_NAMES = new Set(["keystore", ".keystore", "truststore", ".truststore"]);

/** Never descended into, under any root: huge, hostile to walk, or nothing to do with us. */
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".svn", ".hg", "__pycache__",
  "proc", "sys", "dev", "run", "tmp",
  "WinSxS",
  "Caches"
]);

/**
 * Extra names skipped under the DEFAULT roots only. An operator who
 * configures a path means it; a default root is our guess, so its noise
 * is ours to cut. Each entry is here for a measured or obvious reason:
 *   · site-packages / dist-packages / vendor — language package trees:
 *     certifi's cacert.pem and hundreds of TEST certificates and keys
 *     shipped inside libraries (tornado, twisted, urllib3...). Not the
 *     device's crypto, and they would drown the item cap.
 *   · test(s) / testdata / fixtures / examples / samples — same.
 *   (Container layers — /var/lib/docker, containerd, snapd — and package
 *   databases go by absolute PATH in defaultFileDiscoveryRoots, not by
 *   name: /etc/docker/certs.d holds real registry CAs.)
 *   · Package Cache / WindowsApps / Windows Defender — installer caches
 *     and ACL-sealed trees on Windows.
 *   · Cellar / Caskroom — Homebrew's per-version install trees; their
 *     `etc` is walked separately as a root.
 *   · tracenium — our own directories: the agent's mTLS key would be
 *     reported as a "loose key" on every device of the fleet.
 */
const DEFAULT_SKIP_NAMES = new Set([
  "site-packages", "dist-packages", "vendor",
  "test", "tests", "testdata", "testing", "fixtures", "examples", "samples",
  "Package Cache", "WindowsApps", "Windows Defender", "Windows Defender Advanced Threat Protection",
  "Cellar", "Caskroom",
  "cache", ".cache", "Cache",
  "tracenium"
]);

const MAX_DEPTH = 6;
/** Candidate files per scan. Well above what a server has; the item cap (2000) is the real ceiling. */
const MAX_FILES_DEFAULT = 3000;
/**
 * Wall-clock budget for the whole walk. The facts job has 300s end to
 * end and, on Windows, up to ~120s of it can go to the two privsvc store
 * reads (see JOB_DEFAULT_TIMEOUT_SECONDS in the backend). 45s keeps the
 * walk from ever being the thing that times the job out.
 */
const TIME_BUDGET_MS_DEFAULT = 45_000;
/** A certificate or key is a few KB. Anything past this is not one. */
const MAX_FILE_BYTES = 256 * 1024;
/** Keystores can hold many entries. */
const MAX_KEYSTORE_BYTES = 4 * 1024 * 1024;
/**
 * A file with at least this many certificates, ALL self-signed CAs, under
 * a DEFAULT root is a copy of a public trust bundle (certifi, the distro
 * ca-bundle, Homebrew's cert.pem). Inventorying it root by root would add
 * ~140 fleet-identical rows per copy and push real certificates out of
 * the item cap. It is counted instead (`trustBundlesSkipped`). A private
 * CA bundle is a handful of certificates and never trips this.
 */
const TRUST_BUNDLE_MIN = 40;

const CERT_PEM_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const PRIVATE_KEY_RE = /-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/;

export type FileRoot = { path: string; origin: "default" | "configured" };

/** What one file yielded. Cached by (path, size, mtime); holds NO key material. */
export type FileScanRecord = {
  origin: "default" | "configured";
  kind: "pem" | "der" | "pkcs12" | "jks" | "jceks" | "key" | "none";
  /** Certificates as base64 DER — public data. */
  certs: Array<{ der: string; hasPrivateKey: boolean }>;
  keys: KeyFacts[];
  /** A keystore that exists and could not be opened. */
  unreadableReason?: string;
  trustBundle?: boolean;
};

export interface FileScanCache {
  get(path: string, size: number, mtimeMs: number): FileScanRecord | undefined;
  put(path: string, size: number, mtimeMs: number, record: FileScanRecord): void;
  prune(seen: Set<string>, keepPrefixes: string[]): void;
}

export type CollectCertFilesOptions = {
  timeBudgetMs?: number;
  maxFiles?: number;
  cache?: FileScanCache;
  /** Realpaths already inventoried elsewhere (configured Java keystores). */
  excludeRealPaths?: Set<string>;
  /** Absolute paths never walked (default-root exclusions). */
  excludePaths?: string[];
  /** Test seam. */
  clock?: () => number;
};

export type CertFileKey = KeyFacts & { path: string };

export type CertFileResult = {
  items: CdpCertItem[];
  stores: CdpStoreInfo[];
  parseFailures: number;
  filesScanned: number;
  /** Files that looked like certificates/keystores and could not be read. */
  unreadable: number;
  /** The same, by path: each file is its own store (`file:<path>`). */
  unreadableFiles: string[];
  /** Why, when there is something better to say than "unreadable" — a
   *  PKCS#12 that needs a password is not the same as EACCES. */
  unreadableReasons: Record<string, string>;
  /** Directories under a CONFIGURED root that exist and could not be
   *  listed. Reported as prefix stores, so only THEIR certificates are
   *  exempt from removal. */
  unreadableDirs: string[];
  /** Directories/files under a DEFAULT root without permission (the Linux
   *  agent runs unprivileged: /etc/ssl/private, postgres data dirs...).
   *  Expected, so not reported one by one — the caller only protects the
   *  ones under which something was inventoried before. */
  deniedPaths: string[];
  /** Why the walk stopped early, or null. */
  truncated: "time" | "files" | null;
  /** Kept for callers of the old contract: true when the file cap was hit. */
  capped: boolean;
  /** Roots the walk did not finish. */
  incompleteRoots: string[];
  keys: CertFileKey[];
  keystores: number;
  trustBundlesSkipped: number;
  cacheHits: number;
  elapsedMs: number;
};

/**
 * Every certificate in one file's bytes.
 *
 * PEM bundles legitimately hold a chain, so a single file can yield
 * several. Exported for tests: the private-key skip is the rule most
 * worth pinning, and it must hold on content rather than on the name.
 */
export function certificatesInBuffer(buf: Buffer, filePath: string): Buffer[] {
  const text = buf.toString("latin1");

  // A PEM that carries a private key yields NO certificates — not
  // stripped of the key and parsed for the rest. The key itself is
  // described by private-key-info (presence only).
  if (PRIVATE_KEY_RE.test(text)) {
    return [];
  }

  const pems = text.match(CERT_PEM_RE);
  if (pems && pems.length > 0) {
    return pems.map((pem) => Buffer.from(pem, "utf8"));
  }

  // No PEM armour: treat as DER if the extension says so and it starts
  // like a SEQUENCE. Guessing on content alone would mean handing random
  // binaries to the parser.
  const ext = path.extname(filePath).toLowerCase();
  if ((ext === ".der" || ext === ".cer" || ext === ".crt") && buf.length > 2 && buf[0] === 0x30) {
    return [buf];
  }

  return [];
}

function isCandidate(name: string): boolean {
  const ext = path.extname(name).toLowerCase();
  return CERT_EXTENSIONS.has(ext) || KEYSTORE_EXTENSIONS.has(ext) || KEY_EXTENSIONS.has(ext) || KEYSTORE_NAMES.has(name.toLowerCase());
}

function sizeCapFor(name: string): number {
  const ext = path.extname(name).toLowerCase();
  if (KEYSTORE_EXTENSIONS.has(ext) || KEYSTORE_NAMES.has(name.toLowerCase()) || ext === ".p12" || ext === ".pfx") {
    return MAX_KEYSTORE_BYTES;
  }
  return MAX_FILE_BYTES;
}

/** `dir` + separator, so `/opt` never matches `/optx`. Exported for the caller's prefix stores. */
export function dirPrefix(dir: string): string {
  const trimmed = dir.length > 1 ? dir.replace(/[\\/]+$/, "") : dir;
  const sep = /^[a-zA-Z]:\\/.test(trimmed) || trimmed.includes("\\") ? "\\" : path.sep;
  return trimmed.endsWith(sep) ? trimmed : trimmed + sep;
}

function norm(p: string, win: boolean): string {
  const t = p.replace(/[\\/]+$/, "");
  return win ? t.toLowerCase() : t;
}

/**
 * Raíces por defecto por SO, y lo que se excluye debajo de ellas.
 *
 * El criterio: dónde apuntan los ficheros de configuración de los
 * servicios, no «todo el disco». Nada de /home, /Users ni C:\Users: son
 * datos personales (y las claves SSH de usuario son la ola 1.4, con su
 * propio tratamiento). Lo que ya leen los proveedores de almacén (el
 * bundle de la distro, /etc/ssl/certs, /etc/pki/ca-trust) se excluye para
 * no inventariar dos veces las mismas raíces con dos identidades.
 */
export function defaultFileDiscoveryRoots(
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv = process.env
): { roots: string[]; exclude: string[] } {
  if (platform === "linux") {
    return {
      roots: [
        // /etc entero y no una lista de servicios: es pequeño (miles de
        // ficheros, no millones) y cada servicio pone sus certificados en
        // un sitio distinto (nginx, apache2, httpd, haproxy, postfix,
        // dovecot, openvpn, ipsec.d, kubernetes, docker/certs.d, ldap,
        // letsencrypt...). Una lista siempre se deja alguno.
        "/etc",
        "/usr/local/etc",
        // Software de terceros y datos servidos: donde viven los
        // keystores de Tomcat/Jira/Confluence y los certificados de
        // aplicaciones instaladas a mano.
        "/opt",
        "/srv",
        // /var/lib con cuidado: aquí están los datos de postgres, kubelet
        // pki, grafana, jenkins... pero también las capas de Docker y las
        // bases de paquetes, que DEFAULT_SKIP_NAMES corta.
        "/var/lib"
      ],
      exclude: [
        "/etc/ssl/certs",           // proveedor linux (fs/etc-ssl-certs)
        "/etc/pki/ca-trust",        // bundle de la distro (fs/ca-trust-bundle)
        "/etc/pki/tls/certs",       // proveedor linux (fs/etc-pki-tls-certs)
        "/etc/ca-certificates",
        "/usr/local/share/ca-certificates",
        "/etc/alternatives",
        "/etc/tracenium",
        "/var/lib/tracenium",
        "/var/lib/kubelet/pods",    // un ca.crt de service account por pod
        // Capas de contenedores: sistemas de ficheros enteros de imágenes
        // (inventariar imágenes es la ola 4.4, no esto).
        "/var/lib/docker",
        "/var/lib/containerd",
        "/var/lib/snapd",
        "/var/lib/flatpak",
        "/var/lib/lxd",
        "/var/lib/lxcfs",
        // Bases de paquetes.
        "/var/lib/dpkg",
        "/var/lib/apt",
        "/var/lib/rpm",
        "/var/lib/yum",
        "/var/lib/dnf",
        "/var/lib/PackageKit"
      ]
    };
  }
  if (platform === "darwin") {
    return {
      roots: [
        "/private/etc",
        "/usr/local/etc",
        "/opt/homebrew/etc",
        // /Library: aplicaciones de servidor y agentes de terceros ponen
        // aquí sus identidades (Application Support/<vendor>).
        "/Library",
        "/opt"
      ],
      exclude: [
        "/private/etc/ssl/cert.pem",  // bundle del sistema (ya en el almacén de raíces)
        "/Library/Caches",
        "/Library/Developer",         // Command Line Tools / Xcode: miles de ficheros de prueba
        "/Library/Frameworks",        // Python.framework & co.: certifi y tests
        "/Library/Java",              // JVMs: sus cacerts los lee el proveedor Java
        "/Library/Keychains",         // keychains: proveedor macOS
        "/Library/Application Support/Tracenium",
        "/opt/homebrew"               // el árbol de Homebrew; su etc/ es raíz propia
      ]
    };
  }
  if (platform === "win32") {
    const programData = env.ProgramData || env.PROGRAMDATA || "C:\\ProgramData";
    const programFiles = env.ProgramFiles || env.PROGRAMFILES || "C:\\Program Files";
    const programFilesX86 = env["ProgramFiles(x86)"] || env["PROGRAMFILES(X86)"] || "C:\\Program Files (x86)";
    const systemDrive = env.SystemDrive || "C:";
    return {
      roots: [programData, programFiles, programFilesX86, `${systemDrive}\\inetpub`],
      exclude: [
        // Windows guarda sus propias claves de máquina aquí (sin
        // extensión, pero es gigante) y el resto es Defender, WER, menú
        // inicio... El almacén de certificados lo lee el PrivSvc.
        `${programData}\\Microsoft`,
        `${programData}\\Package Cache`,
        `${programData}\\Tracenium`,
        `${programFiles}\\Tracenium`,
        `${programFiles}\\Java`,        // cacerts: proveedor Java
        `${programFilesX86}\\Java`,
        `${programFiles}\\WindowsApps`,
        `${programFiles}\\Windows Defender`,
        `${programFiles}\\Common Files\\microsoft shared`
      ]
    };
  }
  return { roots: [], exclude: [] };
}

type WalkState = {
  started: number;
  clock: () => number;
  timeBudgetMs: number;
  filesLeft: number;
  stopped: "time" | "files" | null;
};

/** Walk one root, bounded in depth, file count and time. */
async function* walk(
  dir: string,
  depth: number,
  origin: FileRoot["origin"],
  state: WalkState,
  excluded: Set<string>,
  win: boolean,
  onDirError: (dir: string) => void
): AsyncGenerator<string> {
  if (depth > MAX_DEPTH || state.stopped) return;
  if (excluded.has(norm(dir, win))) return;

  let entries: fs.Dirent[];
  try {
    entries = await fs.promises.readdir(dir, { withFileTypes: true });
  } catch (err: any) {
    // Not worth failing the scan for — but worth SAYING: a directory that
    // exists and cannot be listed hides stores we inventoried yesterday.
    if (err?.code !== "ENOENT" && err?.code !== "ENOTDIR") onDirError(dir);
    return;
  }
  // Orden estable: con un presupuesto, el corte tiene que caer siempre en
  // el mismo sitio, o dos escaneos seguidos verían conjuntos distintos.
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  for (const entry of entries) {
    if (state.stopped) return;
    if (state.clock() - state.started > state.timeBudgetMs) {
      state.stopped = "time";
      return;
    }
    const full = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      if (origin === "default" && (DEFAULT_SKIP_NAMES.has(entry.name) || entry.name.toLowerCase() === "tracenium")) continue;
      // Symlinks are not followed: a link back up the tree turns a
      // bounded walk into an unbounded one, and a link into someone's
      // home directory turns an inventory into a privacy incident.
      // (A Dirent for a symlink is never isDirectory(), so this is
      // guaranteed by readdir itself; symlinked FILES are skipped below.)
      yield* walk(full, depth + 1, origin, state, excluded, win, onDirError);
      continue;
    }

    if (!entry.isFile()) continue;
    if (!isCandidate(entry.name)) continue;
    if (excluded.has(norm(full, win))) continue;
    if (state.filesLeft <= 0) {
      state.stopped = "files";
      return;
    }
    state.filesLeft -= 1;
    yield full;
  }
}

/** Read and classify one file. Never throws. */
function scanBuffer(buf: Buffer, filePath: string, origin: FileRoot["origin"]): FileScanRecord {
  const record: FileScanRecord = { origin, kind: "none", certs: [], keys: [] };

  if (looksLikeJks(buf) || looksLikeJceks(buf)) {
    record.kind = looksLikeJks(buf) ? "jks" : "jceks";
    try {
      for (const entry of parseJks(buf)) {
        entry.certsDer.forEach((der, idx) =>
          record.certs.push({ der: der.toString("base64"), hasPrivateKey: entry.type === "key" && idx === 0 })
        );
      }
    } catch (err: any) {
      record.certs = [];
      record.unreadableReason = `${record.kind}: ${String(err?.message || "malformed").slice(0, 200)}`;
    }
    return record;
  }

  // PKCS#12 por ESTRUCTURA, no por nombre: un `keystore.p12` de Tomcat,
  // un `.pfx` de IIS o un `store` sin extensión son lo mismo.
  if (looksLikePkcs12(buf)) {
    record.kind = "pkcs12";
    try {
      for (const c of readPkcs12Certificates(buf)) {
        record.certs.push({ der: c.der.toString("base64"), hasPrivateKey: c.hasPrivateKey });
      }
    } catch (err) {
      // Un PFX que no abrimos NO es un fichero vacío: si ayer tenía
      // certificados, hoy no son bajas (2a80f2c). La razón nunca lleva
      // bytes del fichero.
      record.certs = [];
      record.unreadableReason = err instanceof Pkcs12Error ? `pkcs12: ${err.message}` : "pkcs12: malformed";
    }
    return record;
  }

  const keys = describePrivateKeys(buf);
  if (keys.length > 0) {
    record.kind = "key";
    record.keys = keys;
    return record;
  }

  const blobs = certificatesInBuffer(buf, filePath);
  if (blobs.length > 0) {
    record.kind = blobs.length === 1 && blobs[0] === buf ? "der" : "pem";
    record.certs = blobs.map((b) => ({ der: pemOrDerToDerBase64(b), hasPrivateKey: false }));
  }
  return record;
}

function pemOrDerToDerBase64(b: Buffer): string {
  const text = b.toString("latin1");
  if (text.startsWith("-----BEGIN CERTIFICATE-----")) {
    return text.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/[^A-Za-z0-9+/=]/g, "");
  }
  return b.toString("base64");
}

/**
 * Certificates, keystores and loose keys under the given roots.
 *
 * Plain strings are CONFIGURED roots (the pre-ola-1 contract). The caller
 * builds the default roots with defaultFileDiscoveryRoots.
 */
export async function collectCertFiles(
  rootsIn: Array<string | FileRoot>,
  options: CollectCertFilesOptions = {}
): Promise<CertFileResult> {
  const clock = options.clock ?? Date.now;
  const started = clock();
  const result: CertFileResult = {
    items: [],
    stores: [],
    parseFailures: 0,
    filesScanned: 0,
    unreadable: 0,
    unreadableFiles: [],
    unreadableReasons: {},
    unreadableDirs: [],
    deniedPaths: [],
    truncated: null,
    capped: false,
    incompleteRoots: [],
    keys: [],
    keystores: 0,
    trustBundlesSkipped: 0,
    cacheHits: 0,
    elapsedMs: 0
  };
  const roots: FileRoot[] = (Array.isArray(rootsIn) ? rootsIn : [])
    .map((r) => (typeof r === "string" ? { path: r, origin: "configured" as const } : r))
    .filter((r) => r && typeof r.path === "string" && r.path.length > 0);
  if (roots.length === 0) return result;

  const win = process.platform === "win32";
  const excluded = new Set((options.excludePaths ?? []).map((p) => norm(p, win)));
  const state: WalkState = {
    started,
    clock,
    timeBudgetMs: options.timeBudgetMs ?? TIME_BUDGET_MS_DEFAULT,
    filesLeft: options.maxFiles ?? MAX_FILES_DEFAULT,
    stopped: null
  };
  const seenStores = new Map<string, CdpStoreInfo>();
  const visited = new Set<string>();

  for (let r = 0; r < roots.length; r++) {
    const root = roots[r];
    if (state.stopped) {
      result.incompleteRoots.push(root.path);
      continue;
    }
    // Una raíz del operador dentro de una por defecto (o al revés) no
    // puede inventariar el mismo fichero dos veces con dos orígenes.
    const onDirError = (dir: string) => {
      if (root.origin === "configured") result.unreadableDirs.push(dir);
      else result.deniedPaths.push(dir);
    };
    // La exclusión por defecto no aplica a lo que el operador pidió.
    const rootExcluded = root.origin === "default" ? excluded : new Set<string>();

    for await (const filePath of walk(root.path, 0, root.origin, state, rootExcluded, win, onDirError)) {
      const key = norm(filePath, win);
      if (visited.has(key)) continue;
      visited.add(key);
      result.filesScanned += 1;

      let stat: fs.Stats;
      try {
        stat = await fs.promises.stat(filePath);
      } catch {
        continue; // se fue entre el readdir y el stat
      }
      if (stat.size === 0 || stat.size > sizeCapFor(path.basename(filePath))) continue;

      if (options.excludeRealPaths && options.excludeRealPaths.size > 0) {
        try {
          if (options.excludeRealPaths.has(await fs.promises.realpath(filePath))) continue;
        } catch {
          // sin realpath no hay duplicado que evitar
        }
      }

      let record = options.cache?.get(filePath, stat.size, stat.mtimeMs);
      if (record && record.origin !== root.origin) record = undefined;
      if (record) {
        result.cacheHits += 1;
      } else {
        let buf: Buffer;
        try {
          buf = await fs.promises.readFile(filePath);
        } catch {
          // Sin permiso. Un fichero con nombre de clave se dice como
          // clave ilegible (su existencia ES el dato); lo demás es un
          // almacén que no se pudo mirar.
          if (KEY_EXTENSIONS.has(path.extname(filePath).toLowerCase())) {
            result.keys.push({ path: filePath, format: "unknown", encrypted: null, readable: false });
          } else if (root.origin === "configured") {
            result.unreadable += 1;
            result.unreadableFiles.push(filePath);
          } else {
            result.deniedPaths.push(filePath);
          }
          continue;
        }
        record = scanBuffer(buf, filePath, root.origin);
        // Si llevaba una clave, que sus bytes no se queden en memoria más
        // de lo necesario.
        if (record.kind === "key") buf.fill(0);
        options.cache?.put(filePath, stat.size, stat.mtimeMs, record);
      }

      emitRecord(record, filePath, root.origin, result, seenStores, options.cache, stat);
    }

    if (state.stopped) result.incompleteRoots.push(root.path);
  }

  result.truncated = state.stopped;
  result.capped = state.stopped === "files";
  result.stores = [...seenStores.values()];
  result.elapsedMs = clock() - started;
  if (options.cache) {
    try {
      options.cache.prune(visited, result.incompleteRoots.map(dirPrefix));
    } catch {
      // la caché es una optimización; su fallo no cuesta el escaneo
    }
  }
  return result;
}

function emitRecord(
  record: FileScanRecord,
  filePath: string,
  origin: FileRoot["origin"],
  result: CertFileResult,
  seenStores: Map<string, CdpStoreInfo>,
  cache: FileScanCache | undefined,
  stat: fs.Stats
): void {
  if (record.kind === "pkcs12" || record.kind === "jks" || record.kind === "jceks") result.keystores += 1;

  for (const k of record.keys) result.keys.push({ ...k, path: filePath });

  if (record.unreadableReason) {
    // Un keystore que no abre se dice SIEMPRE, también bajo una raíz por
    // defecto: es exactamente lo que el operador necesita saber.
    result.unreadable += 1;
    result.unreadableFiles.push(filePath);
    result.unreadableReasons[filePath] = record.unreadableReason;
    return;
  }
  if (record.trustBundle) {
    result.trustBundlesSkipped += 1;
    return;
  }
  if (record.certs.length === 0) return;

  const store: CdpStoreInfo = {
    id: `file:${filePath}`,
    name: filePath,
    // A certificate in a config directory is infrastructure, same as
    // one in a machine store — not an OS trust anchor.
    scope: "machine"
  };
  const source: CdpCertItem["source"] = record.kind === "jks" || record.kind === "jceks" ? "java-store" : "file";

  const parsed: CdpCertItem[] = [];
  for (const c of record.certs) {
    const item = parseCertToItem(Buffer.from(c.der, "base64"), {
      store,
      hasPrivateKey: c.hasPrivateKey,
      // La clave de un fichero vive en software y es tan extraíble como
      // el fichero: no hay política de exportación que consultar.
      ...(c.hasPrivateKey ? { keyStorage: "software" as const, keyExportable: true } : {})
    });
    if (item) parsed.push({ ...item, source });
    else result.parseFailures += 1;
  }

  if (origin === "default" && parsed.length >= TRUST_BUNDLE_MIN && parsed.every((i) => i.isCA && i.selfSigned)) {
    result.trustBundlesSkipped += 1;
    // Se recuerda como bundle: la próxima vez ni se parsea.
    try {
      cache?.put(filePath, stat.size, stat.mtimeMs, { ...record, certs: [], trustBundle: true });
    } catch {
      // optimización
    }
    return;
  }

  seenStores.set(store.id, store);
  result.items.push(...parsed);
}
