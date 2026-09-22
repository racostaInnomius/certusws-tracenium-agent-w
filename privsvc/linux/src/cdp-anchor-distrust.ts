// privsvc/linux/src/cdp-anchor-distrust.ts
//
// Quitar la confianza a un ancla en Linux. ADR-0011, decision 10.
//
// Gemelo de `CdpAnchorDistrust.cs` (Windows → store Disallowed) y de
// `privsvc/macos/src/anchor-distrust.ts` (trust setting deny). Mismo
// contrato IPC: entra `{ thumbprint, sha1 }`, sale
// `{ distrusted, sha1, subject }` o un error con código. Hasta ahora
// Linux no tenía ruta: el job `cdp_anchor_distrust` llegaba al privsvc y
// moría en "unknown method".
//
// ⚠️ La huella puede ser SHA-1 (40 hex, lo que esperan Windows y macOS)
// o SHA-256 (64 hex). Se aceptan las dos a propósito: la UI de CDP manda
// `fingerprint256` —es la clave con la que el inventario identifica un
// ancla—, y el backend lo reenvía tal cual como `thumbprint` y `sha1`.
//
// ── El mecanismo depende de la distro, y no hay uno común ────────────
//
//   RHEL/Fedora/Alma/Rocky/Amazon (p11-kit, `update-ca-trust`):
//     el PEM va a /etc/pki/ca-trust/source/blocklist/ (en versiones
//     viejas `blacklist/`) y se regenera con `update-ca-trust extract`.
//     p11-kit hace que la lista de bloqueo GANE a cualquier ancla, venga
//     del paquete o de source/anchors — equivalente exacto a Disallowed.
//   SUSE (p11-kit, `update-ca-certificates` propio de SUSE):
//     mismo modelo en /etc/pki/trust/blocklist/ (o `blacklist/`).
//   Debian/Ubuntu (`ca-certificates`):
//     no hay lista de bloqueo. `update-ca-certificates` solo conoce dos
//     fuentes: las líneas de /etc/ca-certificates.conf (rutas bajo
//     /usr/share/ca-certificates; un `!` delante las DESELECCIONA, y el
//     postinst del paquete lo respeta en cada actualización) y todo
//     `*.crt` de /usr/local/share/ca-certificates, que entra SIEMPRE. Para
//     el primero se antepone `!`; para el segundo se renombra el fichero
//     a `*.crt.tracenium-distrusted` — sigue en disco (reversible
//     quitando el sufijo), pero deja de ser `*.crt`. Es el caso que más
//     importa: una CA de inspección TLS plantada a mano vive ahí.
//     Se regenera con `--fresh` porque OpenSSL no solo lee el bundle:
//     también busca por los enlaces con hash de /etc/ssl/certs, y un
//     enlace colgado de un ancla ya retirada seguiría dando confianza.
//
// Si no se reconoce ninguno se devuelve `trust_store_unsupported`. Fingir
// éxito aquí sería la peor respuesta posible: el portal diría
// «remediado» sobre un equipo que sigue confiando.
//
// ── Mismas salvaguardas que las otras dos plataformas ───────────────
//
// El control plane NUNCA manda material de certificado: se opera por
// huella y el PEM que se escribe en la lista de bloqueo es el que el
// propio equipo ya tenía en su trust store. Por esta ruta un control
// plane comprometido no puede introducir nada, solo retirar confianza.
// Además: jamás un ancla de la cadena propia del agente, jamás un ancla
// ausente, la huella se valida (40 hex) antes de usarse en un nombre de
// fichero, y los comandos van por execFile, sin shell.
//
// ── La verificación es parte de la operación ────────────────────────
//
// Tras regenerar se vuelve a leer lo que el sistema REALMENTE usa (los
// bundles extraídos y el directorio de hashes). Si la huella sigue ahí
// se devuelve `distrust_not_effective`: un «ok» sin comprobar es la
// clase de falso verde que ya nos costó en los despliegues.

import crypto from "crypto";
import fs from "fs";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import { certPaths } from "./paths";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";

const execFileAsync = promisify(execFile);

/**
 * Techo de la regeneración. `update-ca-certificates` en Debian corre los
 * hooks de /etc/ca-certificates/update.d (el de Java reescribe cacerts y
 * tarda segundos). El cliente IPC espera más — ver privsvc-client-linux.
 */
export const REBUILD_TIMEOUT_MS = 60_000;
/** Un bundle del sistema ronda los 200 KB; el tope es para no leer basura. */
const MAX_READ_BYTES = 4 * 1024 * 1024;
const MAX_LOCAL_DEPTH = 3;

export const DISTRUSTED_SUFFIX = ".tracenium-distrusted";

const DEBIAN_CONF = "/etc/ca-certificates.conf";
const DEBIAN_SHARE = "/usr/share/ca-certificates";
const DEBIAN_LOCAL = "/usr/local/share/ca-certificates";

/** Todo el acceso al sistema pasa por aquí, para poder probarlo con fakes. */
export type DistrustDeps = {
  exists(p: string): boolean;
  /** Lanza si no se puede leer. */
  readFile(p: string): string;
  /** Nombres de entradas + si son directorio. Lanza si no se puede listar. */
  readDir(p: string): { name: string; dir: boolean }[];
  writeFile(p: string, data: string): void;
  rename(from: string, to: string): void;
  exec(bin: string, args: string[], timeoutMs: number): Promise<{ stdout: string; stderr: string }>;
  /** Ficheros con los certificados en los que confía el propio agente. */
  ownAnchorFiles(): string[];
};

export const realDeps: DistrustDeps = {
  exists: (p) => fs.existsSync(p),
  readFile: (p) => {
    const st = fs.statSync(p);
    if (st.size > MAX_READ_BYTES) throw new Error(`${p}: too large`);
    return fs.readFileSync(p, "utf8");
  },
  readDir: (p) =>
    fs.readdirSync(p, { withFileTypes: true }).map((e) => ({ name: e.name, dir: e.isDirectory() })),
  writeFile: (p, data) => {
    // Atómico: escribir al lado y renombrar. Un /etc/ca-certificates.conf
    // a medio escribir rompería la próxima actualización del paquete.
    const tmp = `${p}.tracenium-tmp`;
    fs.writeFileSync(tmp, data, { encoding: "utf8", mode: 0o644 });
    fs.renameSync(tmp, p);
  },
  rename: (from, to) => fs.renameSync(from, to),
  exec: async (bin, args, timeoutMs) => {
    const { stdout, stderr } = await execFileAsync(bin, args, {
      timeout: timeoutMs,
      maxBuffer: 4 * 1024 * 1024
    });
    return { stdout: String(stdout || ""), stderr: String(stderr || "") };
  },
  ownAnchorFiles: () => {
    const p = certPaths();
    return [p.caBundle, p.bundledRootCa];
  }
};

export type Mechanism =
  | {
      kind: "p11kit";
      family: "rhel" | "suse";
      blocklistDir: string;
      rebuild: [string, string[]];
      bundles: string[];
      hashDirs: string[];
    }
  | {
      kind: "debian";
      family: "debian";
      rebuild: [string, string[]];
      bundles: string[];
      hashDirs: string[];
    };

export type DistrustOutcome =
  | {
      ok: true;
      sha1: string | null;
      sha256: string | null;
      subject: string | null;
      mechanism: string;
      family: string;
      alreadyDistrusted: boolean;
      changed: string[];
    }
  | { ok: false; code: string; message: string };

// ── Certificados ─────────────────────────────────────────────────────

const PEM_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

export function normalizeFingerprint(value: unknown): string {
  return String(value ?? "").replace(/[^0-9a-fA-F]/g, "").toUpperCase();
}

function pemsIn(text: string): string[] {
  return text.match(PEM_RE) ?? [];
}

function derOf(pem: string): Buffer {
  return Buffer.from(pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, ""), "base64");
}

export function fingerprintOfPem(pem: string, algo: "sha1" | "sha256"): string {
  return crypto.createHash(algo).update(derOf(pem)).digest("hex").toUpperCase();
}

/** La huella buscada dice con qué se compara: 40 hex → SHA-1, 64 → SHA-256. */
const algoOf = (fp: string): "sha1" | "sha256" => (fp.length === 64 ? "sha256" : "sha1");

function subjectOf(pem: string): string | null {
  try {
    return new crypto.X509Certificate(pem).subject.split("\n").join(", ");
  } catch {
    return null;
  }
}

function pemInText(text: string, fp: string): string | null {
  return pemsIn(text).find((p) => fingerprintOfPem(p, algoOf(fp)) === fp) ?? null;
}

function pemInFile(deps: DistrustDeps, file: string, fp: string): string | null {
  try {
    return pemInText(deps.readFile(file), fp);
  } catch {
    return null;
  }
}

// ── Detección ────────────────────────────────────────────────────────

function firstExisting(deps: DistrustDeps, paths: string[]): string | null {
  return paths.find((p) => deps.exists(p)) ?? null;
}

const binCandidates = (name: string) => [`/usr/sbin/${name}`, `/usr/bin/${name}`, `/sbin/${name}`, `/bin/${name}`];

/**
 * El mecanismo de ESTE equipo, por las herramientas y directorios que
 * hay — no por /etc/os-release: un derivado raro con el ID que no
 * conocemos sigue teniendo (o no) `update-ca-trust`, y eso es lo que
 * decide si la operación funciona.
 */
export function detectMechanism(deps: DistrustDeps): Mechanism | { unsupported: string } {
  const updateCaTrust = firstExisting(deps, binCandidates("update-ca-trust"));
  if (updateCaTrust && deps.exists("/etc/pki/ca-trust/source")) {
    const blocklistDir = firstExisting(deps, [
      "/etc/pki/ca-trust/source/blocklist",
      "/etc/pki/ca-trust/source/blacklist"
    ]);
    if (!blocklistDir) {
      return { unsupported: "update-ca-trust present but no source/blocklist (or blacklist) directory" };
    }
    const pemDir = "/etc/pki/ca-trust/extracted/pem";
    return {
      kind: "p11kit",
      family: "rhel",
      blocklistDir,
      rebuild: [updateCaTrust, ["extract"]],
      bundles: ["tls-ca-bundle.pem", "email-ca-bundle.pem", "objsign-ca-bundle.pem"].map((f) => path.join(pemDir, f)),
      hashDirs: [path.join(pemDir, "directory-hash")]
    };
  }

  const updateCaCertificates = firstExisting(deps, binCandidates("update-ca-certificates"));
  if (updateCaCertificates && deps.exists("/etc/pki/trust")) {
    const blocklistDir = firstExisting(deps, ["/etc/pki/trust/blocklist", "/etc/pki/trust/blacklist"]);
    if (!blocklistDir) {
      return { unsupported: "/etc/pki/trust present but no blocklist (or blacklist) directory" };
    }
    return {
      kind: "p11kit",
      family: "suse",
      blocklistDir,
      rebuild: [updateCaCertificates, []],
      bundles: ["/var/lib/ca-certificates/ca-bundle.pem"],
      hashDirs: ["/var/lib/ca-certificates/pem"]
    };
  }

  if (updateCaCertificates && deps.exists(DEBIAN_CONF)) {
    return {
      kind: "debian",
      family: "debian",
      rebuild: [updateCaCertificates, ["--fresh"]],
      bundles: ["/etc/ssl/certs/ca-certificates.crt"],
      hashDirs: ["/etc/ssl/certs"]
    };
  }

  return {
    unsupported:
      "no supported trust-store mechanism found (need update-ca-trust + /etc/pki/ca-trust, " +
      "SUSE /etc/pki/trust, or Debian /etc/ca-certificates.conf)"
  };
}

// ── Lo que el sistema usa de verdad ──────────────────────────────────

/**
 * ¿Confía hoy el sistema en esta huella? Se mira lo EXTRAÍDO (bundles y
 * directorio de hashes), no las fuentes: es lo que leen OpenSSL, curl y
 * compañía, y por tanto lo único que responde la pregunta.
 */
export function findTrusted(deps: DistrustDeps, mech: Mechanism, fp: string): string | null {
  for (const bundle of mech.bundles) {
    if (!deps.exists(bundle)) continue;
    const pem = pemInFile(deps, bundle, fp);
    if (pem) return pem;
  }
  for (const dir of mech.hashDirs) {
    if (!deps.exists(dir)) continue;
    let entries: { name: string; dir: boolean }[];
    try {
      entries = deps.readDir(dir);
    } catch {
      continue;
    }
    for (const e of entries) {
      if (e.dir) continue;
      const full = path.join(dir, e.name);
      // El bundle ya se leyó arriba; releerlo 150 veces no aporta nada.
      if (mech.bundles.includes(full)) continue;
      const pem = pemInFile(deps, full, fp);
      if (pem) return pem;
    }
  }
  return null;
}

// ── Debian: dónde está la fuente de esa ancla ────────────────────────

type DebianSources = {
  /** Índices de líneas activas del .conf cuyo fichero contiene la huella. */
  confLines: number[];
  /** Ya deseleccionada con `!`. */
  confDeselected: boolean;
  lines: string[];
  /** *.crt de /usr/local/share/ca-certificates con la huella. */
  localFiles: string[];
  /** Ya renombrados por nosotros. */
  localDistrusted: boolean;
};

function underDir(root: string, rel: string): string | null {
  const full = path.resolve(root, rel);
  return full.startsWith(root + path.sep) ? full : null;
}

function walkLocal(deps: DistrustDeps, dir: string, depth: number, out: string[]): void {
  if (depth > MAX_LOCAL_DEPTH) return;
  let entries: { name: string; dir: boolean }[];
  try {
    entries = deps.readDir(dir);
  } catch {
    return;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.dir) walkLocal(deps, full, depth + 1, out);
    else out.push(full);
  }
}

function debianSources(deps: DistrustDeps, fp: string): DebianSources {
  const text = deps.readFile(DEBIAN_CONF);
  const lines = text.split("\n");
  const out: DebianSources = { confLines: [], confDeselected: false, lines, localFiles: [], localDistrusted: false };

  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    const deselected = line.startsWith("!");
    const file = underDir(DEBIAN_SHARE, deselected ? line.slice(1).trim() : line);
    if (!file || !pemInFile(deps, file, fp)) return;
    if (deselected) out.confDeselected = true;
    else out.confLines.push(i);
  });

  const files: string[] = [];
  if (deps.exists(DEBIAN_LOCAL)) walkLocal(deps, DEBIAN_LOCAL, 0, files);
  for (const f of files) {
    if (f.endsWith(".crt") && pemInFile(deps, f, fp)) out.localFiles.push(f);
    else if (f.endsWith(`.crt${DISTRUSTED_SUFFIX}`) && pemInFile(deps, f, fp)) out.localDistrusted = true;
  }
  return out;
}

function blocklistFile(mech: Extract<Mechanism, { kind: "p11kit" }>, pem: string): string {
  // El nombre sale del SHA-256 del certificado local, no de la entrada:
  // no hay forma de que la petición meta un `/` o un `..` en la ruta.
  const sha256 = fingerprintOfPem(pem, "sha256").toLowerCase();
  return path.join(mech.blocklistDir, `tracenium-distrust-${sha256}.pem`);
}

/** ¿Hay ya en la lista de bloqueo un fichero con esta huella? (sea nuestro o no) */
function inBlocklist(deps: DistrustDeps, mech: Extract<Mechanism, { kind: "p11kit" }>, fp: string): boolean {
  let entries: { name: string; dir: boolean }[];
  try {
    entries = deps.readDir(mech.blocklistDir);
  } catch {
    return false;
  }
  return entries.some((e) => !e.dir && pemInFile(deps, path.join(mech.blocklistDir, e.name), fp) !== null);
}

function alreadyDistrusted(deps: DistrustDeps, mech: Mechanism, fp: string): boolean {
  if (mech.kind === "p11kit") return inBlocklist(deps, mech, fp);
  try {
    const src = debianSources(deps, fp);
    return src.confDeselected || src.localDistrusted;
  } catch {
    return false;
  }
}

// ── La operación ─────────────────────────────────────────────────────

export async function distrustAnchor(rawFingerprint: unknown, deps: DistrustDeps = realDeps): Promise<DistrustOutcome> {
  const fp = normalizeFingerprint(rawFingerprint);
  if (fp.length !== 40 && fp.length !== 64) {
    return { ok: false, code: "invalid_params", message: "certificate fingerprint (SHA-1 or SHA-256 hex) is required" };
  }

  const detected = detectMechanism(deps);
  if ("unsupported" in detected) {
    return { ok: false, code: "trust_store_unsupported", message: detected.unsupported };
  }
  const mech = detected;
  const mechanismName = mech.kind === "p11kit" ? "p11-kit-blocklist" : "ca-certificates.conf";

  // ── Salvaguarda 1: jamás la cadena propia del agente ──────────────
  //
  // En Linux el agente confía en un bundle PRIVADO (crypto-store no
  // toca el trust store del sistema), así que retirar un ancla del
  // sistema no debería cortarle el mTLS. Se comprueba igual: la barrera
  // es la misma en las tres plataformas, y se evalúa contra ficheros
  // LOCALES, no contra lo que diga el servidor.
  for (const own of deps.ownAnchorFiles()) {
    if (deps.exists(own) && pemInFile(deps, own, fp)) {
      return {
        ok: false,
        code: "anchor_is_own_chain",
        message: "refusing to distrust an anchor this agent's own certificate chain depends on"
      };
    }
  }

  // ── Salvaguarda 2: tiene que estar presente ───────────────────────
  const pem = findTrusted(deps, mech, fp);
  if (!pem) {
    // Idempotencia: si ya la retiramos nosotros, repetir el job es éxito,
    // no «no está».
    if (alreadyDistrusted(deps, mech, fp)) {
      return {
        ok: true,
        sha1: fp.length === 40 ? fp : null,
        sha256: fp.length === 64 ? fp : null,
        subject: null,
        mechanism: mechanismName,
        family: mech.family,
        alreadyDistrusted: true,
        changed: []
      };
    }
    return {
      ok: false,
      code: "anchor_not_present",
      message: "certificate is not in this machine's trust store; nothing to distrust"
    };
  }
  const subject = subjectOf(pem);
  const changed: string[] = [];

  try {
    if (mech.kind === "p11kit") {
      const target = blocklistFile(mech, pem);
      if (!inBlocklist(deps, mech, fp)) {
        // El PEM que ya estaba en el trust store del equipo, no uno que
        // haya mandado nadie.
        deps.writeFile(target, `${pem}\n`);
        changed.push(target);
      }
    } else {
      const src = debianSources(deps, fp);
      if (src.confLines.length === 0 && src.localFiles.length === 0) {
        // Está en el bundle pero no en ninguna fuente que
        // update-ca-certificates conozca (p. ej. pegado a mano en
        // ca-certificates.crt). No hay forma de desconfiar sin borrar, y
        // borrar no es lo que pide la decisión 10.
        return {
          ok: false,
          code: "anchor_source_unknown",
          message: `anchor is trusted but not listed in ${DEBIAN_CONF} nor under ${DEBIAN_LOCAL}; not distrusted`
        };
      }
      if (src.confLines.length > 0) {
        const lines = [...src.lines];
        for (const i of src.confLines) lines[i] = `!${lines[i].trim()}`;
        deps.writeFile(DEBIAN_CONF, lines.join("\n"));
        changed.push(DEBIAN_CONF);
      }
      for (const f of src.localFiles) {
        deps.rename(f, `${f}${DISTRUSTED_SUFFIX}`);
        changed.push(f);
      }
    }
  } catch (err: any) {
    return { ok: false, code: "distrust_failed", message: `could not write trust configuration: ${err?.message || err}` };
  }

  const [bin, args] = mech.rebuild;
  try {
    await deps.exec(bin, args, REBUILD_TIMEOUT_MS);
  } catch (err: any) {
    return {
      ok: false,
      code: "distrust_failed",
      message:
        `${path.basename(bin)} failed: ${String(err?.stderr || err?.message || err).trim().split("\n")[0]}` +
        (changed.length > 0 ? ` (configuration already changed: ${changed.join(", ")})` : "")
    };
  }

  // ── Verificación ──────────────────────────────────────────────────
  if (findTrusted(deps, mech, fp)) {
    return {
      ok: false,
      code: "distrust_not_effective",
      message:
        `anchor still present in the extracted trust store after ${path.basename(bin)}` +
        (changed.length > 0 ? ` (configuration changed: ${changed.join(", ")})` : "")
    };
  }

  return {
    ok: true,
    sha1: fingerprintOfPem(pem, "sha1"),
    sha256: fingerprintOfPem(pem, "sha256"),
    subject,
    mechanism: mechanismName,
    family: mech.family,
    alreadyDistrusted: changed.length === 0,
    changed
  };
}

export async function handleCdpAnchorDistrust(req: PrivSvcRequest, deps: DistrustDeps = realDeps): Promise<PrivSvcResponse> {
  const p: any = req.params || {};
  // El agente manda las dos claves con la misma huella (Windows lee
  // `thumbprint`, macOS `sha1`). Aquí vale cualquiera, SHA-1 o SHA-256.
  const out = await distrustAnchor(p.sha1 || p.thumbprint, deps);
  if (!out.ok) {
    logger.warn("cdp_anchor_distrust_failed", { code: out.code, message: out.message });
    return fail(req.id, out.code, out.message);
  }
  logger.info("cdp_anchor_distrusted", {
    sha1: out.sha1,
    sha256: out.sha256,
    subject: out.subject,
    mechanism: out.mechanism,
    family: out.family,
    alreadyDistrusted: out.alreadyDistrusted,
    changed: out.changed
  });
  return success(req.id, {
    distrusted: true,
    sha1: out.sha1,
    sha256: out.sha256,
    thumbprint: out.sha1,
    subject: out.subject,
    mechanism: out.mechanism,
    family: out.family,
    alreadyDistrusted: out.alreadyDistrusted,
    changed: out.changed
  });
}
