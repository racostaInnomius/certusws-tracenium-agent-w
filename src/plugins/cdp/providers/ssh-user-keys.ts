// src/plugins/cdp/providers/ssh-user-keys.ts
//
// Ola 1.4 de CDP-VS-KEYFACTOR-2026-09.md — claves SSH POR USUARIO.
//
// Hasta ahora CDP solo veia las claves de HOST del sshd
// (providers/ssh-host-keys.ts). Eso responde «con que identidad se
// presenta este servidor» y deja fuera la pregunta que de verdad hace un
// auditor: **quien puede entrar**. Un `authorized_keys` es una concesion
// de acceso permanente, sin caducidad, sin CA que la revoque y sin
// registro en ningun sitio; es lo mas parecido a una contrasena eterna
// que queda en un parque moderno, y no aparece en ningun inventario.
//
// ── Dos cosas distintas, y la diferencia es el producto ─────────────
//
//   `authorized_keys`  claves que CONCEDEN acceso a esta cuenta. El
//                      riesgo esta aqui: una clave de un portatil que se
//                      perdio en 2021 sigue abriendo la puerta.
//   `*.pub`            claves que el usuario TIENE. Dicen a donde puede
//                      ir esa persona, no quien entra aqui.
//
// Se reportan por separado (`kind`) porque mezclarlas produce un numero
// grande y sin significado.
//
// ── Solo inventario. NUNCA material de clave ────────────────────────
//
// De las claves publicas se lee todo: son publicas por definicion. De
// las PRIVADAS, por defecto, NI SE ABRE EL FICHERO.
//
// ⚠️ POR QUE (22-sep-2026, hecho medido, no una precaucion teorica):
// ejecutar la primera version de este colector en un Mac con CrowdStrike
// disparo una deteccion **High**. Un proceso leyendo `~/.ssh/id_*` ES el
// patron de «credential access» que todos los EDR vigilan, y da igual
// que nosotros no nos quedemos el secreto: lo que el EDR ve es la
// lectura. Un agente de inventario marcado como robo de credenciales en
// la flota del cliente es un incidente para el cliente y una llamada de
// soporte para nosotros.
//
// De ahi los tres modos de `cdp.sshUserKeys`:
//
//   "public-only" (POR DEFECTO)
//        `authorized_keys`, `authorized_keys2` y `*.pub` se LEEN — son
//        publicos por definicion y ningun EDR los vigila. De las
//        privadas solo se hace `stat`: existe, que permisos tiene, que
//        tamano y de cuando es. El tipo y la huella salen del `.pub`
//        hermano cuando esta. `encrypted` queda en null, que ya
//        significa «no se sabe».
//   "full"
//        ademas se lee la CABECERA de las privadas para decir si estan
//        cifradas (el blob publico y el nombre del cifrado van en claro
//        antes de la parte cifrada). Sigue sin leerse un byte del
//        secreto, pero ABRE el fichero — y eso es lo que dispara al EDR.
//        Quien lo encienda necesita exclusiones documentadas.
//   "off"
//        no se mira nada.
//
// La descripcion de formatos PEM la hace private-key-info.ts (ola 1.1),
// que ya tiene esa disciplina escrita, y solo se usa en modo "full".
//
// ── Opciones de authorized_keys: hechos, no juicios ─────────────────
//
// `command="..."`, `from="10.0.0.0/8"`, `no-pty`, `restrict`... se
// reportan tal cual. Una clave con `from=` y `command=` esta acotada y
// una sin nada no lo esta, pero cual de las dos es aceptable depende de
// la politica del cliente, y eso se decide en el control plane (donde se
// puede cambiar sin desplegar la flota), no aqui.

import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";
import type { CdpSshUserKey, CdpSshUserKeys, CdpSshUserPrivateKey } from "../../../domain/cdp-types";
import { parseSshPublicKey } from "./ssh-host-keys";
import { describePrivateKeys } from "../private-key-info";

/** Un authorized_keys enorme es un error de configuracion, no un inventario. */
const MAX_LINES_PER_FILE = 2000;
/** Tope de entradas en el payload. Un bastion legitimo ronda las decenas. */
export const MAX_SSH_USER_KEYS = 1000;
export const MAX_SSH_USER_PRIVATE_KEYS = 300;
/** Usuarios a mirar. Un servidor de terminal acumula perfiles viejos. */
const MAX_USERS = 200;
/** Un fichero de claves de mas de 1 MB no es un fichero de claves. */
const MAX_FILE_BYTES = 1024 * 1024;

/** Ver la cabecera del fichero: "public-only" es el defecto por el EDR. */
export type SshUserKeysMode = "public-only" | "full" | "off";

export type SshUserKeysOptions = {
  platform?: NodeJS.Platform;
  mode?: SshUserKeysMode;
  /** Semilla de test: [usuario, home]. */
  users?: Array<{ user: string; home: string }>;
  /** Semilla de test: rutas de sistema con authorized_keys. */
  systemFiles?: string[];
};

/**
 * Nombres de clave privada de OpenSSH. Se reconoce por el NOMBRE y por
 * tener un `.pub` hermano, nunca abriendo el fichero: las dos señales
 * bastan y ninguna toca el contenido.
 */
const PRIVATE_KEY_NAME_RE = /^(id_[a-z0-9_]+|.*\.(pem|key))$/i;

/**
 * Usuarios y sus directorios personales.
 *
 * En POSIX se lee `/etc/passwd` y no `/home`: un home puede estar en
 * cualquier sitio (`/var/lib/gitolite`, `/opt/app`) y justo esas cuentas
 * de servicio son las que suelen tener un `authorized_keys` que nadie
 * recuerda. Las cuentas sin shell real (`nologin`, `false`) SI se miran:
 * `git` y `rsync` funcionan con `authorized_keys` y shell restringida, y
 * saltarselas esconderia exactamente la concesion mas interesante.
 */
export function localUsers(platform: NodeJS.Platform = os.platform()): Array<{ user: string; home: string }> {
  const out: Array<{ user: string; home: string }> = [];
  const seen = new Set<string>();
  const add = (user: string, home: string) => {
    if (!user || !home || seen.has(home) || out.length >= MAX_USERS) return;
    seen.add(home);
    out.push({ user, home });
  };

  if (platform === "win32") {
    const base = path.join(process.env.SystemDrive || "C:", "\\Users");
    try {
      for (const name of fs.readdirSync(base)) {
        if (["Public", "Default", "Default User", "All Users"].includes(name)) continue;
        add(name, path.join(base, name));
      }
    } catch {
      /* sin perfiles legibles no hay nada que mirar */
    }
    return out;
  }

  // ⚠️ En macOS las cuentas de PERSONA viven en OpenDirectory, no en
  // /etc/passwd — ahi solo estan las del sistema. El fichero EXISTE, asi
  // que el `catch` de abajo nunca salta y sin esto no se miraria ni un
  // solo home real. Se enumera /Users ademas del passwd (y no con `dscl`,
  // que seria un proceso hijo mas que excluir en el EDR).
  if (platform === "darwin") {
    try {
      for (const name of fs.readdirSync("/Users")) {
        if (name.startsWith(".") || ["Shared", "Guest"].includes(name)) continue;
        add(name, path.join("/Users", name));
      }
    } catch {
      /* sin /Users legible no hay homes que mirar */
    }
  }

  try {
    const passwd = fs.readFileSync("/etc/passwd", "utf8");
    for (const line of passwd.split("\n")) {
      const f = line.split(":");
      if (f.length < 6) continue;
      const user = f[0]?.trim();
      const home = f[5]?.trim();
      // Los homes falsos de las cuentas del sistema no existen o son
      // directorios compartidos: mirarlos es ruido garantizado.
      if (!home || home === "/" || home === "/nonexistent" || home === "/dev/null") continue;
      add(user, home);
    }
  } catch {
    // Sin /etc/passwd legible (o en un macOS con usuarios en OpenDirectory)
    // queda el convenio de siempre.
    const base = platform === "darwin" ? "/Users" : "/home";
    try {
      for (const name of fs.readdirSync(base)) {
        if (name.startsWith(".") || ["Shared", "Guest"].includes(name)) continue;
        add(name, path.join(base, name));
      }
    } catch {
      /* nada que mirar */
    }
    add("root", "/root");
  }
  return out;
}

/** Ficheros de claves autorizadas fuera de un home. */
export function systemAuthorizedKeyFiles(platform: NodeJS.Platform = os.platform()): string[] {
  if (platform === "win32") {
    // OpenSSH para Windows: TODA cuenta de administrador entra por este
    // fichero, no por su perfil. Es el authorized_keys mas importante de
    // un Windows y el que nadie mira.
    return [path.join(process.env.ProgramData || "C:\\ProgramData", "ssh", "administrators_authorized_keys")];
  }
  return ["/etc/ssh/authorized_keys", "/etc/ssh/authorized_keys2"];
}

/**
 * Trocea la parte de opciones de una linea de authorized_keys.
 *
 * Las opciones van separadas por comas, pero una comilla puede contener
 * comas y espacios (`command="a,b c"`), asi que no vale un `split(",")`.
 * Devuelve null cuando la linea empieza directamente por el tipo de
 * clave (el caso normal).
 */
export function splitAuthorizedOptions(line: string): { options: string[]; rest: string } {
  const s = line.trim();
  // `ssh-rsa AAAA…`, `ecdsa-sha2-nistp256 …`, `sk-ssh-ed25519@openssh.com …`
  if (/^(ssh-|ecdsa-|sk-|rsa-sha2-|webauthn-)/.test(s)) return { options: [], rest: s };

  const options: string[] = [];
  let current = "";
  let quoted = false;
  let i = 0;
  for (; i < s.length; i += 1) {
    const c = s[i];
    if (quoted) {
      if (c === "\\" && i + 1 < s.length) {
        current += c + s[i + 1];
        i += 1;
        continue;
      }
      if (c === '"') quoted = false;
      current += c;
      continue;
    }
    if (c === '"') {
      quoted = true;
      current += c;
      continue;
    }
    if (c === ",") {
      if (current.trim()) options.push(current.trim());
      current = "";
      continue;
    }
    if (c === " " || c === "\t") {
      // Fuera de comillas, un espacio cierra las opciones: lo que sigue
      // es la clave.
      if (current.trim()) options.push(current.trim());
      return { options, rest: s.slice(i + 1).trim() };
    }
    current += c;
  }
  // Linea sin clave: solo opciones. No es una concesion, es basura.
  if (current.trim()) options.push(current.trim());
  return { options, rest: "" };
}

/** Una linea de authorized_keys → entrada, o null (comentario, vacia, rota). */
export function parseAuthorizedKeyLine(line: string, user: string, filePath: string): CdpSshUserKey | null {
  const s = line.trim();
  if (!s || s.startsWith("#")) return null;
  const { options, rest } = splitAuthorizedOptions(s);
  if (!rest) return null;
  const parts = rest.split(/\s+/);
  const key = parseSshPublicKey(`${parts[0]} ${parts[1] ?? ""}`, filePath, { allowSk: true });
  if (!key) return null;
  const comment = parts.slice(2).join(" ").trim();
  return {
    kind: "authorized",
    user,
    path: filePath,
    keyType: key.keyType,
    algorithm: key.algorithm,
    bits: key.bits,
    curve: key.curve,
    fingerprintSha256: key.fingerprintSha256,
    ...(comment ? { comment: comment.slice(0, 200) } : {}),
    ...(options.length > 0 ? { options: options.slice(0, 20).map((o) => o.slice(0, 200)) } : {})
  };
}

function readTextFile(file: string): string | null {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > MAX_FILE_BYTES) return null;
    return fs.readFileSync(file, "utf8");
  } catch {
    return null;
  }
}

/**
 * Cabecera `openssh-key-v1`: nombre del cifrado y blob publico.
 *
 * Los dos son PUBLICOS y van en claro ANTES de la parte cifrada, que no
 * se toca. Es la unica forma de decir «id_ed25519 existe, es Ed25519 y
 * esta sin contrasena» sin abrir la clave.
 */
export function describeOpensshPrivateKey(text: string): { encrypted: boolean; publicLine: string | null } | null {
  const m = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/.exec(text);
  if (!m) return null;
  let blob: Buffer;
  try {
    blob = Buffer.from(m[1].replace(/\s+/g, ""), "base64");
  } catch {
    return null;
  }
  const magic = "openssh-key-v1\0";
  if (blob.length < magic.length + 16 || blob.subarray(0, magic.length).toString("latin1") !== magic) return null;
  let off = magic.length;
  const field = () => {
    if (off + 4 > blob.length) return null;
    const len = blob.readUInt32BE(off);
    if (len > blob.length - off - 4) return null;
    const v = blob.subarray(off + 4, off + 4 + len);
    off += 4 + len;
    return v;
  };
  const cipher = field();
  if (!cipher) return null;
  field(); // kdfname
  field(); // kdfoptions
  if (off + 4 > blob.length) return null;
  off += 4; // numero de claves
  const pub = field();
  const encrypted = cipher.toString("ascii") !== "none";
  if (!pub || pub.length < 4) return { encrypted, publicLine: null };
  const typeLen = pub.readUInt32BE(0);
  if (typeLen > pub.length - 4) return { encrypted, publicLine: null };
  const keyType = pub.subarray(4, 4 + typeLen).toString("ascii");
  return { encrypted, publicLine: `${keyType} ${pub.toString("base64")}` };
}

/**
 * ¿Es este fichero una clave privada? Se decide SIN abrirlo: por el
 * nombre o porque existe su `.pub` hermano. Las dos señales son de
 * metadatos, y ninguna dispara al EDR.
 */
export function isPrivateKeyName(name: string, entries: string[]): boolean {
  if (name.endsWith(".pub")) return false;
  if (["known_hosts", "known_hosts2", "config", "authorized_keys", "authorized_keys2", "environment", "rc"].includes(name)) return false;
  if (name.endsWith(".old") || name.endsWith(".bak")) return false;
  if (entries.includes(`${name}.pub`)) return true;
  return PRIVATE_KEY_NAME_RE.test(name);
}

export async function collectSshUserKeys(options: SshUserKeysOptions = {}): Promise<CdpSshUserKeys> {
  const platform = options.platform ?? os.platform();
  const mode: SshUserKeysMode = options.mode ?? "public-only";
  const users = options.users ?? localUsers(platform);
  const result: CdpSshUserKeys = { users: 0, keys: [], privateKeys: [], unreadable: 0, truncated: false, mode };
  if (mode === "off") return result;
  const seenUsers = new Set<string>();

  const pushKey = (k: CdpSshUserKey) => {
    if (result.keys.length >= MAX_SSH_USER_KEYS) {
      result.truncated = true;
      return;
    }
    result.keys.push(k);
  };

  const readAuthorized = (file: string, user: string) => {
    const text = readTextFile(file);
    if (text === null) {
      // Existe pero no se pudo leer: eso es un dato, no un cero.
      if (fs.existsSync(file)) result.unreadable += 1;
      return;
    }
    seenUsers.add(user);
    const lines = text.split("\n").slice(0, MAX_LINES_PER_FILE);
    for (const line of lines) {
      const k = parseAuthorizedKeyLine(line, user, file);
      if (k) pushKey(k);
    }
  };

  for (const { user, home } of users) {
    const sshDir = path.join(home, ".ssh");
    let entries: string[];
    try {
      entries = fs.readdirSync(sshDir);
    } catch {
      continue; // sin ~/.ssh no hay nada, y no es un fallo
    }

    for (const name of entries) {
      const full = path.join(sshDir, name);
      if (name === "authorized_keys" || name === "authorized_keys2") {
        readAuthorized(full, user);
        continue;
      }
      if (name.endsWith(".pub")) {
        const text = readTextFile(full);
        if (text === null) {
          result.unreadable += 1;
          continue;
        }
        seenUsers.add(user);
        const first = text.split("\n").find((l) => l.trim() && !l.trim().startsWith("#"));
        const parts = (first ?? "").trim().split(/\s+/);
        const key = parseSshPublicKey(`${parts[0]} ${parts[1] ?? ""}`, full, { allowSk: true });
        if (!key) continue;
        const comment = parts.slice(2).join(" ").trim();
        pushKey({
          kind: "public",
          user,
          path: full,
          keyType: key.keyType,
          algorithm: key.algorithm,
          bits: key.bits,
          curve: key.curve,
          fingerprintSha256: key.fingerprintSha256,
          ...(comment ? { comment: comment.slice(0, 200) } : {})
        });
        continue;
      }
      // Lo que queda puede ser una clave PRIVADA. Solo presencia, y —
      // salvo en modo "full" — sin abrir el fichero (ver la cabecera).
      if (!isPrivateKeyName(name, entries)) continue;
      if (result.privateKeys.length >= MAX_SSH_USER_PRIVATE_KEYS) {
        result.truncated = true;
        continue;
      }
      seenUsers.add(user);
      result.privateKeys.push(describeUserPrivateKey(full, user, sshDir, entries, mode));
    }
  }

  for (const file of options.systemFiles ?? systemAuthorizedKeyFiles(platform)) {
    // El usuario de un authorized_keys de sistema no es una persona: es
    // «cualquier administrador». Decir el fichero es mas honesto que
    // inventar un nombre de cuenta.
    readAuthorized(file, platform === "win32" ? "(administrators)" : "(system)");
  }

  result.users = seenUsers.size;
  return result;
}

/**
 * Presencia de una clave privada de usuario.
 *
 * En "public-only" (el defecto) NO se abre el fichero: solo `stat`
 * —existe, permisos, tamaño, fecha— y lo que diga el `.pub` hermano, que
 * es publico. `encrypted` queda en null, que es la respuesta honesta:
 * «no se sabe», no «no».
 *
 * En "full" se lee ademas la cabecera para decir si esta cifrada. Sigue
 * sin leerse un byte del secreto, pero abre el fichero — y eso es lo que
 * un EDR marca como acceso a credenciales.
 */
function describeUserPrivateKey(
  file: string,
  user: string,
  sshDir: string,
  entries: string[],
  mode: SshUserKeysMode
): CdpSshUserPrivateKey {
  const base: CdpSshUserPrivateKey = { user, path: file, format: "unknown", encrypted: null, readable: true };

  // Metadatos: ni abren el fichero ni lo leen. `mode` en octal es el dato
  // de higiene que un auditor pide (una clave 0644 la lee cualquiera).
  try {
    const st = fs.statSync(file);
    base.sizeBytes = st.size;
    base.modifiedAt = new Date(st.mtimeMs).toISOString();
    base.filePermissions = (st.mode & 0o777).toString(8).padStart(3, "0");
  } catch {
    base.readable = false;
  }

  if (mode === "full" && base.readable) {
    const text = readTextFile(file);
    if (text === null) {
      base.readable = false;
    } else {
      const openssh = describeOpensshPrivateKey(text);
      if (openssh) {
        base.format = "openssh";
        base.encrypted = openssh.encrypted;
        const parsed = openssh.publicLine ? parseSshPublicKey(openssh.publicLine, file, { allowSk: true }) : null;
        if (parsed) {
          base.keyType = parsed.keyType;
          base.keyAlgorithm = parsed.algorithm;
          if (parsed.bits !== null) base.keySizeBits = parsed.bits;
          if (parsed.curve) base.curve = parsed.curve;
          base.fingerprintSha256 = parsed.fingerprintSha256;
        }
      } else {
        const facts = describePrivateKeys(Buffer.from(text, "utf8"))[0];
        if (facts) {
          base.format = facts.format;
          base.encrypted = facts.encrypted;
          if (facts.keyAlgorithm) base.keyAlgorithm = facts.keyAlgorithm;
          if (facts.keySizeBits) base.keySizeBits = facts.keySizeBits;
          if (facts.curve) base.curve = facts.curve;
        }
      }
    }
  }

  // La mitad publica hermana: identifica la MISMA clave que el
  // authorized_keys de otro equipo, que es como se cierra el circulo
  // «esta clave privada abre aquellas N cuentas». Y es publica, asi que
  // se lee en los dos modos.
  const pubName = `${path.basename(file)}.pub`;
  if (entries.includes(pubName)) {
    const pubPath = path.join(sshDir, pubName);
    base.publicHalfPath = pubPath;
    if (!base.fingerprintSha256) {
      const pubText = readTextFile(pubPath);
      const parts = (pubText ?? "").trim().split(/\s+/);
      const parsed = parseSshPublicKey(`${parts[0]} ${parts[1] ?? ""}`, pubPath, { allowSk: true });
      if (parsed) {
        base.keyType = parsed.keyType;
        base.keyAlgorithm = parsed.algorithm;
        if (parsed.bits !== null) base.keySizeBits = parsed.bits;
        if (parsed.curve) base.curve = parsed.curve;
        base.fingerprintSha256 = parsed.fingerprintSha256;
      }
    }
  }
  return base;
}

/** Digest estable del bloque, para que solo viaje cuando cambia. */
export function sshUserKeysDigest(block: CdpSshUserKeys): string {
  return crypto.createHash("sha256").update(JSON.stringify(block)).digest("hex");
}
