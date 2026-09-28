// privsvc/linux/src/sshd-dropin.ts
//
// Nuestro drop-in de sshd, en puro (texto → texto): qué escribir, qué
// quitar, y quién gana si el valor efectivo no es el nuestro. Lo usan el
// handler dedicado de SSH (pmp-remediation.ts) y la remediación genérica
// (generic-config.ts, forma `sshd`): los dos escriben en el MISMO fichero,
// así que las reglas —00- delante, el 99- de antes se vacía directiva a
// directiva, el revert sólo quita lo nuestro— tienen que ser las mismas.

import path from "path";

export const SSHD_MAIN_CONFIG = "/etc/ssh/sshd_config";
export const SSHD_DROPIN_DIR = "/etc/ssh/sshd_config.d";
// 00-: ver la cabecera. sshd se queda con el PRIMER valor que lee.
export const SSHD_DROPIN_NAME = "00-tracenium-hardening.conf";
export const SSHD_DROPIN_FILE = path.join(SSHD_DROPIN_DIR, SSHD_DROPIN_NAME);
// El nombre anterior. Sigue en los equipos que ya recibieron un fix; se
// vacía directiva a directiva (ver planSshDropinChanges), nunca de golpe.
export const LEGACY_SSHD_DROPIN_FILE = path.join(SSHD_DROPIN_DIR, "99-tracenium-hardening.conf");

// Safe SSH KexAlgorithms set — 2024 baseline matching the
// CIS L1 server profile. We deliberately exclude:
//   * diffie-hellman-group1-sha1   (DH 1024-bit, broken)
//   * diffie-hellman-group14-sha1  (SHA-1 — deprecated)
//   * diffie-hellman-group-exchange-sha1
//   * any *-sha1 variants
// We keep:
//   * curve25519-sha256(@libssh.org) — preferred
//   * ecdh-sha2-nistp256/384/521    — NIST curves, widely supported
//   * diffie-hellman-group14-sha256 — RFC 8268, modern fallback
//   * diffie-hellman-group16-sha512 — DH 4096-bit
//   * sntrup761x25519-sha512@openssh.com — post-quantum, OpenSSH 9+
export const SAFE_SSH_KEX_ALGORITHMS = [
  "sntrup761x25519-sha512@openssh.com",
  "curve25519-sha256",
  "curve25519-sha256@libssh.org",
  "ecdh-sha2-nistp256",
  "ecdh-sha2-nistp384",
  "ecdh-sha2-nistp521",
  "diffie-hellman-group16-sha512",
  "diffie-hellman-group14-sha256",
].join(",");

// ── SSH drop-in directive editor ──────────────────────────────────
//
// Replaces or appends a single directive in the tracenium-managed
// drop-in. Comments + blank lines preserved. Multiple existing
// occurrences of the same directive (someone hand-edited our file)
// are collapsed into one, with our value winning.
export function setDirective(
  content: string,
  directive: string,
  value: string
): string {
  // "" → [] y no [""]: si no, el fichero nuevo empezaba con una línea en blanco.
  const lines = content === "" ? [] : content.split("\n");
  const lower = directive.toLowerCase();
  let found = false;
  const out: string[] = [];
  for (const raw of lines) {
    const trimmed = raw.trim();
    // Match the directive (case-insensitive per OpenSSH spec).
    // Skip commented-out forms.
    if (!trimmed.startsWith("#")) {
      const m = trimmed.match(/^(\S+)\s+/);
      if (m && m[1].toLowerCase() === lower) {
        if (!found) {
          // First occurrence: replace with our value.
          out.push(`${directive} ${value}`);
          found = true;
        }
        // Drop subsequent duplicates entirely.
        continue;
      }
    }
    out.push(raw);
  }
  if (!found) {
    // Append at end. Ensure there's a trailing newline before our
    // directive so we don't merge into a previous comment.
    if (out.length > 0 && out[out.length - 1].trim() !== "") {
      out.push("");
    }
    out.push(`${directive} ${value}`);
  }
  // Always end the file with exactly one trailing newline.
  while (out.length > 1 && out[out.length - 1] === "") out.pop();
  out.push("");
  return out.join("\n");
}

// Read a directive value from rendered sshd_config (output of
// `sshd -T`). Returns undefined if the directive isn't in the
// effective config (rare — sshd compiles defaults for everything).
export function readEffectiveSshd(directive: string, sshdT: string): string | undefined {
  const lower = directive.toLowerCase();
  for (const line of sshdT.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const space = trimmed.indexOf(" ");
    if (space <= 0) continue;
    const key = trimmed.slice(0, space).toLowerCase();
    if (key === lower) return trimmed.slice(space + 1).trim();
  }
  return undefined;
}

// ── Drop-in: nombre, migración y precedencia ───────────────────────
//
// Hay dos ficheros nuestros posibles: el 00- actual y el 99- de antes
// de sep-2026. La migración va DIRECTIVA A DIRECTIVA: cuando un fix (o
// un revert) toca `PasswordAuthentication`, esa directiva se escribe en
// el 00- (o se quita) y se quita del 99-; las demás directivas del 99-
// se quedan donde están. Mover el 99- entero al 00- de una vez haría
// efectivas, en un job de OTRO check, directivas que llevaban meses
// perdiendo contra un drop-in anterior (p. ej. un `PasswordAuthentication
// no` latente tras el 50-cloud-init.conf): cortarle el acceso por
// contraseña a alguien sin que lo pidiera ese job. El 99- se borra solo

export type DropinChange = {
  file: string;
  oldContent: string;
  /** null = borrar el fichero. */
  newContent: string | null;
};

/**
 * Cambios en disco para fijar (`value` string) o quitar (`value` null)
 * `directive` en nuestros drop-ins. Pura. [] si no hay nada que cambiar.
 *   fijar  — el 00- la lleva con nuestro valor; el 99- deja de llevarla.
 *   quitar — ninguno de los dos la lleva (el revert).
 */
export function planSshDropinChanges(
  current: { primary: string; legacy: string },
  directive: string,
  value: string | null
): DropinChange[] {
  const changes: DropinChange[] = [];
  const fromRevertPlan = (file: string, oldContent: string) => {
    const p = planSshRevert(oldContent, directive);
    if (p.action === "write") changes.push({ file, oldContent, newContent: p.content });
    if (p.action === "remove") changes.push({ file, oldContent, newContent: null });
  };

  if (value === null) {
    fromRevertPlan(SSHD_DROPIN_FILE, current.primary);
  } else {
    const next = setDirective(current.primary, directive, value);
    if (next !== current.primary) changes.push({ file: SSHD_DROPIN_FILE, oldContent: current.primary, newContent: next });
  }
  fromRevertPlan(LEGACY_SSHD_DROPIN_FILE, current.legacy);
  return changes;
}

// ── ¿Quién fija la directiva antes que nosotros? ───────────────────
//
// Sólo para EXPLICAR un fix que no surtió efecto: la verdad sobre el
// valor efectivo la da siempre `sshd -T`, nunca este recorrido. Imita
// el orden de lectura de sshd sobre lo que importa aquí: el sshd_config
// principal hasta su Include de sshd_config.d, y los drop-ins que
// ordenan (byte a byte, como el glob de sshd en locale C) antes que el
// nuestro. Se para en el primer `Match`: lo que va detrás es
// condicional y `sshd -T` sin -C no lo aplica. No sigue Includes
// anidados (p. ej. el de crypto-policies dentro de 50-redhat.conf): si
// el culpable está ahí, el mensaje lo dice sin nombrarlo.

export type SshdDefinition = { source: string; line: number; value: string };

export type SshdPrecedence = {
  /** false = el sshd_config principal no incluye sshd_config.d antes de su primer Match: nuestro drop-in no se lee. */
  dropinIncluded: boolean;
  /** Definiciones de la directiva que sshd lee ANTES que la nuestra, en orden de lectura. */
  earlier: SshdDefinition[];
};

function directiveValue(line: string): string {
  const v = line.trim().replace(/^[^\s=]+\s*=?\s*/, "").trim();
  return v.replace(/^"(.*)"$/, "$1");
}

function globToRegExp(glob: string): RegExp {
  const body = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]");
  return new RegExp(`^${body}$`);
}

// Byte a byte, como strcmp: `localeCompare` ordenaría «0-x» y «00-x»
// distinto de como lo hace sshd.
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** Pura: recorre la configuración como sshd y devuelve quién define `directive` antes que nuestro drop-in. */
export function sshdEarlierDefinitions(
  mainConfig: string,
  dropins: { name: string; content: string }[],
  directive: string
): SshdPrecedence {
  const lower = directive.toLowerCase();
  const earlier: SshdDefinition[] = [];

  const scan = (source: string, content: string, onInclude?: (args: string[]) => boolean): boolean => {
    const lines = String(content || "").split("\n");
    for (let i = 0; i < lines.length; i++) {
      const key = directiveKey(lines[i]);
      if (key === null) continue;
      if (key === "match") return false;
      if (key === lower) earlier.push({ source, line: i + 1, value: directiveValue(lines[i]) });
      if (key === "include" && onInclude && onInclude(directiveValue(lines[i]).split(/\s+/))) return true;
    }
    return false;
  };

  const dropinIncluded = scan(SSHD_MAIN_CONFIG, mainConfig, (args) => {
    // Rutas relativas: relativas a /etc/ssh (sshd_config(5), Include).
    const patterns = args
      .map((a) => (a.startsWith("/") ? a : path.posix.join("/etc/ssh", a)))
      .filter((a) => path.posix.dirname(a) === SSHD_DROPIN_DIR)
      .map((a) => globToRegExp(path.posix.basename(a)));
    if (!patterns.length) return false;
    const names = dropins
      .map((d) => d.name)
      .filter((n) => !n.startsWith(".") && patterns.some((re) => re.test(n)))
      .sort(byteOrder);
    for (const name of names) {
      if (byteOrder(name, SSHD_DROPIN_NAME) >= 0) break;
      scan(path.posix.join(SSHD_DROPIN_DIR, name), dropins.find((d) => d.name === name)!.content);
    }
    return true;
  });

  return { dropinIncluded, earlier };
}

/**
 * Pura: el porqué, legible para el operador, de que `directive` no
 * quedara como pedimos. El culpable va PRIMERO: el agente corta el
 * `reason` del ack a 200 caracteres, y la lista de KEX efectiva puede
 * ocupar eso sola.
 */
export function explainSshdOverride(directive: string, actual: string, p: SshdPrecedence): string {
  const where = p.earlier.map((d) => `${d.source}:${d.line} (${d.value})`).join(", ");
  if (!p.dropinIncluded) {
    return (
      `${SSHD_MAIN_CONFIG} does not Include ${SSHD_DROPIN_DIR}/*.conf before its first Match, so sshd never reads ` +
      `${SSHD_DROPIN_FILE}` +
      (where ? `; ${directive} is set in ${where}` : "") +
      `. Tracenium does not edit sshd_config. Effective ${directive}: ${actual}`
    );
  }
  if (where) {
    return (
      `${where} sets ${directive} before ${SSHD_DROPIN_FILE} and sshd keeps the first value it reads. ` +
      `Tracenium does not edit other files; change or remove that line. Effective ${directive}: ${actual}`
    );
  }
  return (
    `${directive} is overridden although ${SSHD_DROPIN_FILE} sets it; no earlier definition in ${SSHD_MAIN_CONFIG} ` +
    `or ${SSHD_DROPIN_DIR} (a nested Include or an sshd -o option may override it). Effective ${directive}: ${actual}`
  );
}

// Clave de una línea de sshd_config, en minúsculas; null en blancos y
// comentarios. OpenSSH admite `Clave valor` y `Clave=valor`.
export function directiveKey(line: string): string | null {
  const t = line.trim();
  if (!t || t.startsWith("#")) return null;
  const m = t.match(/^([^\s=]+)(?:\s|=|$)/);
  return m ? m[1].toLowerCase() : null;
}

export type SshRevertPlan =
  | { action: "noop" }
  | { action: "write"; content: string }
  | { action: "remove" };

/**
 * Qué hacer con el drop-in para deshacer `directive`. Pura.
 *   noop   — nuestro fichero no la tiene (nada nuestro que quitar).
 *   write  — quitarla y dejar el resto de directivas.
 *   remove — era la única: el fichero entero sobra.
 */
export function planSshRevert(content: string, directive: string): SshRevertPlan {
  const lower = directive.toLowerCase();
  const lines = String(content || "").split("\n");
  if (!lines.some(l => directiveKey(l) === lower)) return { action: "noop" };
  // Todas las apariciones: setDirective colapsa duplicados, pero un
  // fichero editado a mano podría tener varias y bastaría una para que
  // el revert no surtiera efecto.
  const kept = lines.filter(l => directiveKey(l) !== lower);
  if (!kept.some(l => directiveKey(l) !== null)) return { action: "remove" };
  // setDirective separa con una línea en blanco; al quitar la directiva
  // quedan blancos sueltos en los extremos.
  while (kept.length && kept[0].trim() === "") kept.shift();
  while (kept.length && kept[kept.length - 1].trim() === "") kept.pop();
  return { action: "write", content: kept.join("\n") + "\n" };
}
