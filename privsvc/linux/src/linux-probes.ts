// privsvc/linux/src/linux-probes.ts
//
// Sondas genéricas de Linux (fase 2 del cierre de brecha CIS). El control
// plane manda una lista `kind.key` en la policy (`compliance.linuxProbes`)
// y este módulo la resuelve SIN juzgar nada: el veredicto es del catálogo.
//
// ── Por qué kinds cerrados y no comandos ─────────────────────────────
//
// La policy viaja como JSON y se puede editar en crudo. Si la sonda fuera
// un comando, la policy sería ejecución remota como root. Por eso cada
// sonda es un kind de una lista cerrada más una clave, y el kind decide
// el ÚNICO binario/fichero que se toca:
//
//   kmod.<mod>        /proc/modules, modprobe -n -v, /etc/modprobe.d
//   mount.<path>      /proc/self/mountinfo
//   unit.<unit>       systemctl is-enabled / is-active
//   pkg.<name>        dpkg-query -W (Debian) · rpm -q (RHEL/SUSE)
//   file.<path>       stat
//   files.<dir>       stat de cada fichero regular del directorio
//   conf.<file>:<key> "key = value" / "key value" del fichero (+ .d/*.conf)
//   lines.<file|dir>  líneas no comentario del fichero, o de todos los
//                     ficheros regulares del directorio (rules.d, sudoers.d)
//   sysctl.<key>      /proc/sys/<key con / por .>
//   sshd.<key>        `sshd -T` (una ejecución para todas las claves)
//
// ── Claves con punto ─────────────────────────────────────────────────
//
// El evaluador del backend parte los paths por ".", así que una clave con
// punto (autofs.service, login.defs, sshd_config.d) no sería direccionable.
// El catálogo la escribe con "~" en lugar de "." y aquí se decodifica al
// tocar el sistema; la evidencia se indexa por la clave TAL CUAL llegó,
// que es la que el catálogo usa en el path.
//
// ── Ausente = omitido ────────────────────────────────────────────────
//
// Un fichero que no existe, un módulo que no hay, un paquete no instalado
// se reportan como tales (`exists: false`, `installed: false`): eso ES
// evidencia. Lo que se omite es lo que no se pudo leer (permiso, error):
// aparece en `errors` y el catálogo resuelve not_applicable.

import * as fsDefault from "fs";
import * as pathMod from "path";

export type ExecFn = (bin: string, args: string[]) => Promise<{ stdout: string; stderr: string; code: number | null }>;

export interface ProbeDeps {
  readFile(p: string): string | null;
  exists(p: string): boolean;
  stat(p: string): { mode: number; uid: number; gid: number; isDir: boolean; isFile: boolean } | null;
  readdir(p: string): string[];
  exec: ExecFn;
  /** uid/gid → nombre; null si no resuelve. */
  userName(uid: number): string | null;
  groupName(gid: number): string | null;
  family: "debian" | "rhel" | "suse" | "unknown";
}

export const PROBE_KINDS = ["kmod", "mount", "unit", "pkg", "file", "files", "conf", "lines", "sysctl", "sshd"] as const;
export type ProbeKind = (typeof PROBE_KINDS)[number];

export function decodeKey(k: string): string {
  return k.replace(/~/g, ".");
}

/** `kind.key` → (kind, key). null si no se entiende. */
export function parseProbe(probe: string): { kind: ProbeKind; key: string } | null {
  if (typeof probe !== "string") return null;
  const dot = probe.indexOf(".");
  if (dot <= 0) return null;
  const kind = probe.slice(0, dot) as ProbeKind;
  const key = probe.slice(dot + 1).trim();
  if (!(PROBE_KINDS as readonly string[]).includes(kind) || key.length === 0) return null;
  if (/[\s;|&`$<>"'\x00-\x1f]/.test(key)) return null;
  return { kind, key };
}

export function probesFromParams(params: unknown): string[] {
  const raw = (params as any)?.linuxProbes;
  if (!Array.isArray(raw)) return [];
  return raw.filter((x): x is string => typeof x === "string");
}

// ── parsers puros ────────────────────────────────────────────────────

export function parseProcModules(text: string): Set<string> {
  const out = new Set<string>();
  for (const line of text.split("\n")) {
    const name = line.trim().split(/\s+/)[0];
    if (name) out.add(name);
  }
  return out;
}

/** `modprobe -n -v <mod>` → ¿está neutralizado con install /bin/false|true? */
export function modprobeShowsInstallFalse(stdout: string): boolean {
  return /^\s*install\s+\/bin\/(false|true)\b/m.test(stdout);
}

/** ¿Hay `blacklist <mod>` en /etc/modprobe.d/*.conf? */
export function isBlacklisted(confTexts: string[], mod: string): boolean {
  const re = new RegExp(`^\\s*blacklist\\s+${mod.replace(/[-_]/g, "[-_]")}\\s*$`, "m");
  return confTexts.some((t) => re.test(t));
}

/** /proc/self/mountinfo → path → {fstype, source, options[]} */
export function parseMountinfo(text: string): Map<string, { fstype: string; source: string; options: string[] }> {
  const out = new Map<string, { fstype: string; source: string; options: string[] }>();
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    const sep = line.indexOf(" - ");
    if (sep < 0) continue;
    const left = line.slice(0, sep).split(/\s+/);
    const right = line.slice(sep + 3).split(/\s+/);
    if (left.length < 6 || right.length < 3) continue;
    const mountPoint = left[4].replace(/\\040/g, " ");
    const mountOpts = left[5].split(",");
    const fstype = right[0];
    const source = right[1];
    const superOpts = (right[2] || "").split(",");
    out.set(mountPoint, { fstype, source, options: Array.from(new Set([...mountOpts, ...superOpts].filter(Boolean))) });
  }
  return out;
}

/** "key = value" | "key value" (login.defs, sshd_config, pwquality.conf, journald.conf). Última aparición gana. */
export function parseKeyValue(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line || line.startsWith("[")) continue;
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_.\-]*)\s*(?:=\s*|\s+)(.*)$/);
    if (!m) continue;
    out.set(m[1], m[2].trim().replace(/^["']|["']$/g, ""));
  }
  return out;
}

export function nonCommentLines(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));
}

export function modeOctal(mode: number): string {
  return "0" + (mode & 0o7777).toString(8).padStart(3, "0");
}

// ── colectores ───────────────────────────────────────────────────────

async function probeKmod(mod: string, deps: ProbeDeps): Promise<Record<string, unknown>> {
  const loaded = parseProcModules(deps.readFile("/proc/modules") ?? "").has(mod.replace(/-/g, "_")) || parseProcModules(deps.readFile("/proc/modules") ?? "").has(mod);
  const r = await deps.exec("/usr/sbin/modprobe", ["-n", "-v", mod]);
  const installFalse = modprobeShowsInstallFalse(r.stdout);
  // "Module X not found" → no existe en este kernel.
  const exists = !/not found in directory|Module .* not found/i.test(r.stderr + r.stdout) || installFalse;
  const confs: string[] = [];
  for (const f of deps.readdir("/etc/modprobe.d")) {
    if (!f.endsWith(".conf")) continue;
    const t = deps.readFile(pathMod.join("/etc/modprobe.d", f));
    if (t !== null) confs.push(t);
  }
  return { loaded, exists, installFalse, blacklisted: isBlacklisted(confs, mod) };
}

async function probeUnit(unit: string, deps: ProbeDeps): Promise<Record<string, unknown>> {
  const en = await deps.exec("/usr/bin/systemctl", ["is-enabled", unit]);
  const ac = await deps.exec("/usr/bin/systemctl", ["is-active", unit]);
  const enabled = (en.stdout.trim() || en.stderr.trim() || "unknown").split("\n")[0];
  const active = ac.stdout.trim().split("\n")[0] || "unknown";
  return {
    enabled,            // enabled | disabled | masked | static | generated | not-found | alias | indirect
    active,             // active | inactive | failed | unknown
    isEnabled: enabled === "enabled" || enabled === "static" || enabled === "generated" || enabled === "indirect" || enabled === "alias",
    isActive: active === "active",
    exists: !/not-found|No such file|could not be found/i.test(enabled + " " + en.stderr),
  };
}

async function probePkg(name: string, deps: ProbeDeps): Promise<Record<string, unknown>> {
  if (deps.family === "debian") {
    const r = await deps.exec("/usr/bin/dpkg-query", ["-W", "-f=${Status}\t${Version}", name]);
    const installed = r.code === 0 && /\binstall ok installed\b/.test(r.stdout);
    const version = installed ? (r.stdout.split("\t")[1] || "").trim() : null;
    return { installed, version };
  }
  const r = await deps.exec("/usr/bin/rpm", ["-q", "--qf", "%{VERSION}-%{RELEASE}", name]);
  const installed = r.code === 0 && !/not installed/i.test(r.stdout);
  return { installed, version: installed ? r.stdout.trim() : null };
}

function statFile(p: string, deps: ProbeDeps): Record<string, unknown> {
  const st = deps.stat(p);
  if (!st) return { exists: false };
  return {
    exists: true,
    mode: modeOctal(st.mode),
    uid: st.uid,
    gid: st.gid,
    owner: deps.userName(st.uid) ?? String(st.uid),
    group: deps.groupName(st.gid) ?? String(st.gid),
    isDir: st.isDir,
  };
}

function probeFiles(dir: string, deps: ProbeDeps): Record<string, unknown> {
  const st = deps.stat(dir);
  if (!st || !st.isDir) return { exists: false, count: 0 };
  let worst = 0;
  let count = 0;
  let nonRootOwner = 0;
  let nonRootGroup = 0;
  const items: Array<{ name: string; mode: string; owner: string; group: string }> = [];
  for (const name of deps.readdir(dir)) {
    const s = deps.stat(pathMod.join(dir, name));
    if (!s || !s.isFile) continue;
    count++;
    worst |= s.mode & 0o777;
    if (s.uid !== 0) nonRootOwner++;
    if (s.gid !== 0) nonRootGroup++;
    if (items.length < 50) items.push({ name, mode: modeOctal(s.mode), owner: deps.userName(s.uid) ?? String(s.uid), group: deps.groupName(s.gid) ?? String(s.gid) });
  }
  return { exists: true, count, worstMode: modeOctal(worst), nonRootOwner, nonRootGroup, items };
}

/** conf.<file>:<key>. Lee el fichero y, si existe, `<file>.d/*.conf` (los drop-ins mandan). */
function probeConf(spec: string, deps: ProbeDeps): { value: string | null; found: boolean } {
  const sep = spec.lastIndexOf(":");
  if (sep <= 0) return { value: null, found: false };
  const file = decodeKey(spec.slice(0, sep));
  const key = spec.slice(sep + 1);
  const texts: string[] = [];
  const base = deps.readFile(file);
  if (base !== null) texts.push(base);
  const dropDir = file + ".d";
  if (deps.exists(dropDir)) {
    for (const f of deps.readdir(dropDir).sort()) {
      if (!f.endsWith(".conf")) continue;
      const t = deps.readFile(pathMod.join(dropDir, f));
      if (t !== null) texts.push(t);
    }
  }
  if (texts.length === 0) return { value: null, found: false };
  let value: string | null = null;
  let found = false;
  for (const t of texts) {
    const kv = parseKeyValue(t);
    for (const [k, v] of kv) {
      if (k.toLowerCase() === key.toLowerCase()) { value = v; found = true; }
    }
  }
  return { value, found };
}

/**
 * Resuelve la lista. Devuelve el bloque `probes` (kind → key → evidencia) y
 * los errores. Cada sonda se aísla: una que reviente no tira las demás.
 */
export async function collectLinuxProbes(probes: string[], deps: ProbeDeps): Promise<{ probes: Record<string, Record<string, unknown>>; errors: Record<string, string> }> {
  const out: Record<string, Record<string, unknown>> = {};
  const errors: Record<string, string> = {};
  let mounts: Map<string, { fstype: string; source: string; options: string[] }> | null = null;
  let sshd: Map<string, string> | null = null;
  for (const probe of probes) {
    const parsed = parseProbe(probe);
    if (!parsed) continue;
    const { kind, key } = parsed;
    const bucket = (out[kind] ??= {});
    try {
      switch (kind) {
        case "kmod":
          bucket[key] = await probeKmod(decodeKey(key), deps);
          break;
        case "mount": {
          mounts ??= parseMountinfo(deps.readFile("/proc/self/mountinfo") ?? "");
          const m = mounts.get(decodeKey(key));
          bucket[key] = m ? { present: true, fstype: m.fstype, source: m.source, options: m.options } : { present: false };
          break;
        }
        case "unit":
          bucket[key] = await probeUnit(decodeKey(key), deps);
          break;
        case "pkg":
          bucket[key] = await probePkg(decodeKey(key), deps);
          break;
        case "file":
          bucket[key] = statFile(decodeKey(key), deps);
          break;
        case "files":
          bucket[key] = probeFiles(decodeKey(key), deps);
          break;
        case "conf": {
          const r = probeConf(key, deps);
          // Fichero inexistente o clave ausente: se omite (el catálogo decide
          // con onMissing). Un valor vacío explícito viaja como "".
          if (r.found) bucket[key] = r.value ?? "";
          break;
        }
        case "lines": {
          const target = decodeKey(key);
          const st = deps.stat(target);
          if (st?.isDir) {
            const acc: string[] = [];
            for (const name of deps.readdir(target).sort()) {
              const s2 = deps.stat(pathMod.join(target, name));
              if (!s2?.isFile) continue;
              const t = deps.readFile(pathMod.join(target, name));
              if (t !== null) acc.push(...nonCommentLines(t));
            }
            bucket[key] = acc.slice(0, 1000);
          } else {
            const t = deps.readFile(target);
            if (t !== null) bucket[key] = nonCommentLines(t).slice(0, 500);
          }
          break;
        }
        case "sshd": {
          sshd ??= await (async () => {
            const r = await deps.exec("/usr/sbin/sshd", ["-T"]);
            if (!r.stdout) return new Map<string, string>();
            const m = new Map<string, string>();
            for (const line of r.stdout.split("\n")) {
              const t = line.trim();
              const sp = t.indexOf(" ");
              if (sp > 0) m.set(t.slice(0, sp).toLowerCase(), t.slice(sp + 1).trim());
            }
            return m;
          })();
          const v = sshd.get(key.toLowerCase());
          if (v !== undefined) bucket[key] = /^-?\d+$/.test(v) ? Number(v) : v;
          break;
        }
        case "sysctl": {
          const t = deps.readFile("/proc/sys/" + key.replace(/\./g, "/"));
          if (t !== null) {
            const v = t.trim();
            bucket[key] = /^-?\d+$/.test(v) ? Number(v) : v;
          }
          break;
        }
      }
    } catch (err: any) {
      errors[probe] = String(err?.message || err).slice(0, 120);
    }
  }
  return { probes: out, errors };
}

// ── deps reales ──────────────────────────────────────────────────────

export function realProbeDeps(exec: ExecFn, family: ProbeDeps["family"]): ProbeDeps {
  const fs = fsDefault;
  let passwd: Map<number, string> | null = null;
  let group: Map<number, string> | null = null;
  const load = (file: string): Map<number, string> => {
    const m = new Map<number, string>();
    try {
      for (const line of fs.readFileSync(file, "utf8").split("\n")) {
        const parts = line.split(":");
        if (parts.length >= 3 && /^\d+$/.test(parts[2])) m.set(Number(parts[2]), parts[0]);
      }
    } catch { /* sin fichero: se devuelve el número */ }
    return m;
  };
  return {
    readFile: (p) => { try { return fs.readFileSync(p, "utf8"); } catch { return null; } },
    exists: (p) => { try { return fs.existsSync(p); } catch { return false; } },
    stat: (p) => { try { const s = fs.statSync(p); return { mode: s.mode, uid: s.uid, gid: s.gid, isDir: s.isDirectory(), isFile: s.isFile() }; } catch { return null; } },
    readdir: (p) => { try { return fs.readdirSync(p); } catch { return []; } },
    exec,
    userName: (uid) => (passwd ??= load("/etc/passwd")).get(uid) ?? null,
    groupName: (gid) => (group ??= load("/etc/group")).get(gid) ?? null,
    family,
  };
}
