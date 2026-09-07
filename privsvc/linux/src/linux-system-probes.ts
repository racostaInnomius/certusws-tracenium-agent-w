// privsvc/linux/src/linux-system-probes.ts
//
// Fase 4 del cierre de brecha CIS (Ubuntu): colectores DEDICADOS para los
// controles cuyo Audit es un script sobre el estado de todo el sistema
// (usuarios y grupos, ficheros world-writable, dconf/GDM, auditd, AIDE,
// banners…). Misma disciplina que linux-probes.ts: el kind es cerrado, el
// kind decide qué se toca, y aquí no se juzga nada — se resume en campos
// contables (listas de nombres, conteos, peor modo) y el catálogo decide.
//
//   users.audit          /etc/passwd, /etc/group, /etc/shells, login.defs,
//                        `useradd -D`, `passwd -S -a`, stat de los homes
//   fs.scan              `find` sobre los sistemas de ficheros locales:
//                        world-writable, sin dueño/grupo, SUID/SGID
//   fs.varlog            modo/dueño/grupo de los ficheros de /var/log
//   dconf.<path>:<key>   /etc/dconf/db/*.d/* + locks
//   ini.<file>:<sec>:<k> clave de una sección INI (gdm custom.conf)
//   listen.<port>        /proc/net/{tcp,tcp6,udp,udp6}
//   net.wireless         /sys/class/net/*/wireless
//   grub.password|cmdline  /boot/grub/grub.cfg + /proc/cmdline
//   auditd.privileged|immutable|logfiles|configfiles|tools
//   aide.integrity       /etc/aide/aide.conf(.d)
//   banner.<file>|motd|pam_motd|sshd
//   proc.<comm>          /proc/[pid]/status → usuarios que lo ejecutan
//   sshkeys.host         /etc/ssh/ssh_host_*_key{,.pub}
//
// ── Fronteras que NO se cruzan ───────────────────────────────────────
//
// El perfil AppArmor del PrivSvc niega /etc/shadow, /etc/sudoers y /home
// a propósito (es la garantía que promete su cabecera). Por eso:
//   · el estado de contraseñas sale de `passwd -S -a` (estado P/L/NP,
//     fecha y días de inactividad), nunca de /etc/shadow;
//   · el escaneo de ficheros PODA /home y /root: lo que un usuario tenga
//     en su carpeta no es evidencia que este daemon lea;
//   · sudoers (timestamp_timeout) queda fuera.
// Lo que no se puede medir se declara como límite en el catálogo, no se
// inventa.

import * as pathMod from "path";
import { modeOctal, nonCommentLines, parseKeyValue, parseMountinfo, type ProbeDeps } from "./linux-probes";

type Obj = Record<string, unknown>;

const NOLOGIN_RE = /(nologin|\/bin\/false|\/usr\/bin\/false)$/;
const SAMPLE = 20;

// ── helpers ──────────────────────────────────────────────────────────

interface PasswdEntry { name: string; pw: string; uid: number; gid: number; home: string; shell: string }
interface GroupEntry { name: string; gid: number; members: string[] }

export function parsePasswd(text: string): PasswdEntry[] {
  const out: PasswdEntry[] = [];
  for (const line of text.split("\n")) {
    const f = line.split(":");
    if (f.length < 7 || !f[0]) continue;
    out.push({ name: f[0], pw: f[1], uid: Number(f[2]), gid: Number(f[3]), home: f[5], shell: f[6].trim() });
  }
  return out;
}

export function parseGroup(text: string): GroupEntry[] {
  const out: GroupEntry[] = [];
  for (const line of text.split("\n")) {
    const f = line.split(":");
    if (f.length < 4 || !f[0]) continue;
    out.push({ name: f[0], gid: Number(f[2]), members: f[3].trim() ? f[3].trim().split(",") : [] });
  }
  return out;
}

/** `passwd -S -a`: `name status date min max warn inactive`. status P|L|NP. */
export function parsePasswdStatus(text: string): Map<string, { status: string; changed: Date | null; inactive: number | null }> {
  const out = new Map<string, { status: string; changed: Date | null; inactive: number | null }>();
  for (const line of text.split("\n")) {
    const f = line.trim().split(/\s+/);
    if (f.length < 3) continue;
    let changed: Date | null = null;
    const iso = f[2].match(/^(\d{4})-(\d{2})-(\d{2})$/);
    const us = f[2].match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
    if (iso) changed = new Date(Date.UTC(Number(iso[1]), Number(iso[2]) - 1, Number(iso[3])));
    else if (us) changed = new Date(Date.UTC(Number(us[3]), Number(us[1]) - 1, Number(us[2])));
    const inactive = f.length >= 7 && /^-?\d+$/.test(f[6]) ? Number(f[6]) : null;
    out.set(f[0], { status: f[1], changed, inactive });
  }
  return out;
}

function duplicates<T>(items: T[]): T[] {
  const seen = new Map<T, number>();
  for (const i of items) seen.set(i, (seen.get(i) || 0) + 1);
  return [...seen.entries()].filter(([, n]) => n > 1).map(([k]) => k);
}

function readDirTexts(dir: string, deps: ProbeDeps, filter?: (name: string) => boolean): Array<{ path: string; text: string }> {
  const out: Array<{ path: string; text: string }> = [];
  for (const name of deps.readdir(dir).sort()) {
    if (filter && !filter(name)) continue;
    const p = pathMod.join(dir, name);
    const st = deps.stat(p);
    if (!st?.isFile) continue;
    const t = deps.readFile(p);
    if (t !== null) out.push({ path: p, text: t });
  }
  return out;
}

/** `[section]` + `key=value`; devuelve sección → clave → valor (última gana). */
export function parseIni(text: string): Map<string, Map<string, string>> {
  const out = new Map<string, Map<string, string>>();
  let cur = "";
  for (const raw of text.split("\n")) {
    const line = raw.replace(/[#;].*$/, "").trim();
    if (!line) continue;
    const sec = line.match(/^\[(.+)\]$/);
    if (sec) { cur = sec[1].trim().toLowerCase(); if (!out.has(cur)) out.set(cur, new Map()); continue; }
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    if (!out.has(cur)) out.set(cur, new Map());
    out.get(cur)!.set(line.slice(0, eq).trim().toLowerCase(), line.slice(eq + 1).trim());
  }
  return out;
}

function octal(s: string): number { return parseInt(s, 8); }

// ── users.audit ───────────────────────────────────────────────────────

export async function probeUsersAudit(deps: ProbeDeps): Promise<Obj> {
  const passwd = parsePasswd(deps.readFile("/etc/passwd") ?? "");
  const groups = parseGroup(deps.readFile("/etc/group") ?? "");
  const shells = nonCommentLines(deps.readFile("/etc/shells") ?? "").filter((s) => s.startsWith("/"));
  const validShells = new Set(shells.filter((s) => !NOLOGIN_RE.test(s)));
  const defs = parseKeyValue(deps.readFile("/etc/login.defs") ?? "");
  const uidMin = Number(defs.get("UID_MIN") ?? 1000) || 1000;

  const statusText = (await deps.exec("/usr/bin/passwd", ["-S", "-a"])).stdout;
  const status = parsePasswdStatus(statusText);
  const useradd = await deps.exec("/usr/sbin/useradd", ["-D"]);
  const inactiveDefault = Number((useradd.stdout.match(/^INACTIVE=(-?\d+)/m) || [])[1]);

  const now = Date.now();
  const gidToGroup = new Map(groups.map((g) => [g.gid, g]));
  const shadowGroup = groups.find((g) => g.name === "shadow");
  const interactive = passwd.filter((u) => validShells.has(u.shell));

  const homeIssues: Array<{ user: string; issue: string }> = [];
  for (const u of interactive) {
    const st = deps.stat(u.home);
    if (!st || !st.isDir) { homeIssues.push({ user: u.name, issue: "missing" }); continue; }
    if (st.uid !== u.uid) homeIssues.push({ user: u.name, issue: `owner:${deps.userName(st.uid) ?? st.uid}` });
    if ((st.mode & 0o027) !== 0) homeIssues.push({ user: u.name, issue: `mode:${modeOctal(st.mode)}` });
  }

  // TMOUT en los ficheros de perfil de shell.
  const profileFiles = [
    ...["/etc/profile", "/etc/bashrc", "/etc/bash.bashrc"].map((p) => ({ path: p, text: deps.readFile(p) })),
    ...readDirTexts("/etc/profile.d", deps, (n) => n.endsWith(".sh")),
  ].filter((f): f is { path: string; text: string } => typeof f.text === "string");
  const tmout: Obj = { configured: false, value: null, readonly: false, exported: false, files: [] as string[] };
  for (const f of profileFiles) {
    for (const line of nonCommentLines(f.text)) {
      const v = line.match(/\bTMOUT=(\d+)/);
      if (v) { tmout.configured = true; tmout.value = Number(v[1]); (tmout.files as string[]).push(f.path); }
      if (/^\s*(typeset\s+-xr\s+TMOUT=\d+|.*\breadonly\s+TMOUT\b)/.test(line)) tmout.readonly = true;
      if (/^\s*(typeset\s+-xr\s+TMOUT=\d+|.*\bexport\b.*\bTMOUT\b)/.test(line)) tmout.exported = true;
    }
  }

  // umask de root: /root/.profile y /root/.bashrc — más permisivo que 0027 = violación.
  const rootUmaskViolations: string[] = [];
  for (const p of ["/root/.profile", "/root/.bashrc", "/root/.bash_profile"]) {
    const t = deps.readFile(p);
    if (t === null) continue;
    for (const line of nonCommentLines(t)) {
      const m = line.match(/^\s*umask\s+([0-7]{3,4})\b/);
      if (m && (octal(m[1]) & 0o027) !== 0o027) rootUmaskViolations.push(`${p}:${m[1]}`);
    }
  }

  // PATH de root, como lo vería un login shell.
  const pathIssues: string[] = [];
  let rootPath: string | null = null;
  const bash = await deps.exec("/bin/bash", ["-l", "-c", 'printf %s "$PATH"']);
  if (bash.code === 0 && bash.stdout) {
    rootPath = bash.stdout.trim().split("\n").pop() ?? null;
    if (rootPath) {
      if (rootPath.includes("::")) pathIssues.push("empty entry (::)");
      if (/:\s*$/.test(rootPath)) pathIssues.push("trailing colon");
      for (const dir of rootPath.split(":")) {
        if (dir === "") continue;
        if (dir === ".") { pathIssues.push("current directory (.)"); continue; }
        const st = deps.stat(dir);
        if (!st) { pathIssues.push(`${dir}: missing`); continue; }
        if (!st.isDir) { pathIssues.push(`${dir}: not a directory`); continue; }
        if (st.uid !== 0) pathIssues.push(`${dir}: owner ${deps.userName(st.uid) ?? st.uid}`);
        if ((st.mode & 0o022) !== 0) pathIssues.push(`${dir}: mode ${modeOctal(st.mode)}`);
      }
    }
  }

  const withPassword = (n: string) => status.get(n)?.status === "P";
  return {
    users: passwd.length,
    interactiveUsers: interactive.length,
    uidMin,
    uid0: passwd.filter((u) => u.uid === 0).map((u) => u.name),
    gid0Users: passwd.filter((u) => u.gid === 0).map((u) => u.name),
    gid0Groups: groups.filter((g) => g.gid === 0).map((g) => g.name),
    duplicateUids: duplicates(passwd.map((u) => u.uid)),
    duplicateGids: duplicates(groups.map((g) => g.gid)),
    duplicateUserNames: duplicates(passwd.map((u) => u.name)),
    duplicateGroupNames: duplicates(groups.map((g) => g.name)),
    passwdNotShadowed: passwd.filter((u) => u.pw !== "x").map((u) => u.name),
    groupsMissing: [...new Set(passwd.filter((u) => !gidToGroup.has(u.gid)).map((u) => String(u.gid)))],
    shadowGroupMembers: shadowGroup
      ? [...new Set([...shadowGroup.members, ...passwd.filter((u) => u.gid === shadowGroup.gid).map((u) => u.name)])]
      : [],
    systemAccountsWithShell: passwd
      .filter((u) => u.uid < uidMin && !["root", "halt", "sync", "shutdown", "nfsnobody"].includes(u.name) && !NOLOGIN_RE.test(u.shell))
      .map((u) => u.name),
    noLoginShellUnlocked: passwd
      .filter((u) => u.name !== "root" && !validShells.has(u.shell))
      .filter((u) => status.has(u.name) && !status.get(u.name)!.status.startsWith("L"))
      .map((u) => u.name),
    emptyPasswords: [...status.entries()].filter(([, s]) => s.status === "NP").map(([n]) => n),
    passwordStatusAvailable: status.size > 0,
    rootPasswordStatus: status.get("root")?.status ?? null,
    inactiveDefault: Number.isFinite(inactiveDefault) ? inactiveDefault : null,
    inactiveOver45: [...status.entries()].filter(([n, s]) => withPassword(n) && s.inactive !== null && s.inactive > 45).map(([n]) => n),
    lastChangeInFuture: [...status.entries()].filter(([n, s]) => withPassword(n) && s.changed !== null && s.changed.getTime() > now).map(([n]) => n),
    homeIssues: homeIssues.slice(0, SAMPLE),
    homeIssueCount: homeIssues.length,
    tmout,
    rootUmaskViolations,
    rootPath: { value: rootPath, issues: pathIssues },
  };
}

// ── fs.scan / fs.varlog ──────────────────────────────────────────────

const PSEUDO_FS = /^(proc|sysfs|devtmpfs|devpts|tmpfs|cgroup2?|bpf|debugfs|tracefs|securityfs|pstore|autofs|fusectl|configfs|hugetlbfs|mqueue|binfmt_misc|rpc_pipefs|fuse\..*|squashfs|overlay|nsfs|ramfs|efivarfs|selinuxfs|nfs.*|cifs|smb.*|vfat|iso9660|ncpfs)$/;
const SKIP_MOUNT_PREFIX = ["/proc", "/sys", "/dev", "/run", "/snap", "/boot/efi", "/home", "/root"];

export function localMountsForScan(mountinfo: string): string[] {
  const out: string[] = [];
  for (const [mp, m] of parseMountinfo(mountinfo)) {
    if (PSEUDO_FS.test(m.fstype)) continue;
    if (SKIP_MOUNT_PREFIX.some((p) => mp === p || mp.startsWith(p + "/"))) continue;
    out.push(mp);
  }
  return out.sort();
}

export interface FsScanResult {
  mounts: string[]; worldWritableFiles: number; worldWritableDirs: number; unowned: number; ungrouped: number;
  suidSgid: string[]; sampleWorldWritable: string[]; sampleUnowned: string[]; denied: number; timedOut: boolean; durationMs: number;
}

/** Salida de `find -printf '%y\t%m\t%U\t%G\t%p\n'` → clasificación. */
export function classifyFindOutput(stdout: string, deps: ProbeDeps): Omit<FsScanResult, "mounts" | "denied" | "timedOut" | "durationMs"> {
  const r = { worldWritableFiles: 0, worldWritableDirs: 0, unowned: 0, ungrouped: 0, suidSgid: [] as string[], sampleWorldWritable: [] as string[], sampleUnowned: [] as string[] };
  for (const line of stdout.split("\n")) {
    const f = line.split("\t");
    if (f.length < 5) continue;
    const [type, modeStr, uidStr, gidStr] = f;
    const p = f.slice(4).join("\t");
    const mode = octal(modeStr);
    if ((mode & 0o002) !== 0) {
      if (type === "f") { r.worldWritableFiles++; if (r.sampleWorldWritable.length < SAMPLE) r.sampleWorldWritable.push(p); }
      else if (type === "d" && (mode & 0o1000) === 0) { r.worldWritableDirs++; if (r.sampleWorldWritable.length < SAMPLE) r.sampleWorldWritable.push(p + "/"); }
    }
    if (type === "f" && (mode & 0o6000) !== 0 && r.suidSgid.length < 400) r.suidSgid.push(p);
    const uid = Number(uidStr), gid = Number(gidStr);
    const noUser = deps.userName(uid) === null, noGroup = deps.groupName(gid) === null;
    if (noUser) r.unowned++;
    if (noGroup) r.ungrouped++;
    if ((noUser || noGroup) && r.sampleUnowned.length < SAMPLE) r.sampleUnowned.push(p);
  }
  return r;
}

export const FS_SCAN_TIMEOUT_MS = 25_000;

export async function probeFsScan(deps: ProbeDeps): Promise<FsScanResult> {
  const mounts = localMountsForScan(deps.readFile("/proc/self/mountinfo") ?? "");
  const started = Date.now();
  if (mounts.length === 0) return { mounts, worldWritableFiles: 0, worldWritableDirs: 0, unowned: 0, ungrouped: 0, suidSgid: [], sampleWorldWritable: [], sampleUnowned: [], denied: 0, timedOut: false, durationMs: 0 };
  const args = [
    ...mounts, "-xdev",
    "(", "-path", "/home", "-o", "-path", "/root", "-o", "-path", "*/containers/storage/*", "-o", "-path", "*/containerd/*", "-o", "-path", "*/kubelet/*", ")", "-prune", "-o",
    "(", "-perm", "-0002", "-o", "-nouser", "-o", "-nogroup", "-o", "(", "-type", "f", "-perm", "/6000", ")", ")",
    "-printf", "%y\t%m\t%U\t%G\t%p\n",
  ];
  const r = await deps.exec("/usr/bin/find", args, FS_SCAN_TIMEOUT_MS);
  const durationMs = Date.now() - started;
  const denied = (r.stderr.match(/Permission denied/g) || []).length;
  const timedOut = r.code === null && durationMs >= FS_SCAN_TIMEOUT_MS - 500;
  return { mounts, ...classifyFindOutput(r.stdout, deps), denied, timedOut, durationMs };
}

/** Tabla de CIS 6.1.3.1: patrón de nombre → (máscara de bits prohibidos, dueños, grupos). */
const VARLOG_RULES: Array<{ re: RegExp; mask: number; users: RegExp; groups: RegExp }> = [
  { re: /^(lastlog|lastlog\..*|wtmp|wtmp\..*|wtmp-.*|btmp|btmp\..*|btmp-.*|README)$/, mask: 0o113, users: /^root$/, groups: /^(utmp|root)$/ },
  { re: /^(secure|auth\.log|syslog|messages)$/, mask: 0o137, users: /^(root|syslog)$/, groups: /^(adm|root)$/ },
  { re: /^(SSSD|sssd)(\..*)?$/i, mask: 0o117, users: /^(SSSD|root)$/i, groups: /^(SSSD|root)$/i },
  { re: /^(gdm|gdm3)(\..*)?$/, mask: 0o117, users: /^root$/, groups: /^(gdm|gdm3|root)$/ },
  { re: /\.journal~?$/, mask: 0o137, users: /^root$/, groups: /^(systemd-journal|root)$/ },
];
const VARLOG_DEFAULT = { mask: 0o137, users: /^(root|syslog)$/, groups: /^(adm|root)$/ };

export function probeVarLog(deps: ProbeDeps): Obj {
  let files = 0;
  let violationCount = 0;
  const sample: string[] = [];
  const walk = (dir: string, depth: number) => {
    if (depth > 6) return;
    for (const name of deps.readdir(dir)) {
      const p = pathMod.join(dir, name);
      const st = deps.stat(p);
      if (!st) continue;
      if (st.isDir) { walk(p, depth + 1); continue; }
      if (!st.isFile) continue;
      files++;
      const rule = VARLOG_RULES.find((r) => r.re.test(name)) ?? VARLOG_DEFAULT;
      const owner = deps.userName(st.uid) ?? String(st.uid);
      const group = deps.groupName(st.gid) ?? String(st.gid);
      const bad: string[] = [];
      if ((st.mode & rule.mask) !== 0) bad.push(`mode ${modeOctal(st.mode)}`);
      if (!rule.users.test(owner)) bad.push(`owner ${owner}`);
      if (!rule.groups.test(group)) bad.push(`group ${group}`);
      if (!bad.length) continue;
      violationCount++;
      if (sample.length < SAMPLE) sample.push(`${p}: ${bad.join(", ")}`);
    }
  };
  walk("/var/log", 0);
  return { files, violations: violationCount, sample };
}

// ── dconf ────────────────────────────────────────────────────────────

const DCONF_DB = "/etc/dconf/db";

export function parseDconfValue(raw: string): unknown {
  const v = raw.trim();
  if (v === "true") return true;
  if (v === "false") return false;
  const typed = v.match(/^(?:uint32|int32|uint64|int64|double)\s+(-?\d+(?:\.\d+)?)$/);
  if (typed) return Number(typed[1]);
  if (/^-?\d+$/.test(v)) return Number(v);
  if (/^'.*'$/s.test(v) || /^".*"$/s.test(v)) return v.slice(1, -1);
  return v;
}

/** Lee TODOS los keyfiles y locks de /etc/dconf/db/*.d una vez. */
export function loadDconf(deps: ProbeDeps): { values: Map<string, unknown>; locks: Set<string>; profiles: string[] } {
  const values = new Map<string, unknown>();
  const locks = new Set<string>();
  for (const d of deps.readdir(DCONF_DB)) {
    if (!d.endsWith(".d")) continue;
    const dir = pathMod.join(DCONF_DB, d);
    for (const f of readDirTexts(dir, deps)) {
      for (const [sec, kv] of parseIni(f.text)) for (const [k, v] of kv) values.set(`${sec}:${k}`, parseDconfValue(v));
    }
    for (const f of readDirTexts(pathMod.join(dir, "locks"), deps)) {
      for (const line of nonCommentLines(f.text)) locks.add(line.replace(/^\//, ""));
    }
  }
  const profiles = deps.readdir("/etc/dconf/profile").filter((n) => deps.stat(pathMod.join("/etc/dconf/profile", n))?.isFile);
  return { values, locks, profiles };
}

export function probeDconf(key: string, db: ReturnType<typeof loadDconf>): Obj | null {
  const sep = key.lastIndexOf(":");
  if (sep <= 0) return null;
  const path = key.slice(0, sep).replace(/^\//, "").toLowerCase();
  const name = key.slice(sep + 1).toLowerCase();
  const has = db.values.has(`${path}:${name}`);
  return { present: has, value: has ? db.values.get(`${path}:${name}`) : null, locked: db.locks.has(`${path}/${name}`) };
}

// ── listen.<port> ────────────────────────────────────────────────────

function hexAddr(h: string): string {
  if (h.length === 8) return [3, 2, 1, 0].map((i) => parseInt(h.slice(i * 2, i * 2 + 2), 16)).join(".");
  // IPv6: 4 palabras little-endian de 32 bits
  const words: string[] = [];
  for (let i = 0; i < 4; i++) {
    const w = h.slice(i * 8, i * 8 + 8);
    const bytes = [3, 2, 1, 0].map((j) => w.slice(j * 2, j * 2 + 2));
    words.push(bytes[0] + bytes[1], bytes[2] + bytes[3]);
  }
  return words.map((w) => w.replace(/^0+(?=.)/, "")).join(":").toLowerCase();
}

function isLoopback(addr: string): boolean {
  return addr.startsWith("127.") || addr === "0:0:0:0:0:0:0:1" || addr === "0:0:0:0:0:ffff:7f00:1";
}

export function parseProcNet(text: string, port: number, tcp: boolean): string[] {
  const out: string[] = [];
  for (const line of text.split("\n").slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 4) continue;
    const [addr, portHex] = f[1].split(":");
    if (parseInt(portHex, 16) !== port) continue;
    if (tcp ? f[3] !== "0A" : f[3] !== "07") continue;
    out.push(hexAddr(addr));
  }
  return out;
}

export function probeListen(portKey: string, deps: ProbeDeps): Obj | null {
  const port = Number(portKey);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
  const addrs: string[] = [];
  for (const [file, tcp] of [["/proc/net/tcp", true], ["/proc/net/tcp6", true], ["/proc/net/udp", false], ["/proc/net/udp6", false]] as const) {
    const t = deps.readFile(file);
    if (t !== null) addrs.push(...parseProcNet(t, port, tcp).map((a) => `${tcp ? "tcp" : "udp"}:${a}`));
  }
  const uniq = [...new Set(addrs)];
  return { listening: uniq.length > 0, nonLoopback: uniq.some((a) => !isLoopback(a.slice(4))), addrs: uniq.slice(0, SAMPLE) };
}

// ── net.wireless ─────────────────────────────────────────────────────

export function probeWireless(deps: ProbeDeps): Obj {
  const interfaces: string[] = [];
  const up: string[] = [];
  for (const ifc of deps.readdir("/sys/class/net")) {
    const base = `/sys/class/net/${ifc}`;
    if (!deps.exists(`${base}/wireless`) && !deps.exists(`${base}/phy80211`)) continue;
    interfaces.push(ifc);
    if ((deps.readFile(`${base}/operstate`) ?? "").trim() === "up") up.push(ifc);
  }
  return { interfaces, up };
}

// ── grub ─────────────────────────────────────────────────────────────

const GRUB_CFGS = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"];

function grubText(deps: ProbeDeps): { path: string; text: string } | null {
  for (const p of GRUB_CFGS) { const t = deps.readFile(p); if (t !== null) return { path: p, text: t }; }
  return null;
}

export function probeGrubPassword(deps: ProbeDeps): Obj {
  const g = grubText(deps);
  if (!g) return { exists: false, superusers: false, password: false };
  return {
    exists: true, path: g.path,
    superusers: /^\s*set\s+superusers\s*=/m.test(g.text),
    password: /^\s*password(_pbkdf2)?\s+\S+/m.test(g.text),
  };
}

export function probeGrubCmdline(deps: ProbeDeps): Obj {
  const g = grubText(deps);
  const linuxLines = g ? g.text.split("\n").filter((l) => /^\s*linux(efi|16)?\s/.test(l)) : [];
  const current = (deps.readFile("/proc/cmdline") ?? "").trim();
  const backlog = (s: string) => { const m = s.match(/\baudit_backlog_limit=(\d+)/); return m ? Number(m[1]) : null; };
  return {
    exists: !!g,
    linuxEntries: linuxLines.length,
    entriesWithoutAudit1: linuxLines.filter((l) => !/\baudit=1\b/.test(l)).length,
    entriesWithoutBacklogLimit: linuxLines.filter((l) => backlog(l) === null).length,
    entriesBacklogBelow8192: linuxLines.filter((l) => { const b = backlog(l); return b !== null && b < 8192; }).length,
    currentAudit1: /\baudit=1\b/.test(current),
    currentBacklogLimit: backlog(current),
  };
}

// ── auditd ───────────────────────────────────────────────────────────

const AUDIT_TOOLS = ["auditctl", "aureport", "ausearch", "autrace", "auditd", "augenrules"];

function auditRulesOnDisk(deps: ProbeDeps): string[] {
  return readDirTexts("/etc/audit/rules.d", deps, (n) => n.endsWith(".rules")).flatMap((f) => nonCommentLines(f.text));
}

export async function probeAuditdPrivileged(deps: ProbeDeps, suidSgid: string[]): Promise<Obj> {
  const disk = auditRulesOnDisk(deps).join("\n");
  const run = await deps.exec("/usr/sbin/auditctl", ["-l"]);
  const running = run.code === 0 ? run.stdout : null;
  const missingOnDisk = suidSgid.filter((b) => !disk.includes(b));
  const missingRunning = running === null ? null : suidSgid.filter((b) => !running.includes(b));
  return {
    binaries: suidSgid.length,
    missingOnDisk: missingOnDisk.length,
    missingRunning: missingRunning === null ? null : missingRunning.length,
    sampleMissing: missingOnDisk.slice(0, SAMPLE),
    auditctlAvailable: running !== null,
  };
}

export async function probeAuditdImmutable(deps: ProbeDeps): Promise<Obj> {
  const lines = auditRulesOnDisk(deps).filter((l) => /^-e\s+\d/.test(l));
  const last = lines.length ? lines[lines.length - 1].replace(/\s+/g, " ") : null;
  const st = await deps.exec("/usr/sbin/auditctl", ["-s"]);
  const m = st.stdout.match(/^enabled\s+(\d)/m);
  return { onDisk: last === "-e 2", lastEnabledLine: last, running: m ? Number(m[1]) : null };
}

export function probeAuditdLogfiles(deps: ProbeDeps): Obj {
  const conf = parseKeyValue(deps.readFile("/etc/audit/auditd.conf") ?? "");
  const logFile = conf.get("log_file") ?? "/var/log/audit/audit.log";
  const dir = pathMod.dirname(logFile);
  const st = deps.stat(dir);
  if (!st?.isDir) return { dir, exists: false };
  let files = 0, worst = 0, nonRootOwner = 0, groupNotRootAdm = 0;
  for (const name of deps.readdir(dir)) {
    const s = deps.stat(pathMod.join(dir, name));
    if (!s?.isFile) continue;
    files++;
    worst |= s.mode & 0o777;
    if (s.uid !== 0) nonRootOwner++;
    const g = deps.groupName(s.gid) ?? String(s.gid);
    if (g !== "root" && g !== "adm") groupNotRootAdm++;
  }
  return { dir, exists: true, dirMode: modeOctal(st.mode), dirOwner: deps.userName(st.uid) ?? String(st.uid), files, worstMode: modeOctal(worst), nonRootOwner, groupNotRootAdm };
}

export function probeAuditdConfigfiles(deps: ProbeDeps): Obj {
  let count = 0, worst = 0, nonRootOwner = 0, nonRootGroup = 0;
  const walk = (dir: string, depth: number) => {
    if (depth > 3) return;
    for (const name of deps.readdir(dir)) {
      const p = pathMod.join(dir, name);
      const s = deps.stat(p);
      if (!s) continue;
      if (s.isDir) { walk(p, depth + 1); continue; }
      if (!s.isFile || !/\.(conf|rules)$/.test(name)) continue;
      count++;
      worst |= s.mode & 0o777;
      if (s.uid !== 0) nonRootOwner++;
      if (s.gid !== 0) nonRootGroup++;
    }
  };
  walk("/etc/audit", 0);
  return { count, worstMode: modeOctal(worst), nonRootOwner, nonRootGroup };
}

export function probeAuditdTools(deps: ProbeDeps): Obj {
  const missing: string[] = [];
  let worst = 0, nonRootOwner = 0, nonRootGroup = 0, present = 0;
  for (const tool of AUDIT_TOOLS) {
    const p = [`/usr/sbin/${tool}`, `/sbin/${tool}`].find((c) => deps.stat(c)?.isFile);
    if (!p) { missing.push(tool); continue; }
    const s = deps.stat(p)!;
    present++;
    worst |= s.mode & 0o777;
    if (s.uid !== 0) nonRootOwner++;
    if (s.gid !== 0) nonRootGroup++;
  }
  return { present, missing, worstMode: modeOctal(worst), nonRootOwner, nonRootGroup };
}

// ── aide.integrity ───────────────────────────────────────────────────

const AIDE_OPTS = ["p", "i", "n", "u", "g", "s", "b", "acl", "xattrs", "sha512"];

export function probeAideIntegrity(deps: ProbeDeps): Obj {
  const texts = [deps.readFile("/etc/aide/aide.conf"), deps.readFile("/etc/aide.conf"), ...readDirTexts("/etc/aide/aide.conf.d", deps).map((f) => f.text)]
    .filter((t): t is string => typeof t === "string");
  const lines = texts.flatMap((t) => nonCommentLines(t));
  const covered: string[] = [];
  const missing: string[] = [];
  for (const tool of AUDIT_TOOLS) {
    const ok = lines.some((l) => {
      const m = l.match(new RegExp(`^/(?:usr/)?sbin/${tool}\\s+(\\S+)`));
      if (!m) return false;
      const opts = new Set(m[1].split("+"));
      return AIDE_OPTS.every((o) => opts.has(o));
    });
    (ok ? covered : missing).push(tool);
  }
  return { configured: texts.length > 0, toolsCovered: covered.length, toolsMissing: missing };
}

// ── banner ───────────────────────────────────────────────────────────

const MOTD_FILES = ["/etc/motd", "/run/motd", "/usr/lib/motd"];
const MOTD_DIRS = ["/etc/motd.d", "/run/motd.d", "/usr/lib/motd.d", "/etc/update-motd.d"];

function osId(deps: ProbeDeps): string | null {
  const m = (deps.readFile("/etc/os-release") ?? "").match(/^ID=["']?([A-Za-z0-9_-]+)/m);
  return m ? m[1] : null;
}

export function bannerIssues(text: string, id: string | null): string[] {
  const out: string[] = [];
  if (/\\[vrms]/.test(text)) out.push("escape sequence");
  if (id && new RegExp(`\\b${id}\\b`, "i").test(text)) out.push(`os name (${id})`);
  return out;
}

export function probeBannerFile(file: string, deps: ProbeDeps): Obj {
  const t = deps.readFile(file);
  if (t === null) return { exists: false };
  const issues = bannerIssues(t, osId(deps));
  const st = deps.stat(file);
  return { exists: true, empty: t.trim().length === 0, issues, clean: issues.length === 0, mode: st ? modeOctal(st.mode) : null, owner: st ? deps.userName(st.uid) ?? String(st.uid) : null, group: st ? deps.groupName(st.gid) ?? String(st.gid) : null };
}

export function probeBannerMotd(deps: ProbeDeps): Obj {
  const id = osId(deps);
  const files: string[] = [...MOTD_FILES];
  for (const d of MOTD_DIRS) for (const n of deps.readdir(d)) files.push(pathMod.join(d, n));
  const violations: string[] = [];
  let checked = 0;
  for (const f of files) {
    const t = deps.readFile(f);
    if (t === null) continue;
    checked++;
    const issues = bannerIssues(t, id);
    if (issues.length && violations.length < SAMPLE) violations.push(`${f}: ${issues.join(", ")}`);
  }
  return { files: checked, violations: violations.length, sample: violations };
}

export function probeBannerPamMotd(deps: ProbeDeps): Obj {
  const id = osId(deps);
  const services: Array<{ service: string; lines: number; withoutMotdArg: number; badMotdFiles: string[] }> = [];
  let violations = 0;
  for (const svc of ["sshd", "login", "su", "gdm-password"]) {
    const file = [`/etc/pam.d/${svc}`, `/usr/lib/pam.d/${svc}`].find((p) => deps.exists(p));
    if (!file) continue;
    const lines = nonCommentLines(deps.readFile(file) ?? "").filter((l) => /\bpam_motd\.so\b/.test(l));
    if (!lines.length) continue;
    let withoutMotdArg = 0;
    const bad: string[] = [];
    for (const l of lines) {
      const paths = [...l.matchAll(/\bmotd=(["']?)(\S+?)\1(?:\s|$)/g)].map((m) => m[2]);
      if (!paths.length) { withoutMotdArg++; continue; }
      for (const p of paths) {
        const t = deps.readFile(p);
        if (t !== null && bannerIssues(t, id).length) bad.push(p);
      }
    }
    violations += withoutMotdArg + bad.length;
    services.push({ service: svc, lines: lines.length, withoutMotdArg, badMotdFiles: bad });
  }
  return { services, violations };
}

export function probeBannerSshd(bannerPath: string | undefined, deps: ProbeDeps): Obj {
  if (!bannerPath || bannerPath === "none") return { configured: false };
  const st = deps.stat(bannerPath);
  return {
    configured: true, path: bannerPath, exists: !!st,
    ...(st ? { mode: modeOctal(st.mode), owner: deps.userName(st.uid) ?? String(st.uid), group: deps.groupName(st.gid) ?? String(st.gid) } : {}),
  };
}

// ── proc.<comm> ──────────────────────────────────────────────────────

export function probeProc(comm: string, deps: ProbeDeps): Obj {
  const users = new Set<string>();
  let pids = 0;
  for (const d of deps.readdir("/proc")) {
    if (!/^\d+$/.test(d)) continue;
    const st = deps.readFile(`/proc/${d}/status`);
    if (st === null) continue;
    const name = (st.match(/^Name:\s*(.+)$/m) || [])[1]?.trim();
    if (name !== comm) continue;
    pids++;
    const uid = Number((st.match(/^Uid:\s*(\d+)/m) || [])[1]);
    if (Number.isFinite(uid)) users.add(deps.userName(uid) ?? String(uid));
  }
  return { running: pids > 0, pids, users: [...users].sort() };
}

// ── sshkeys.host ─────────────────────────────────────────────────────

export function probeSshHostKeys(deps: ProbeDeps): Obj {
  let priv = 0, pub = 0;
  const privViolations: string[] = [];
  const pubViolations: string[] = [];
  for (const name of deps.readdir("/etc/ssh")) {
    if (!/^ssh_host_.*_key(\.pub)?$/.test(name)) continue;
    const p = `/etc/ssh/${name}`;
    const s = deps.stat(p);
    if (!s?.isFile) continue;
    const owner = deps.userName(s.uid) ?? String(s.uid);
    const group = deps.groupName(s.gid) ?? String(s.gid);
    const bad: string[] = [];
    if (name.endsWith(".pub")) {
      pub++;
      if ((s.mode & 0o133) !== 0) bad.push(`mode ${modeOctal(s.mode)}`);
      if (owner !== "root") bad.push(`owner ${owner}`);
      if (group !== "root") bad.push(`group ${group}`);
      if (bad.length) pubViolations.push(`${name}: ${bad.join(", ")}`);
    } else {
      priv++;
      const groupOk = group === "root" || group === "ssh_keys";
      const modeOk = group === "ssh_keys" ? (s.mode & 0o137) === 0 : (s.mode & 0o177) === 0;
      if (!modeOk) bad.push(`mode ${modeOctal(s.mode)}`);
      if (owner !== "root") bad.push(`owner ${owner}`);
      if (!groupOk) bad.push(`group ${group}`);
      if (bad.length) privViolations.push(`${name}: ${bad.join(", ")}`);
    }
  }
  return { private: priv, public: pub, privateViolations: privViolations.length, publicViolations: pubViolations.length, sample: [...privViolations, ...pubViolations].slice(0, SAMPLE) };
}
