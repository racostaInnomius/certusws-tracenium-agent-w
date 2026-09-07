// privsvc/macos/src/macos-system-probes.ts
//
// Fase 5 del cierre de brecha CIS (macOS): lo que las sondas genéricas de la
// fase 3 no cubrían — preferencias POR USUARIO, perfiles de configuración,
// volúmenes, carpetas world-writable, pistas de contraseña, Time Machine,
// sueño en portátiles, banner de login, Touch ID. Misma disciplina: el kind
// es cerrado, aquí sólo se resume, el catálogo juzga.
//
//   userpref.<domain>:<key>        `sudo -u <user> defaults read <domain> <key>`
//   userpref.host:<domain>:<key>   …con -currentHost (ByHost)
//   userpref.home:<ruta>:<key>     …sobre /Users/<u>/<ruta> (contenedores)
//   profile.<Key>                  system_profiler SPConfigurationProfileDataType,
//                                  una ejecución, claves aplanadas (última gana)
//   mac.timemachine|hints|homefolders|wwapps|wwsystem|wwlibrary|volumes|
//       policybanner|sleep|touchid|locationclients|fulldiskaccess|mdm|efi
//
// Los usuarios locales son las carpetas de /Users con dueño uid >= 500
// (fuera Shared y Guest). Un valor que no existe para un usuario no cuenta
// (`missing`); `distinct` lleva los valores encontrados como texto, que es
// lo que el catálogo compara.

import * as pathMod from "path";
import type { MacProbeDeps } from "./macos-probes";
import { decodeKey, modeOctal } from "./macos-probes";

type Obj = Record<string, unknown>;
const SAMPLE = 20;
export const FIND_TIMEOUT_MS = 8_000;

export interface LocalUser { name: string; uid: number; home: string }

export function localUsers(deps: MacProbeDeps): LocalUser[] {
  const out: LocalUser[] = [];
  for (const name of deps.readdir("/Users").sort()) {
    if (name === "Shared" || name === "Guest" || name.startsWith(".")) continue;
    const home = pathMod.join("/Users", name);
    const st = deps.stat(home);
    if (!st?.isDir || st.uid < 500) continue;
    out.push({ name: deps.userName(st.uid) ?? name, uid: st.uid, home });
  }
  return out;
}

// ── userpref ─────────────────────────────────────────────────────────

export function parseUserprefKey(key: string): { mode: "plain" | "host" | "home"; domain: string; name: string } | null {
  let mode: "plain" | "host" | "home" = "plain";
  let rest = key;
  if (rest.startsWith("host:")) { mode = "host"; rest = rest.slice(5); }
  else if (rest.startsWith("home:")) { mode = "home"; rest = rest.slice(5); }
  const sep = rest.lastIndexOf(":");
  if (sep <= 0) return null;
  return { mode, domain: decodeKey(rest.slice(0, sep)), name: decodeKey(rest.slice(sep + 1)) };
}

/** Normaliza la salida de `defaults read`: números, booleanos y texto. */
export function parseDefaultsValue(stdout: string): unknown {
  const t = stdout.trim();
  if (/^-?\d+$/.test(t)) return Number(t);
  if (/^(true|false)$/i.test(t)) return t.toLowerCase() === "true";
  return t;
}

export async function probeUserpref(key: string, users: LocalUser[], deps: MacProbeDeps): Promise<Obj | null> {
  const p = parseUserprefKey(key);
  if (!p) return null;
  const byUser: Record<string, unknown> = {};
  const missing: string[] = [];
  for (const u of users) {
    const domain = p.mode === "home" ? pathMod.join(u.home, p.domain) : p.domain;
    const args = ["-u", u.name, "/usr/bin/defaults", ...(p.mode === "host" ? ["-currentHost"] : []), "read", domain, p.name];
    const r = await deps.exec("/usr/bin/sudo", args);
    if (r.code !== 0 || !r.stdout.trim() || /does not exist/i.test(r.stdout + r.stderr)) { missing.push(u.name); continue; }
    byUser[u.name] = parseDefaultsValue(r.stdout);
  }
  const distinct = [...new Set(Object.values(byUser).map((v) => String(v)))].sort();
  return { users: users.length, present: Object.keys(byUser).length, missing: missing.length, distinct, byUser };
}

// ── profile.<Key> ────────────────────────────────────────────────────

/** Aplana los payloads de system_profiler -json: clave → valor escalar (última gana). */
export function flattenProfiles(json: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const walk = (v: unknown) => {
    if (Array.isArray(v)) { for (const x of v) walk(x); return; }
    if (!v || typeof v !== "object") return;
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (k.startsWith("_")) { walk(val); continue; }
      if (val && typeof val === "object") walk(val);
      else out[k] = val;
    }
  };
  walk(json);
  return out;
}

export async function loadProfiles(deps: MacProbeDeps): Promise<Record<string, unknown>> {
  const r = await deps.exec("/usr/sbin/system_profiler", ["-json", "SPConfigurationProfileDataType"]);
  try { return flattenProfiles(JSON.parse(r.stdout)); } catch { return {}; }
}

// ── mac.* ────────────────────────────────────────────────────────────

export function parseTimeMachine(stdout: string): Obj {
  const auto = stdout.match(/AutoBackup\s*=\s*(\d)/);
  return {
    autoBackup: auto ? Number(auto[1]) === 1 : false,
    destinations: (stdout.match(/DestinationID\s*=/g) || []).length,
    notEncrypted: (stdout.match(/NotEncrypted/g) || []).length,
  };
}

export function parseHints(stdout: string): string[] {
  const out: string[] = [];
  for (const line of stdout.split("\n")) {
    const m = line.trim().match(/^(\S+)\s+(.+)$/);
    // dscl repite la orden (". -list /Users hint") antes del listado.
    if (m && m[1] !== "." && !m[1].startsWith("-") && !m[1].startsWith("_")) out.push(m[1]);
  }
  return out;
}

export function probeHomeFolders(deps: MacProbeDeps): Obj {
  const insecure: string[] = [];
  let checked = 0;
  for (const u of localUsers(deps)) {
    const st = deps.stat(u.home);
    if (!st) continue;
    checked++;
    // 700, 710 y 711 valen (CIS admite el bit x para grupo/otros); lectura o escritura ajena, no.
    if ((st.mode & 0o066) !== 0) insecure.push(`${u.name}: ${modeOctal(st.mode)}`);
  }
  return { checked, insecure };
}

async function findCount(deps: MacProbeDeps, args: string[], exclude: RegExp | null): Promise<Obj> {
  const started = Date.now();
  const r = await deps.exec("/usr/bin/find", args, undefined, FIND_TIMEOUT_MS);
  const durationMs = Date.now() - started;
  const items = r.stdout.split("\n").map((l) => l.trim()).filter((l) => l && (!exclude || !exclude.test(l)));
  return { count: items.length, sample: items.slice(0, SAMPLE), timedOut: r.code !== 0 && durationMs >= FIND_TIMEOUT_MS - 300, durationMs };
}

export function probeWorldWritable(which: "wwapps" | "wwsystem" | "wwlibrary", deps: MacProbeDeps): Promise<Obj> {
  switch (which) {
    case "wwapps": return findCount(deps, ["/System/Volumes/Data/Applications", "-iname", "*.app", "-type", "d", "-perm", "-2"], /Xcode\.app/);
    case "wwsystem": return findCount(deps, ["/System/Volumes/Data/System", "-type", "d", "-perm", "-2"], /downloadDir|locks/);
    case "wwlibrary": return findCount(deps, ["/Library", "-type", "d", "-perm", "-002", "!", "-perm", "-1000", "!", "-xattrname", "com.apple.rootless"], /\/Library\/AppStore/);
  }
}

const INTERNAL_SKIP = /^(Preboot|Recovery|VM|Update|xART|iSCPreboot|Hardware)$/i;

export function parseDiskutilList(stdout: string): { apfs: string[]; hfs: string[]; fat: string[] } {
  const apfs: string[] = [], hfs: string[] = [], fat: string[] = [];
  for (const line of stdout.split("\n")) {
    const id = line.trim().split(/\s+/).pop() ?? "";
    if (!/^disk\d+/.test(id)) continue;
    if (/APFS Volume/.test(line)) apfs.push(id);
    else if (/Apple_HFS|Logical Volume/.test(line)) hfs.push(id);
    else if (/DOS_FAT_32|Microsoft Basic Data/.test(line)) fat.push(id);
  }
  return { apfs, hfs, fat };
}

export function parseDiskutilInfo(stdout: string): { name: string | null; encrypted: boolean | null } {
  const name = (stdout.match(/^\s*Volume Name:\s*(.+)$/m) || [])[1]?.trim() ?? null;
  const fv = stdout.match(/^\s*FileVault:\s*(Yes|No)/m);
  const enc = stdout.match(/^\s*Encrypted:\s*(Yes|No)/m);
  return { name, encrypted: fv ? fv[1] === "Yes" : enc ? enc[1] === "Yes" : null };
}

export async function probeVolumes(deps: MacProbeDeps): Promise<Obj> {
  const out: Obj = {};
  for (const scope of ["internal", "external"] as const) {
    const list = parseDiskutilList((await deps.exec("/usr/sbin/diskutil", ["list", scope])).stdout);
    const vols: Array<{ id: string; name: string | null; encrypted: boolean | null; kind: string }> = [];
    for (const [ids, kind] of [[list.apfs, "apfs"], [list.hfs, "hfs"]] as const) {
      for (const id of ids) {
        const info = parseDiskutilInfo((await deps.exec("/usr/sbin/diskutil", ["info", id])).stdout);
        if (scope === "internal" && info.name && INTERNAL_SKIP.test(info.name)) continue;
        vols.push({ id, name: info.name, encrypted: info.encrypted, kind });
      }
    }
    out[scope] = vols;
    out[`${scope}Unencrypted`] = vols.filter((v) => v.encrypted === false).length;
    if (scope === "external") out.externalFat = list.fat;
  }
  // CoreStorage (macOS 12 2.5.1.3): familias de volúmenes lógicos y cuántas sin cifrar.
  const cs = (await deps.exec("/usr/sbin/diskutil", ["cs", "list"])).stdout;
  out.coreStorageFamilies = (cs.match(/Logical Volume Family/g) || []).length;
  out.coreStorageUnencrypted = (cs.match(/Encryption Type:\s*None/g) || []).length;
  return out;
}

// ── mac.mdm / mac.efi (macOS 12) ─────────────────────────────────────

export function parseProfilesStatus(stdout: string): Obj {
  const mdm = stdout.match(/MDM enrollment:\s*(.+)$/m);
  const dep = stdout.match(/Enrolled via DEP:\s*(.+)$/m);
  const v = mdm ? mdm[1].trim() : null;
  return { enrolled: !!v && /^Yes/i.test(v), userApproved: !!v && /User Approved/i.test(v), enrolledViaDep: dep ? /^Yes/i.test(dep[1].trim()) : null, raw: v };
}

export async function probeMdm(deps: MacProbeDeps): Promise<Obj> {
  const r = await deps.exec("/usr/bin/profiles", ["status", "-type", "enrollment"]);
  return { available: r.code === 0, ...parseProfilesStatus(r.stdout) };
}

export async function probeEfi(deps: MacProbeDeps): Promise<Obj> {
  const cpu = (await deps.exec("/usr/sbin/sysctl", ["-n", "machdep.cpu.brand_string"])).stdout.trim();
  const appleSilicon = /Apple/i.test(cpu);
  if (appleSilicon) return { appleSilicon: true, t2: null, efiCheck: null, compliant: true };
  const bridge = (await deps.exec("/usr/sbin/system_profiler", ["SPiBridgeDataType"])).stdout;
  const t2 = /T2/.test(bridge);
  if (t2) return { appleSilicon: false, t2: true, efiCheck: null, compliant: true };
  const r = await deps.exec("/usr/libexec/firmwarecheckers/eficheck/eficheck", ["--integrity-check"], undefined, FIND_TIMEOUT_MS);
  const ok = /No changes detected/i.test(r.stdout);
  return { appleSilicon: false, t2: false, efiCheck: ok ? "ok" : r.stdout.trim().slice(0, 120) || null, compliant: ok };
}

export function probePolicyBanner(deps: MacProbeDeps): Obj {
  const files: Array<{ name: string; mode: string; worldReadable: boolean }> = [];
  for (const name of deps.readdir("/Library/Security")) {
    if (!/^PolicyBanner\./.test(name)) continue;
    const st = deps.stat(`/Library/Security/${name}`);
    if (!st?.isFile) continue;
    files.push({ name, mode: modeOctal(st.mode), worldReadable: (st.mode & 0o004) !== 0 });
  }
  return { exists: files.length > 0, files, modeOk: files.length > 0 && files.every((f) => f.worldReadable) };
}

export async function probeSleep(deps: MacProbeDeps): Promise<Obj> {
  const model = (await deps.exec("/usr/sbin/sysctl", ["-n", "hw.model"])).stdout.trim();
  const cpu = (await deps.exec("/usr/sbin/sysctl", ["-n", "machdep.cpu.brand_string"])).stdout.trim();
  const pm = (await deps.exec("/usr/bin/pmset", ["-b", "-g"])).stdout;
  const num = (k: string) => { const m = pm.match(new RegExp(`^\\s*${k}\\s+(-?\\d+)`, "m")); return m ? Number(m[1]) : null; };
  const battery = { sleep: num("sleep"), displaysleep: num("displaysleep"), standbydelaylow: num("standbydelaylow"), standbydelayhigh: num("standbydelayhigh"), highstandbythreshold: num("highstandbythreshold"), hibernatemode: num("hibernatemode") };
  return {
    model, isMacBook: /MacBook/i.test(model), appleSilicon: /Apple/i.test(cpu), cpu,
    battery,
    displaySleepLeSleep: battery.sleep !== null && battery.displaysleep !== null ? battery.displaysleep <= battery.sleep : null,
  };
}

export async function probeTouchId(users: LocalUser[], deps: MacProbeDeps): Promise<Obj> {
  const sys = (await deps.exec("/usr/bin/bioutil", ["-r", "-s"])).stdout;
  const timeout = sys.match(/timeout[^:]*:\s*(\d+)/i);
  const byUser: Record<string, { unlock: number | null; applePay: number | null }> = {};
  for (const u of users) {
    const r = await deps.exec("/usr/bin/sudo", ["-u", u.name, "/usr/bin/bioutil", "-r"]);
    const unlock = r.stdout.match(/Touch ID for unlock:\s*(\d)/i);
    const pay = r.stdout.match(/Touch ID for ApplePay:\s*(\d)/i);
    if (unlock || pay) byUser[u.name] = { unlock: unlock ? Number(unlock[1]) : null, applePay: pay ? Number(pay[1]) : null };
  }
  return { timeoutSeconds: timeout ? Number(timeout[1]) : null, users: Object.keys(byUser).length, byUser };
}

export async function probeLocationClients(deps: MacProbeDeps): Promise<Obj> {
  const r = await deps.exec("/usr/bin/defaults", ["read", "/var/db/locationd/clients.plist"]);
  // Las claves de primer nivel del diccionario son los clientes: `"com.apple.x" = {`
  const clients = [...r.stdout.matchAll(/^\s{4}"?([^"\s=]+)"?\s*=\s*\{/gm)].map((m) => m[1]);
  return { available: r.code === 0, clients: clients.slice(0, 100), count: clients.length };
}

export async function probeFullDiskAccess(deps: MacProbeDeps): Promise<Obj> {
  const r = await deps.exec("/usr/bin/sqlite3", ["/Library/Application Support/com.apple.TCC/TCC.db", 'select client from access where auth_value and service = "kTCCServiceSystemPolicyAllFiles"']);
  if (r.code !== 0) return { available: false, note: "TCC.db requires Full Disk Access for the collector" };
  const clients = r.stdout.split("\n").map((l) => l.trim()).filter(Boolean);
  return { available: true, clients: clients.slice(0, 100), count: clients.length };
}
