// privsvc/macos/src/macos-probes.ts
//
// Sondas genéricas de macOS (fase 3 del cierre de brecha CIS). Misma idea
// que linux-probes.ts: el control plane manda `kind.key` en la policy
// (`compliance.macosProbes`) y esto lo resuelve sin juzgar. Kind cerrado,
// nunca un comando.
//
//   pref.<suite>:<key>   lo que CIS audita con osascript: NSUserDefaults
//                        del dominio (perfil MDM + /Library/Preferences),
//                        UNA ejecución de osascript para todas las sondas
//   pmset.<key>          `pmset -g custom`: el valor MÁS ALTO entre las
//                        secciones (Battery / AC / UPS), porque CIS exige
//                        el ajuste en todas
//   launchctl.<label>    ¿está cargado el servicio? (`launchctl list`)
//   systemsetup.<flag>   sólo los get* de la lista cerrada
//   mac.<cmd>            estado parseado de un comando de la lista cerrada:
//                        csrutil, spctl, fdesetup, amfi (nvram), screenlock
//                        (sysadminctl), pwpolicy, cupsctl, xprotect,
//                        rootaccount (dscl), ardagent (ps)
//   authdb.<right>       `security authorizationdb read <right>`: shared y
//                        authenticate-session-owner
//   file / files / lines igual que en Linux
//
// Claves con punto viajan con "~" (com~apple~screensaver). La evidencia se
// indexa por la clave tal cual llegó. Un valor que no existe se omite (el
// catálogo decide con onMissing); lo que no se pudo leer va a `errors`.

import * as fsDefault from "fs";
import * as pathMod from "path";

export type ExecFn = (bin: string, args: string[], input?: string) => Promise<{ stdout: string; stderr: string; code: number | null }>;

export interface MacProbeDeps {
  readFile(p: string): string | null;
  stat(p: string): { mode: number; uid: number; gid: number; isDir: boolean; isFile: boolean } | null;
  readdir(p: string): string[];
  exec: ExecFn;
  userName(uid: number): string | null;
  groupName(gid: number): string | null;
}

export const MAC_PROBE_KINDS = ["pref", "pmset", "launchctl", "systemsetup", "mac", "authdb", "file", "files", "lines"] as const;
export type MacProbeKind = (typeof MAC_PROBE_KINDS)[number];
export const SYSTEMSETUP_FLAGS = new Set(["getremotelogin", "getremoteappleevents", "getusingnetworktime", "getnetworktimeserver", "getwakeonnetworkaccess", "getcomputersleep", "getdisplaysleep", "getrestartfreeze"]);
export const MAC_CMDS = new Set(["csrutil", "spctl", "fdesetup", "amfi", "screenlock", "pwpolicy", "cupsctl", "xprotect", "rootaccount", "ardagent", "sudo", "smbguest", "nfsd", "ssv"]);

export function decodeKey(k: string): string {
  return k.replace(/~/g, ".");
}

export function parseProbe(probe: string): { kind: MacProbeKind; key: string } | null {
  if (typeof probe !== "string") return null;
  const dot = probe.indexOf(".");
  if (dot <= 0) return null;
  const kind = probe.slice(0, dot) as MacProbeKind;
  const key = probe.slice(dot + 1).trim();
  if (!(MAC_PROBE_KINDS as readonly string[]).includes(kind) || key.length === 0) return null;
  // Espacio permitido (claves como "Siri Data Sharing Opt-In Status"); nada de shell.
  if (/[;|&`$<>"'\x00-\x1f]/.test(key)) return null;
  return { kind, key };
}

export function probesFromParams(params: unknown): string[] {
  const raw = (params as any)?.macosProbes;
  if (!Array.isArray(raw)) return [];
  return raw.filter((x): x is string => typeof x === "string");
}

// ── parsers puros ────────────────────────────────────────────────────

/** Script JXA que devuelve JSON {"suite:key": valor|null} para cada par. */
export function buildPrefScript(pairs: Array<{ suite: string; key: string }>): string {
  const list = JSON.stringify(pairs.map((p) => [p.suite, p.key]));
  return [
    "ObjC.import('Foundation');",
    `var pairs = ${list};`,
    "var out = {};",
    "for (var i = 0; i < pairs.length; i++) {",
    "  var s = pairs[i][0], k = pairs[i][1];",
    "  try { var v = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName(s).objectForKey(k)); out[s + ':' + k] = (v === undefined) ? null : v; }",
    "  catch (e) { out[s + ':' + k] = null; }",
    "}",
    "JSON.stringify(out);",
  ].join("\n");
}

export function parsePrefOutput(stdout: string): Record<string, unknown> {
  try {
    const v = JSON.parse(stdout.trim());
    return v && typeof v === "object" ? v : {};
  } catch {
    return {};
  }
}

/** `pmset -g custom` → key → valor máximo entre secciones. */
export function parsePmsetCustom(stdout: string): Record<string, number | string> {
  const out: Record<string, number | string> = {};
  for (const raw of stdout.split("\n")) {
    const line = raw.trim();
    if (!line || line.endsWith(":")) continue;
    const m = line.match(/^(\S+)\s+(.+)$/);
    if (!m) continue;
    const k = m[1];
    const v = /^-?\d+$/.test(m[2].trim()) ? Number(m[2].trim()) : m[2].trim();
    const prev = out[k];
    if (prev === undefined) out[k] = v;
    else if (typeof v === "number" && typeof prev === "number") out[k] = Math.max(prev, v);
  }
  return out;
}

/** `launchctl list` → etiquetas cargadas. */
export function parseLaunchctlList(stdout: string): Set<string> {
  const out = new Set<string>();
  for (const line of stdout.split("\n")) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 3 && parts[2] !== "Label") out.add(parts[2]);
  }
  return out;
}

export function parseSystemsetup(stdout: string): boolean | string | null {
  const t = stdout.trim();
  if (!t) return null;
  if (/:\s*On\b/i.test(t)) return true;
  if (/:\s*Off\b/i.test(t)) return false;
  const m = t.match(/:\s*(.+)$/);
  return m ? m[1].trim() : t;
}

/** pwpolicy -getaccountpolicies (plist) → claves numéricas conocidas. */
export function parsePwpolicy(stdout: string): Record<string, number | boolean> {
  const out: Record<string, number | boolean> = {};
  const grab = (key: string, name: string) => {
    const m = stdout.match(new RegExp(`<key>${key}</key>\\s*<(integer|real)>(-?\\d+(?:\\.\\d+)?)</`));
    if (m) out[name] = Number(m[2]);
  };
  grab("policyAttributeMaximumFailedAuthentications", "maxFailedAuthentications");
  grab("autoEnableInSeconds", "autoEnableInSeconds");
  grab("policyAttributeExpiresEveryNDays", "expiresEveryNDays");
  grab("policyAttributePasswordHistoryDepth", "historyDepth");
  const ml = stdout.match(/policyAttributePassword matches '\^\.\{(\d+),/) || stdout.match(/policyAttributePassword matches '\.\{(\d+),/);
  if (ml) out.minLength = Number(ml[1]);
  const mn = stdout.match(/<key>minimumLength<\/key>\s*<integer>(\d+)</);
  if (mn) out.minLength = Number(mn[1]);
  out.requiresAlpha = /policyAttributePassword matches '[^']*\[A-Za-z\]|minimumAlphaCharacters/.test(stdout);
  out.requiresNumeric = /policyAttributePassword matches '[^']*\[0-9\]|minimumNumericCharacters/.test(stdout);
  return out;
}

export function parseAuthdb(stdout: string): { shared: boolean | null; authenticateSessionOwner: boolean; rule: string | null } {
  const shared = /<key>shared<\/key>\s*<(true|false)\/>/.exec(stdout);
  const rule = /<key>rule<\/key>\s*<array>\s*<string>([^<]+)<\/string>/.exec(stdout);
  return {
    shared: shared ? shared[1] === "true" : null,
    authenticateSessionOwner: /authenticate-session-owner/.test(stdout),
    rule: rule ? rule[1] : null,
  };
}

export function nonCommentLines(text: string): string[] {
  return text.split("\n").map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith("#"));
}

export function modeOctal(mode: number): string {
  return "0" + (mode & 0o7777).toString(8).padStart(3, "0");
}

// ── colectores ───────────────────────────────────────────────────────

function statFile(p: string, deps: MacProbeDeps): Record<string, unknown> {
  const st = deps.stat(p);
  if (!st) return { exists: false };
  return { exists: true, mode: modeOctal(st.mode), uid: st.uid, gid: st.gid, owner: deps.userName(st.uid) ?? String(st.uid), group: deps.groupName(st.gid) ?? String(st.gid), isDir: st.isDir };
}

function probeFiles(dir: string, deps: MacProbeDeps): Record<string, unknown> {
  const st = deps.stat(dir);
  if (!st || !st.isDir) return { exists: false, count: 0 };
  let worst = 0, count = 0, nonRootOwner = 0, nonRootGroup = 0;
  for (const name of deps.readdir(dir)) {
    const s = deps.stat(pathMod.join(dir, name));
    if (!s || !s.isFile) continue;
    count++; worst |= s.mode & 0o777;
    if (s.uid !== 0) nonRootOwner++;
    if (s.gid !== 0) nonRootGroup++;
  }
  return { exists: true, count, worstMode: modeOctal(worst), nonRootOwner, nonRootGroup };
}

async function macCmd(cmd: string, deps: MacProbeDeps): Promise<Record<string, unknown> | null> {
  switch (cmd) {
    case "csrutil": { const r = await deps.exec("/usr/bin/csrutil", ["status"]); return { enabled: /enabled/i.test(r.stdout) && !/disabled/i.test(r.stdout) }; }
    case "spctl": { const r = await deps.exec("/usr/sbin/spctl", ["--status"]); return { enabled: /assessments enabled/i.test(r.stdout) }; }
    case "fdesetup": { const r = await deps.exec("/usr/bin/fdesetup", ["status"]); return { on: /FileVault is On/i.test(r.stdout) }; }
    case "amfi": { const r = await deps.exec("/usr/sbin/nvram", ["-p"]); return { disabled: /amfi_get_out_of_my_way=1/.test(r.stdout) }; }
    case "screenlock": {
      const r = await deps.exec("/usr/sbin/sysadminctl", ["-screenLock", "status"]);
      const t = r.stdout + r.stderr;
      const imm = /delay is immediate/i.test(t);
      const secs = t.match(/delay is (\d+) seconds?/i);
      const off = /screenLock is off/i.test(t);
      return { off, immediate: imm, delaySeconds: imm ? 0 : secs ? Number(secs[1]) : off ? null : null };
    }
    case "pwpolicy": { const r = await deps.exec("/usr/bin/pwpolicy", ["-getaccountpolicies"]); return parsePwpolicy(r.stdout); }
    case "cupsctl": { const r = await deps.exec("/usr/sbin/cupsctl", []); return { sharePrinters: /_share_printers=1/.test(r.stdout) }; }
    case "xprotect": { const r = await deps.exec("/usr/bin/xprotect", ["status"]); return { launchScans: /launch scans:\s*enabled/i.test(r.stdout), backgroundScans: /background scans:\s*enabled/i.test(r.stdout) }; }
    case "rootaccount": { const r = await deps.exec("/usr/bin/dscl", [".", "-read", "/Users/root", "AuthenticationAuthority"]); return { enabled: !/No such key/i.test(r.stdout + r.stderr) && /AuthenticationAuthority/.test(r.stdout) }; }
    case "ardagent": { const r = await deps.exec("/bin/ps", ["-axo", "comm"]); return { running: /ARDAgent/.test(r.stdout) }; }
    case "sudo": {
      const r = await deps.exec("/usr/bin/sudo", ["-V"]);
      const t = r.stdout;
      const to = t.match(/Authentication timestamp timeout:\s*(-?[\d.]+) minutes/i);
      const ty = t.match(/Type of authentication timestamp record:\s*(\w+)/i);
      return { timestampTimeoutMinutes: to ? Number(to[1]) : null, timestampType: ty ? ty[1] : null, logsAllowed: /Log when a command is allowed by sudoers/i.test(t), logsDenied: /Log when a command is denied by sudoers/i.test(t) };
    }
    case "smbguest": { const r = await deps.exec("/usr/sbin/sysadminctl", ["-smbGuestAccess", "status"]); return { enabled: /enabled/i.test(r.stdout + r.stderr) && !/disabled/i.test(r.stdout + r.stderr) }; }
    case "nfsd": { const r = await deps.exec("/sbin/nfsd", ["status"]); return { running: /nfsd service is enabled|nfsd is running/i.test(r.stdout) && !/not running/i.test(r.stdout) }; }
    case "ssv": { const r = await deps.exec("/usr/bin/csrutil", ["authenticated-root", "status"]); return { enabled: /enabled/i.test(r.stdout) && !/disabled/i.test(r.stdout) }; }
    default: return null;
  }
}

export async function collectMacProbes(probes: string[], deps: MacProbeDeps): Promise<{ probes: Record<string, Record<string, unknown>>; errors: Record<string, string> }> {
  const out: Record<string, Record<string, unknown>> = {};
  const errors: Record<string, string> = {};
  const parsed = probes.map((p) => ({ probe: p, parsed: parseProbe(p) })).filter((x) => x.parsed) as Array<{ probe: string; parsed: { kind: MacProbeKind; key: string } }>;

  // pref: una sola ejecución de osascript
  const prefs = parsed.filter((x) => x.parsed.kind === "pref");
  if (prefs.length) {
    const pairs = prefs.map((x) => { const sep = x.parsed.key.lastIndexOf(":"); return { suite: decodeKey(x.parsed.key.slice(0, sep)), key: decodeKey(x.parsed.key.slice(sep + 1)), raw: x.parsed.key }; }).filter((p) => p.suite && p.key);
    try {
      const r = await deps.exec("/usr/bin/osascript", ["-l", "JavaScript", "-e", buildPrefScript(pairs)]);
      const values = parsePrefOutput(r.stdout);
      const bucket = (out.pref ??= {});
      for (const p of pairs) {
        const v = values[`${p.suite}:${p.key}`];
        if (v !== null && v !== undefined) bucket[p.raw] = v;
      }
      if (!r.stdout.trim() && r.stderr) errors["pref"] = r.stderr.slice(0, 120);
    } catch (err: any) { errors["pref"] = String(err?.message || err).slice(0, 120); }
  }

  let pmset: Record<string, number | string> | null = null;
  let launch: Set<string> | null = null;
  for (const { probe, parsed: { kind, key } } of parsed) {
    if (kind === "pref") continue;
    const bucket = (out[kind] ??= {});
    try {
      switch (kind) {
        case "pmset": {
          pmset ??= parsePmsetCustom((await deps.exec("/usr/bin/pmset", ["-g", "custom"])).stdout);
          if (pmset[key] !== undefined) bucket[key] = pmset[key];
          break;
        }
        case "launchctl": {
          launch ??= parseLaunchctlList((await deps.exec("/bin/launchctl", ["list"])).stdout);
          bucket[key] = { loaded: launch.has(decodeKey(key)) };
          break;
        }
        case "systemsetup": {
          const flag = key.toLowerCase();
          if (!SYSTEMSETUP_FLAGS.has(flag)) break;
          const v = parseSystemsetup((await deps.exec("/usr/sbin/systemsetup", ["-" + flag])).stdout);
          if (v !== null) bucket[key] = v;
          break;
        }
        case "mac": {
          if (!MAC_CMDS.has(key)) break;
          const v = await macCmd(key, deps);
          if (v) bucket[key] = v;
          break;
        }
        case "authdb": {
          const right = decodeKey(key);
          if (!/^[A-Za-z0-9.\-_]+$/.test(right)) break;
          const r = await deps.exec("/usr/bin/security", ["authorizationdb", "read", right]);
          if (r.stdout.includes("<plist")) bucket[key] = parseAuthdb(r.stdout);
          break;
        }
        case "file": bucket[key] = statFile(decodeKey(key), deps); break;
        case "files": bucket[key] = probeFiles(decodeKey(key), deps); break;
        case "lines": {
          const t = deps.readFile(decodeKey(key));
          if (t !== null) bucket[key] = nonCommentLines(t).slice(0, 500);
          break;
        }
      }
    } catch (err: any) {
      errors[probe] = String(err?.message || err).slice(0, 120);
    }
  }
  return { probes: out, errors };
}

export function realMacProbeDeps(exec: ExecFn): MacProbeDeps {
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
    } catch { /* sin fichero */ }
    return m;
  };
  return {
    readFile: (p) => { try { return fs.readFileSync(p, "utf8"); } catch { return null; } },
    stat: (p) => { try { const s = fs.statSync(p); return { mode: s.mode, uid: s.uid, gid: s.gid, isDir: s.isDirectory(), isFile: s.isFile() }; } catch { return null; } },
    readdir: (p) => { try { return fs.readdirSync(p); } catch { return []; } },
    exec,
    userName: (uid) => (passwd ??= load("/etc/passwd")).get(uid) ?? null,
    groupName: (gid) => (group ??= load("/etc/group")).get(gid) ?? null,
  };
}
