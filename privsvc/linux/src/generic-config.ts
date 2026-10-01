// privsvc/linux/src/generic-config.ts
//
// `linux.config.set_value` — la remediación GENÉRICA de Linux. El backend
// (modules/patch-management/desired-state-linux.ts) traduce un check del
// catálogo a escrituras concretas y comprueba, simulando, que dejan el check
// en pass. Aquí se VALIDAN otra vez (listas cerradas y guardas repetidas: un
// payload que llegue sin pasar por el backend tampoco las salta), se
// aplican, y se relee el estado con el mismo criterio que la sonda.
//
// Cuatro formas, cada una en un sitio NUESTRO que se puede quitar entero:
//
//   sysctl      /etc/sysctl.d/99-tracenium-hardening.conf + `sysctl -w`.
//               99-tracenium va después de 99-sysctl.conf (el enlace a
//               /etc/sysctl.conf en Debian/RHEL): en el arranque gana el
//               ÚLTIMO fichero, al revés que sshd.
//   kmod        /etc/modprobe.d/tracenium-hardening.conf con
//               `install <mod> /bin/false` + `blacklist <mod>`, y
//               `modprobe -r` si estaba cargado.
//   audit_rule  /etc/audit/rules.d/60-tracenium.rules + `augenrules --load`.
//   conf        systemd (journald, coredump): drop-in
//               <fichero>.d/99-tracenium-hardening.conf, el último en orden.
//               El resto (pwquality, faillock, login.defs, auditd.conf,
//               apport): en su sitio, con copia <fichero>.tracenium.<ts>.bak.
//   line        una línea de una lista CERRADA (fichero Y línea): en un
//               fichero nuestro de un directorio que la herramienta lee
//               entero (limits.d, rules.d) o al final de uno del sistema
//               (pwquality.conf), con copia.
//   pkg         apt-get install --no-install-recommends | remove, de una
//               lista CERRADA; antes, `apt-get -s`: si instalar quita algo, o
//               quitar se lleva otro paquete (ubuntu-standard), no se hace.
//   unit        systemctl enable|disable --now (por systemd-run), lista cerrada.
//   banner      /etc/issue, /etc/issue.net, /etc/motd con el aviso de CIS
//               (o, en el revert, el texto que había), con copia.
//   grub_audit  audit=1 audit_backlog_limit=8192 en un drop-in propio de
//               /etc/default/grub.d + update-grub (por systemd-run: /boot
//               está negado en el perfil). Surte efecto al reiniciar.
//   perm        chmod/chown (por systemd-run) de una lista cerrada de rutas:
//               el modo sólo PIERDE bits (actual & máximo), dueño root:root;
//               los enlaces simbólicos no se tocan (chmod seguiría al destino).
//   sshd        /etc/ssh/sshd_config.d/00-tracenium-hardening.conf, el MISMO
//               drop-in que los handlers dedicados de SSH (sshd-dropin.ts:
//               sshd se queda con el PRIMER valor, por eso 00-). `sshd -t`
//               sobre el conjunto antes de recargar; si lo rechaza, nuestros
//               ficheros vuelven a como estaban. El sshd_config del operador
//               no se toca.
//
// ── Privilegios: por systemd-run, no ampliando el perfil ─────────────
//
// El PrivSvc corre confinado por AppArmor (packaging/linux/apparmor/
// usr.lib.tracenium.privsvc), que a propósito NO le da sys_module,
// sys_admin, net_admin ni audit_control, y deja /proc/sys en sólo lectura.
// `sysctl -w`, `modprobe -r`, `auditctl -s` y `augenrules --load` los
// necesitan: se lanzan con `systemd-run --wait --pipe`, que los ejecuta
// PID 1 como unidad transitoria (lo mismo que ya hace el auto-update con
// dpkg). Son SIEMPRE estos comandos fijos con argumentos validados arriba;
// el perfil sólo gana escritura sobre NUESTROS ficheros de /etc.
//
// ── Lo que no se hace ────────────────────────────────────────────────
//
// · Una regla de auditd con una syscall que no existe en esta arquitectura
//   (`open` en aarch64) o una ruta cuyo directorio no existe: auditctl
//   para de cargar en la PRIMERA regla que falla, y en el siguiente
//   arranque se llevaría por delante las de los ficheros posteriores. Se
//   rechaza antes de escribir. Y si `augenrules --load` falla igualmente,
//   se deja nuestro fichero como estaba.
// · Tocar lo del operador: sólo se quitan líneas/claves de NUESTROS
//   ficheros; en los ficheros editados en su sitio, sólo la clave pedida.
//
// ── Estado (pmp.read_check_state) ────────────────────────────────────
//
// Por escritura, lo que hay en nuestro sitio (`ours`/`present`/`blocked`)
// y el valor vivo. Con eso el backend planifica el revert
// (remediation-revert.ts, planLinux) sin volver a preguntar al equipo.

import fsDefault from "fs";
import pathMod from "path";
import os from "os";
import { execFile } from "child_process";
import {
  LEGACY_SSHD_DROPIN_FILE,
  SSHD_DROPIN_DIR,
  SSHD_DROPIN_FILE,
  SSHD_MAIN_CONFIG,
  directiveKey,
  explainSshdOverride,
  planSshDropinChanges,
  readEffectiveSshd,
  sshdEarlierDefinitions,
} from "./sshd-dropin";
import { probePkg, probeUnit } from "./linux-probes";
import { probeGrubCmdline } from "./linux-system-probes";

// ── Listas cerradas (espejo de desired-state-linux.ts) ───────────────

export const SYSCTL_DROPIN = "/etc/sysctl.d/99-tracenium-hardening.conf";
/** Orden de systemd-sysctl: mismo nombre → gana el directorio anterior. */
export const SYSCTL_DIRS = ["/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d"];
export const MODPROBE_DROPIN = "/etc/modprobe.d/tracenium-hardening.conf";
export const AUDIT_RULES_DIR = "/etc/audit/rules.d";
export const AUDIT_RULES_FILE = "/etc/audit/rules.d/60-tracenium.rules";
export const CONF_DROPIN_NAME = "99-tracenium-hardening.conf";

const IP_FORWARD_GUARD = "turns off IP forwarding — Docker, Kubernetes, VPN gateways and routers stop passing traffic";

export function sysctlGuard(key: string, value: string): string | null {
  const k = key.toLowerCase();
  const forwarding = k === "net.ipv4.ip_forward" || /^net\.ipv[46]\.conf\.[^.]+\.forwarding$/.test(k);
  return forwarding && value.trim() === "0" ? IP_FORWARD_GUARD : null;
}

/** null = se puede bloquear; texto = guarda. Fuera de la lista: no se toca. */
export const KMOD_POLICY: Readonly<Record<string, string | null>> = Object.freeze({
  cramfs: null, freevxfs: null, hfs: null, hfsplus: null, jffs2: null,
  dccp: null, sctp: null, rds: null, tipc: null, atm: null, can: null, "firewire-core": null,
  squashfs: "snap packages are squashfs images — blocking it breaks every snap",
  overlay: "Docker, Podman and containerd store images on overlayfs",
  udf: "Azure (and other clouds) deliver provisioning data on UDF media",
  "usb-storage": "blocks USB storage devices for every user of the machine",
});

type ConfPolicy = {
  mode: "dropin" | "inplace";
  section?: string;
  style: "eq" | "bare" | "shell" | "systemd";
  effect: "immediate" | "service" | "reboot";
  keys: Readonly<Record<string, { guard?: string }>>;
  restart?: string;
};

const AUDITD_HALT = "halts the machine or drops it to single-user when the audit disk fills";

export const CONF_FILES: Readonly<Record<string, ConfPolicy>> = Object.freeze({
  "/etc/systemd/journald.conf": { mode: "dropin", section: "Journal", style: "systemd", effect: "service", restart: "systemd-journald", keys: { Compress: {}, ForwardToSyslog: {}, Storage: {}, MaxFileSec: {} } },
  "/etc/systemd/coredump.conf": { mode: "dropin", section: "Coredump", style: "systemd", effect: "immediate", keys: { Storage: {}, ProcessSizeMax: {} } },
  "/etc/security/pwquality.conf": { mode: "inplace", style: "eq", effect: "immediate", keys: { minlen: {}, difok: {}, maxrepeat: {}, maxsequence: {}, dictcheck: {}, enforcing: {} } },
  "/etc/security/faillock.conf": { mode: "inplace", style: "eq", effect: "immediate", keys: { deny: { guard: "account lockout locks real users out" }, unlock_time: {} } },
  "/etc/login.defs": { mode: "inplace", style: "bare", effect: "immediate", keys: { PASS_MAX_DAYS: {}, PASS_WARN_AGE: {}, PASS_MIN_DAYS: {}, ENCRYPT_METHOD: {}, UMASK: {} } },
  "/etc/audit/auditd.conf": {
    mode: "inplace", style: "eq", effect: "reboot",
    keys: { log_group: {}, space_left_action: {}, max_log_file_action: { guard: "keep_logs never rotates audit logs" }, disk_full_action: { guard: AUDITD_HALT }, admin_space_left_action: { guard: AUDITD_HALT } },
  },
  "/etc/default/apport": { mode: "inplace", style: "shell", effect: "reboot", keys: { enabled: {} } },
});

/**
 * Directivas de sshd que se pueden escribir (clave: en minúsculas, como las
 * imprime `sshd -T`). `guard` se aplica cuando el valor es `guardValue`, el
 * que endurece: devolver el valor anterior en un revert no se bloquea.
 * `list`: algoritmos; se quitan los que este OpenSSH no conoce.
 */
type SshdPolicy = { name: string; guard?: string; guardValue?: string; list?: boolean; values?: readonly string[] };

export const SSHD_DIRECTIVES: Readonly<Record<string, SshdPolicy>> = Object.freeze({
  permitrootlogin: { name: "PermitRootLogin", guardValue: "no", guard: "if root is the account people log in with over SSH, nobody can log in by SSH afterwards" },
  passwordauthentication: { name: "PasswordAuthentication", guardValue: "no", guard: "users who log in with a password are locked out of SSH" },
  permitemptypasswords: { name: "PermitEmptyPasswords" },
  maxauthtries: { name: "MaxAuthTries" },
  logingracetime: { name: "LoginGraceTime" },
  x11forwarding: { name: "X11Forwarding" },
  usepam: { name: "UsePAM" },
  clientaliveinterval: { name: "ClientAliveInterval" },
  clientalivecountmax: { name: "ClientAliveCountMax" },
  // El banner es un fichero: sólo los que nombra el benchmark, y tiene que existir.
  banner: { name: "Banner", values: ["/etc/issue.net", "/etc/issue", "none"] },
  disableforwarding: { name: "DisableForwarding", guardValue: "yes", guard: "turns off SSH tunnels and port forwarding" },
  gssapiauthentication: { name: "GSSAPIAuthentication", guardValue: "no", guard: "Kerberos single sign-on over SSH stops working" },
  hostbasedauthentication: { name: "HostbasedAuthentication" },
  ignorerhosts: { name: "IgnoreRhosts" },
  loglevel: { name: "LogLevel" },
  maxsessions: { name: "MaxSessions" },
  maxstartups: { name: "MaxStartups" },
  permituserenvironment: { name: "PermitUserEnvironment" },
  ciphers: { name: "Ciphers", list: true },
  macs: { name: "MACs", list: true },
  kexalgorithms: { name: "KexAlgorithms", list: true },
});

/**
 * Líneas literales (espejo de LINE_FILES en desired-state-linux.ts). Fuera
 * de esta lista no se escribe nada; las que llevan guarda sólo se dejan
 * QUITAR (el revert), nunca poner.
 */
type LinePolicy = { mode: "ours" | "append"; perms: number; reload?: "augenrules"; lines: Readonly<Record<string, { guard?: string }>> };

export const LINE_FILES: Readonly<Record<string, LinePolicy>> = Object.freeze({
  "/etc/security/limits.d/60-tracenium.conf": { mode: "ours", perms: 0o644, lines: { "* hard core 0": {} } },
  "/etc/apt/apt.conf.d/60tracenium-hardening": {
    mode: "ours", perms: 0o644,
    lines: { 'APT::Install-Recommends "false";': { guard: "apt stops installing recommended packages" }, 'APT::Install-Suggests "false";': { guard: "apt stops installing recommended packages" } },
  },
  "/etc/security/pwquality.conf": { mode: "append", perms: 0o644, lines: { enforce_for_root: {} } },
  "/etc/security/faillock.conf": { mode: "append", perms: 0o644, lines: { even_deny_root: { guard: "root is locked out too after failed passwords" } } },
  "/etc/audit/rules.d/01-tracenium-continue.rules": { mode: "ours", perms: 0o640, reload: "augenrules", lines: { "-c": {} } },
});

/**
 * Paquetes (espejo de PKG_POLICY en desired-state-linux.ts). `guard` en el
 * sentido que la lleva; el sentido contrario se deja (es el revert), pero
 * pasa por la misma simulación de apt.
 */
type PkgRule = {
  /** `acceptable`: cede si la escritura trae `accepted: true` (el operador aceptó el aviso en el portal). */
  install?: { guard?: string; acceptable?: boolean };
  remove?: { guard?: string };
};

export const PKG_POLICY: Readonly<Record<string, PkgRule>> = Object.freeze({
  aide: { install: { guard: "AIDE needs aideinit first" } },
  "aide-common": { install: { guard: "AIDE needs aideinit first" } },
  apparmor: { install: {} },
  "apparmor-utils": { install: {} },
  auditd: { install: {} },
  "audispd-plugins": { install: {} },
  "cracklib-runtime": { install: {} },
  sudo: { install: {} },
  "rsyslog-gnutls": { install: {} },
  "systemd-journal-remote": { install: {} },
  // Aceptable: el portal lo ofrece como requisito de los ajustes de
  // pwquality.conf, con el aviso de PAM delante. Ninguna otra guarda cede.
  "libpam-pwquality": { install: { guard: "turns password-quality checks on in PAM", acceptable: true } },
  telnet: { remove: {} },
  "inetutils-telnet": { remove: {} },
  "telnet-ssl": { remove: {} },
  ftp: { remove: {} },
  tnftp: { remove: {} },
  "ldap-utils": { remove: {} },
  gdm3: { remove: { guard: "removes the graphical desktop" } },
  "xserver-common": { remove: { guard: "removes the graphical desktop" } },
  apache2: { remove: { guard: "removes the web server" } },
  nginx: { remove: { guard: "removes the web server" } },
  bind9: { remove: { guard: "stops answering DNS" } },
  cups: { remove: { guard: "printing stops" } },
  bluez: { remove: { guard: "Bluetooth stops" } },
  "avahi-daemon": { remove: { guard: "local network discovery stops" } },
  xinetd: { remove: { guard: "xinetd services stop" } },
  apport: { remove: { guard: "turning it off is enough" } },
});

/** Unidades (espejo de UNIT_POLICY). `with`: las que van con ella. */
type UnitRule = { enable?: { guard?: string }; disable?: { guard?: string }; with?: readonly string[] };

export const UNIT_POLICY: Readonly<Record<string, UnitRule>> = Object.freeze({
  auditd: { enable: {} },
  "dailyaidecheck.timer": { enable: { guard: "AIDE needs aideinit first" } },
  "update-notifier-motd.service": { disable: {} },
  "update-notifier-motd.timer": { disable: {} },
  "apport.service": { disable: {} },
  "avahi-daemon.socket": { disable: { guard: "local network discovery stops" }, with: ["avahi-daemon.service"] },
  "cups.socket": { disable: { guard: "printing stops" }, with: ["cups.service", "cups-browsed.service"] },
  "bluetooth.service": { disable: { guard: "Bluetooth stops" } },
  "named.service": { disable: { guard: "stops answering DNS" } },
  "xinetd.service": { disable: { guard: "xinetd services stop" } },
});

/** Rutas cuyos permisos se pueden ajustar (espejo de PERM_POLICY). `files`: sus ficheros, sin bajar. */
export const PERM_POLICY: Readonly<Record<string, { maxMode: string; scope: "path" | "files" }>> = Object.freeze({
  "/etc/crontab": { maxMode: "0600", scope: "path" },
  "/etc/cron.d": { maxMode: "0700", scope: "path" },
  "/etc/cron.hourly": { maxMode: "0700", scope: "path" },
  "/etc/cron.daily": { maxMode: "0700", scope: "path" },
  "/etc/cron.weekly": { maxMode: "0700", scope: "path" },
  "/etc/cron.monthly": { maxMode: "0700", scope: "path" },
  "/etc/cron.yearly": { maxMode: "0700", scope: "path" },
  "/etc/ssh/sshd_config": { maxMode: "0600", scope: "path" },
  "/etc/ssh/sshd_config.d": { maxMode: "0600", scope: "files" },
  "/usr/share/keyrings": { maxMode: "0644", scope: "files" },
  "/etc/apt/trusted.gpg.d": { maxMode: "0644", scope: "files" },
});

type PermRestore = { file: string; mode: string; uid: number; gid: number };

export const BANNER_FILES: ReadonlySet<string> = new Set(["/etc/issue", "/etc/issue.net", "/etc/motd"]);
/** El único texto que se escribe (espejo de BANNER_TEXT del backend); el revert trae el que había. */
export const BANNER_TEXT = "Authorized users only. All activity may be monitored and reported.";
export const GRUB_AUDIT_DROPIN = "/etc/default/grub.d/99-tracenium-audit.cfg";
const GRUB_AUDIT_LINE = 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX audit=1 audit_backlog_limit=8192"';
const UPDATE_GRUB = "/usr/sbin/update-grub";

// ── Escrituras ───────────────────────────────────────────────────────

export type LinuxWrite =
  | { kind: "sysctl"; key: string; value: string; persist: boolean }
  | { kind: "kmod"; module: string; disable: boolean }
  | { kind: "audit_rule"; line: string; present: boolean }
  | { kind: "conf"; file: string; key: string; value: string | null }
  | { kind: "sshd"; key: string; value: string | null; required?: string[] }
  | { kind: "line"; file: string; line: string; present: boolean }
  | { kind: "pkg"; name: string; installed: boolean }
  | { kind: "unit"; unit: string; enabled: boolean }
  | { kind: "perm"; path: string; maxMode: string; restore?: PermRestore[] }
  // restore: el revert, con el texto que había (null = no existía).
  | { kind: "banner"; file: string; text: string; restore?: string | null }
  | { kind: "grub_audit"; present: boolean };

const SYSCTL_KEY = /^[A-Za-z0-9_]+(\.[A-Za-z0-9_-]+)+$/;
const SAFE_VALUE = /^[A-Za-z0-9_.:\/ -]{1,64}$/;
const CONF_VALUE = /^[A-Za-z0-9_.:\/-]{1,64}$/;
const SSHD_VALUE = /^[A-Za-z0-9_.:@\/+-]{1,64}$/;
const SSHD_ALGORITHM = /^[a-z0-9][a-z0-9_.@+-]{0,63}$/;
const WATCH_RULE = /^-w (\/[A-Za-z0-9._\/-]+) -p ([rwxa]{1,4}) -k ([A-Za-z0-9_-]{1,32})$/;
const SYSCALL_RULE = /^-a always,exit -F arch=b(32|64) -S ([a-z0-9_]+(?:,[a-z0-9_]+){0,31})((?: -F auid>=1000 -F auid!=unset)?) -k ([A-Za-z0-9_-]{1,32})$/;

export type Check<T> = { ok: true; value: T } | { ok: false; message: string };

const isObj = (v: unknown): v is Record<string, any> => !!v && typeof v === "object" && !Array.isArray(v);

/** Valida el payload entero ANTES de tocar nada: todo o nada. */
export function parseWrites(params: unknown): Check<LinuxWrite[]> {
  const raw = isObj(params) ? params.writes : undefined;
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > 64) return { ok: false, message: "params.writes must be a list of 1–64 writes" };
  const out: LinuxWrite[] = [];
  for (const [i, w] of raw.entries()) {
    const at = `writes[${i}]`;
    if (!isObj(w)) return { ok: false, message: `${at} is not an object` };
    switch (w.kind) {
      case "sysctl": {
        if (typeof w.key !== "string" || !SYSCTL_KEY.test(w.key)) return { ok: false, message: `${at}: invalid sysctl key` };
        if (typeof w.value !== "string" || !SAFE_VALUE.test(w.value)) return { ok: false, message: `${at}: invalid sysctl value` };
        if (typeof w.persist !== "boolean") return { ok: false, message: `${at}: persist must be boolean` };
        const guard = sysctlGuard(w.key, w.value);
        if (guard) return { ok: false, message: `${at}: guarded (${guard})` };
        out.push({ kind: "sysctl", key: w.key, value: w.value, persist: w.persist });
        break;
      }
      case "kmod": {
        if (typeof w.module !== "string" || !Object.prototype.hasOwnProperty.call(KMOD_POLICY, w.module)) return { ok: false, message: `${at}: module not on the list Tracenium may block` };
        if (typeof w.disable !== "boolean") return { ok: false, message: `${at}: disable must be boolean` };
        const guard = w.disable ? KMOD_POLICY[w.module] : null;
        if (guard) return { ok: false, message: `${at}: guarded (${guard})` };
        out.push({ kind: "kmod", module: w.module, disable: w.disable });
        break;
      }
      case "audit_rule": {
        if (typeof w.line !== "string" || w.line.includes("..") || !(WATCH_RULE.test(w.line) || SYSCALL_RULE.test(w.line))) {
          return { ok: false, message: `${at}: audit rule is not one of the two shapes Tracenium writes` };
        }
        if (typeof w.present !== "boolean") return { ok: false, message: `${at}: present must be boolean` };
        out.push({ kind: "audit_rule", line: w.line, present: w.present });
        break;
      }
      case "conf": {
        const policy = typeof w.file === "string" ? CONF_FILES[w.file] : undefined;
        if (!policy) return { ok: false, message: `${at}: file not on the list Tracenium may edit` };
        if (typeof w.key !== "string" || !Object.prototype.hasOwnProperty.call(policy.keys, w.key)) return { ok: false, message: `${at}: key not on the list for ${w.file}` };
        if (w.value !== null && (typeof w.value !== "string" || !CONF_VALUE.test(w.value))) return { ok: false, message: `${at}: invalid value` };
        const guard = w.value !== null ? policy.keys[w.key].guard : undefined;
        if (guard) return { ok: false, message: `${at}: guarded (${guard})` };
        out.push({ kind: "conf", file: w.file, key: w.key, value: w.value });
        break;
      }
      case "sshd": {
        const policy = typeof w.key === "string" ? SSHD_DIRECTIVES[w.key.toLowerCase()] : undefined;
        if (!policy) return { ok: false, message: `${at}: sshd directive not on the list Tracenium may set` };
        let required: string[] | undefined;
        if (w.value !== null) {
          if (typeof w.value !== "string") return { ok: false, message: `${at}: invalid value` };
          if (policy.list) {
            const items = w.value.split(",");
            if (items.length > 32 || !items.every((i: string) => SSHD_ALGORITHM.test(i))) return { ok: false, message: `${at}: invalid algorithm list` };
            if (w.required !== undefined) {
              if (!Array.isArray(w.required) || !w.required.every((r: unknown) => typeof r === "string" && items.includes(r))) {
                return { ok: false, message: `${at}: required algorithms must come from the list` };
              }
              required = w.required.length ? [...w.required] : undefined;
            }
          } else if (!SSHD_VALUE.test(w.value)) {
            return { ok: false, message: `${at}: invalid value` };
          }
          if (policy.values && !policy.values.includes(w.value)) return { ok: false, message: `${at}: ${policy.name} ${w.value} is not a value Tracenium sets` };
          if (policy.guard && w.value.toLowerCase() === policy.guardValue) return { ok: false, message: `${at}: guarded (${policy.guard})` };
        }
        out.push(required ? { kind: "sshd", key: policy.name, value: w.value, required } : { kind: "sshd", key: policy.name, value: w.value });
        break;
      }
      case "line": {
        const policy = typeof w.file === "string" ? LINE_FILES[w.file] : undefined;
        if (!policy) return { ok: false, message: `${at}: file not on the list Tracenium may edit` };
        if (typeof w.line !== "string" || !Object.prototype.hasOwnProperty.call(policy.lines, w.line)) return { ok: false, message: `${at}: line not on the list for ${w.file}` };
        if (typeof w.present !== "boolean") return { ok: false, message: `${at}: present must be boolean` };
        const guard = w.present ? policy.lines[w.line].guard : undefined;
        if (guard) return { ok: false, message: `${at}: guarded (${guard})` };
        out.push({ kind: "line", file: w.file, line: w.line, present: w.present });
        break;
      }
      case "pkg": {
        const policy = typeof w.name === "string" && Object.prototype.hasOwnProperty.call(PKG_POLICY, w.name) ? PKG_POLICY[w.name] : undefined;
        if (!policy) return { ok: false, message: `${at}: package not on the list Tracenium may install or remove` };
        if (typeof w.installed !== "boolean") return { ok: false, message: `${at}: installed must be boolean` };
        const rule = w.installed ? policy.install : policy.remove;
        const accepted = w.installed && policy.install?.acceptable === true && w.accepted === true;
        if (rule?.guard && !accepted) return { ok: false, message: `${at}: guarded (${rule.guard})` };
        out.push({ kind: "pkg", name: w.name, installed: w.installed });
        break;
      }
      case "unit": {
        const policy = typeof w.unit === "string" && Object.prototype.hasOwnProperty.call(UNIT_POLICY, w.unit) ? UNIT_POLICY[w.unit] : undefined;
        if (!policy) return { ok: false, message: `${at}: unit not on the list Tracenium may enable or disable` };
        if (typeof w.enabled !== "boolean") return { ok: false, message: `${at}: enabled must be boolean` };
        const guard = (w.enabled ? policy.enable : policy.disable)?.guard;
        if (guard) return { ok: false, message: `${at}: guarded (${guard})` };
        out.push({ kind: "unit", unit: w.unit, enabled: w.enabled });
        break;
      }
      case "banner": {
        if (typeof w.file !== "string" || !BANNER_FILES.has(w.file)) return { ok: false, message: `${at}: banner file not on the list` };
        if (w.text !== BANNER_TEXT) return { ok: false, message: `${at}: only the standard banner text is written` };
        if (w.restore !== undefined && w.restore !== null && (typeof w.restore !== "string" || w.restore.length > 8192 || w.restore.includes("\0"))) return { ok: false, message: `${at}: invalid restore text` };
        out.push(w.restore !== undefined ? { kind: "banner", file: w.file, text: w.text, restore: w.restore } : { kind: "banner", file: w.file, text: w.text });
        break;
      }
      case "grub_audit": {
        if (typeof w.present !== "boolean") return { ok: false, message: `${at}: present must be boolean` };
        out.push({ kind: "grub_audit", present: w.present });
        break;
      }
      case "perm": {
        const policy = typeof w.path === "string" && Object.prototype.hasOwnProperty.call(PERM_POLICY, w.path) ? PERM_POLICY[w.path] : undefined;
        if (!policy) return { ok: false, message: `${at}: path not on the list Tracenium may change permissions of` };
        if (w.maxMode !== policy.maxMode) return { ok: false, message: `${at}: maxMode for ${w.path} is ${policy.maxMode}` };
        let restore: PermRestore[] | undefined;
        if (w.restore !== undefined) {
          if (!Array.isArray(w.restore) || w.restore.length === 0 || w.restore.length > 256) return { ok: false, message: `${at}: restore must be a list of 1–256 entries` };
          restore = [];
          for (const r of w.restore) {
            const inside = typeof r?.file === "string" && !r.file.includes("..") && (policy.scope === "path" ? r.file === w.path : pathMod.posix.dirname(r.file) === w.path);
            if (!inside) return { ok: false, message: `${at}: restore entry outside ${w.path}` };
            if (typeof r.mode !== "string" || !/^0?[0-7]{3}$/.test(r.mode)) return { ok: false, message: `${at}: restore mode must be three octal digits` };
            if (!Number.isInteger(r.uid) || r.uid < 0 || !Number.isInteger(r.gid) || r.gid < 0) return { ok: false, message: `${at}: restore uid/gid must be numbers` };
            restore.push({ file: r.file, mode: r.mode, uid: r.uid, gid: r.gid });
          }
        }
        out.push(restore ? { kind: "perm", path: w.path, maxMode: w.maxMode, restore } : { kind: "perm", path: w.path, maxMode: w.maxMode });
        break;
      }
      default:
        return { ok: false, message: `${at}: unknown kind` };
    }
  }
  return { ok: true, value: out };
}

// ── Dependencias (inyectables en tests) ──────────────────────────────

export interface GenericDeps {
  readFile(p: string): string | null;
  /** Escritura atómica (temporal + rename) con ese modo. */
  writeFile(p: string, content: string, mode: number): void;
  unlink(p: string): void;
  mkdirp(p: string): void;
  readdir(p: string): string[];
  isDir(p: string): boolean;
  /** Modo actual del fichero, para conservarlo al reescribir. */
  fileMode(p: string): number | null;
  /** lstat: un enlace simbólico sale como `isLink` (y no como fichero). */
  stat(p: string): { mode: number; uid: number; gid: number; isDir: boolean; isFile: boolean; isLink: boolean } | null;
  copyFile(src: string, dst: string): void;
  exec(bin: string, args: string[], timeoutMs?: number, env?: Record<string, string>): Promise<{ stdout: string; stderr: string; code: number | null }>;
  machine(): string;
  now(): Date;
}

export const realDeps: GenericDeps = {
  readFile(p) {
    try {
      return fsDefault.readFileSync(p, "utf8");
    } catch {
      return null;
    }
  },
  writeFile(p, content, mode) {
    const tmp = `${p}.tracenium-tmp`;
    fsDefault.writeFileSync(tmp, content, { mode });
    fsDefault.chmodSync(tmp, mode);
    fsDefault.renameSync(tmp, p);
  },
  unlink(p) {
    try {
      fsDefault.unlinkSync(p);
    } catch (err: any) {
      if (err?.code !== "ENOENT") throw err;
    }
  },
  mkdirp(p) {
    fsDefault.mkdirSync(p, { recursive: true, mode: 0o755 });
  },
  readdir(p) {
    try {
      return fsDefault.readdirSync(p);
    } catch {
      return [];
    }
  },
  isDir(p) {
    try {
      return fsDefault.statSync(p).isDirectory();
    } catch {
      return false;
    }
  },
  fileMode(p) {
    try {
      return fsDefault.statSync(p).mode & 0o7777;
    } catch {
      return null;
    }
  },
  copyFile(src, dst) {
    fsDefault.copyFileSync(src, dst);
  },
  stat(p) {
    try {
      const st = fsDefault.lstatSync(p);
      return { mode: st.mode & 0o7777, uid: st.uid, gid: st.gid, isDir: st.isDirectory(), isFile: st.isFile(), isLink: st.isSymbolicLink() };
    } catch {
      return null;
    }
  },
  exec(bin, args, timeoutMs = 60_000, env) {
    return new Promise((resolve) => {
      execFile(bin, args, { timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024, env: env ? { ...process.env, ...env } : process.env }, (err: any, stdout, stderr) => {
        resolve({ stdout: String(stdout ?? ""), stderr: String(stderr ?? ""), code: err ? (typeof err.code === "number" ? err.code : null) : 0 });
      });
    });
  },
  machine: () => os.machine?.() ?? process.arch,
  now: () => new Date(),
};

// ── Lectores puros ───────────────────────────────────────────────────

const activeLines = (text: string | null) =>
  (text ?? "").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !l.startsWith(";"));

/** Mismo parser que la sonda `conf` (linux-probes.ts parseKeyValue): la última aparición gana. */
export function parseKeyValue(text: string | null): Map<string, string> {
  const out = new Map<string, string>();
  for (const raw of (text ?? "").split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line || line.startsWith("[")) continue;
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_.\-]*)\s*(?:=\s*|\s+)(.*)$/);
    if (!m) continue;
    out.set(m[1], m[2].trim().replace(/^["']|["']$/g, ""));
  }
  return out;
}

function lookup(map: Map<string, string>, key: string): string | null {
  for (const [k, v] of map) if (k.toLowerCase() === key.toLowerCase()) return v;
  return null;
}

/** El valor que ve la sonda: el fichero y luego `<fichero>.d/*.conf` en orden, el último gana. */
export function effectiveConf(file: string, key: string, deps: GenericDeps): { value: string | null; source: string | null } {
  let value: string | null = null;
  let source: string | null = null;
  const take = (path: string) => {
    let v: string | null = null;
    for (const [k, val] of parseKeyValue(deps.readFile(path))) if (k.toLowerCase() === key.toLowerCase()) v = val;
    if (v !== null) {
      value = v;
      source = path;
    }
  };
  take(file);
  const dir = `${file}.d`;
  if (deps.isDir(dir)) for (const f of deps.readdir(dir).filter((n) => n.endsWith(".conf")).sort()) take(pathMod.join(dir, f));
  return { value, source };
}

function confOursPath(file: string): string {
  return CONF_FILES[file].mode === "dropin" ? `${file}.d/${CONF_DROPIN_NAME}` : file;
}

const normSysctl = (v: string | null) => (v === null ? null : v.trim().split(/\s+/).join(" "));

/** sysctl.d: clave normalizada (`/` → `.`), con el `-` inicial (ignorar errores) fuera. */
function sysctlEntries(text: string | null): Array<{ key: string; value: string }> {
  const out: Array<{ key: string; value: string }> = [];
  for (const line of activeLines(text)) {
    const m = /^-?([^=\s]+)\s*=\s*(.*)$/.exec(line);
    if (m) out.push({ key: m[1].replace(/\//g, "."), value: m[2].trim() });
  }
  return out;
}

function globMatches(pattern: string, key: string): boolean {
  if (!pattern.includes("*")) return pattern === key;
  const re = new RegExp("^" + pattern.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join("[^.]*") + "$");
  return re.test(key);
}

/** El valor con el que arranca la clave: systemd-sysctl, último fichero gana. */
export function sysctlBootValue(key: string, deps: GenericDeps): { value: string | null; source: string | null } {
  const byName = new Map<string, string>();
  for (const dir of SYSCTL_DIRS) {
    for (const f of deps.readdir(dir)) {
      if (!f.endsWith(".conf") || byName.has(f)) continue;
      byName.set(f, pathMod.join(dir, f));
    }
  }
  let value: string | null = null;
  let source: string | null = null;
  for (const name of [...byName.keys()].sort()) {
    const path = byName.get(name)!;
    for (const e of sysctlEntries(deps.readFile(path))) {
      if (globMatches(e.key, key)) {
        value = e.value;
        source = path;
      }
    }
  }
  return { value, source };
}

function sysctlRuntime(key: string, deps: GenericDeps): string | null {
  const t = deps.readFile("/proc/sys/" + key.replace(/\./g, "/"));
  return t === null ? null : normSysctl(t);
}

function loadedModules(deps: GenericDeps): Set<string> {
  const out = new Set<string>();
  for (const line of (deps.readFile("/proc/modules") ?? "").split("\n")) {
    const n = line.trim().split(/\s+/)[0];
    if (n) out.add(n);
  }
  return out;
}

function isBlocked(dropin: string | null, mod: string): boolean {
  const lines = activeLines(dropin);
  return lines.includes(`install ${mod} /bin/false`) && lines.includes(`blacklist ${mod}`);
}

// ── Estado ───────────────────────────────────────────────────────────

export type StateEntry =
  | { kind: "sysctl"; key: string; runtime: string | null; ours: string | null; boot: string | null; bootSource: string | null }
  | { kind: "kmod"; module: string; loaded: boolean; blocked: boolean }
  | { kind: "audit_rule"; line: string; present: boolean }
  | { kind: "conf"; file: string; key: string; effective: string | null; ours: string | null; effectiveSource: string | null }
  | { kind: "sshd"; key: string; effective: string | null; ours: string | null }
  | { kind: "line"; file: string; line: string; present: boolean }
  | { kind: "pkg"; name: string; installed: boolean; version: string | null }
  | { kind: "unit"; unit: string; isEnabled: boolean; isActive: boolean; state: string }
  | { kind: "perm"; path: string; entries: PermRestore[] }
  | { kind: "banner"; file: string; content: string | null }
  | { kind: "grub_audit"; ours: boolean; entriesWithoutAudit1: number | null; entriesWithoutBacklogLimit: number | null; entriesBacklogBelow8192: number | null };

/** Lo que se lee una vez por petición: la configuración efectiva de sshd. */
export type ReadContext = {
  sshdT: string | null;
  /** Paquetes y unidades: con la MISMA lectura que la sonda (linux-probes.ts). */
  pkgs?: Map<string, { installed: boolean; version: string | null }>;
  units?: Map<string, { isEnabled: boolean; isActive: boolean; state: string }>;
};

export const SSHD_BIN = "/usr/sbin/sshd";

async function readContext(writes: LinuxWrite[], deps: GenericDeps): Promise<ReadContext> {
  let sshdT: string | null = null;
  if (writes.some((w) => w.kind === "sshd")) {
    const r = await deps.exec(SSHD_BIN, ["-T"], 15_000);
    sshdT = r.code === 0 ? r.stdout : null;
  }
  const pkgs = new Map<string, { installed: boolean; version: string | null }>();
  const units = new Map<string, { isEnabled: boolean; isActive: boolean; state: string }>();
  for (const w of writes) {
    if (w.kind === "pkg" && !pkgs.has(w.name)) {
      const p = await probePkg(w.name, { exec: deps.exec, family: "debian" });
      pkgs.set(w.name, { installed: p.installed === true, version: (p.version as string | null) ?? null });
    } else if (w.kind === "unit" && !units.has(w.unit)) {
      const u = await probeUnit(w.unit, { exec: deps.exec });
      units.set(w.unit, { isEnabled: u.isEnabled === true, isActive: u.isActive === true, state: String(u.enabled) });
    }
  }
  return { sshdT, pkgs, units };
}

/** El valor de la directiva en NUESTRO drop-in 00-, o null. */
export function sshdOurs(text: string | null, key: string): string | null {
  const lower = key.toLowerCase();
  let v: string | null = null;
  for (const l of (text ?? "").split("\n")) {
    if (directiveKey(l) === lower && v === null) v = l.trim().replace(/^[^\s=]+\s*=?\s*/, "").trim();
  }
  return v;
}

export function readEntry(w: LinuxWrite, deps: GenericDeps, ctx: ReadContext = { sshdT: null }): StateEntry {
  switch (w.kind) {
    case "sysctl": {
      const ours = sysctlEntries(deps.readFile(SYSCTL_DROPIN)).filter((e) => e.key === w.key).pop()?.value ?? null;
      const boot = sysctlBootValue(w.key, deps);
      return { kind: "sysctl", key: w.key, runtime: sysctlRuntime(w.key, deps), ours: normSysctl(ours), boot: normSysctl(boot.value), bootSource: boot.source };
    }
    case "kmod": {
      const loaded = loadedModules(deps);
      return { kind: "kmod", module: w.module, loaded: loaded.has(w.module) || loaded.has(w.module.replace(/-/g, "_")), blocked: isBlocked(deps.readFile(MODPROBE_DROPIN), w.module) };
    }
    case "audit_rule":
      return { kind: "audit_rule", line: w.line, present: activeLines(deps.readFile(AUDIT_RULES_FILE)).some((l) => sameAuditRule(l, w.line)) };
    case "conf": {
      const eff = effectiveConf(w.file, w.key, deps);
      const ours = lookup(parseKeyValue(deps.readFile(confOursPath(w.file))), w.key);
      return { kind: "conf", file: w.file, key: w.key, effective: eff.value, ours, effectiveSource: eff.source };
    }
    case "line":
      return { kind: "line", file: w.file, line: w.line, present: activeLines(deps.readFile(w.file)).includes(w.line) };
    case "pkg": {
      const p = ctx.pkgs?.get(w.name);
      return { kind: "pkg", name: w.name, installed: p?.installed ?? false, version: p?.version ?? null };
    }
    case "banner": {
      const t = deps.readFile(w.file);
      return { kind: "banner", file: w.file, content: t === null ? null : t.slice(0, 8192) };
    }
    case "grub_audit": {
      const g = probeGrubCmdline({ readFile: deps.readFile } as any) as Record<string, any>;
      const n = (v: unknown) => (typeof v === "number" ? v : null);
      return {
        kind: "grub_audit",
        ours: deps.readFile(GRUB_AUDIT_DROPIN) !== null,
        entriesWithoutAudit1: g.exists ? n(g.entriesWithoutAudit1) : null,
        entriesWithoutBacklogLimit: g.exists ? n(g.entriesWithoutBacklogLimit) : null,
        entriesBacklogBelow8192: g.exists ? n(g.entriesBacklogBelow8192) : null,
      };
    }
    case "perm":
      return { kind: "perm", path: w.path, entries: permTargets(w.path, deps).map((file) => {
        const st = deps.stat(file)!;
        return { file, mode: "0" + (st.mode & 0o777).toString(8).padStart(3, "0"), uid: st.uid, gid: st.gid };
      }) };
    case "unit": {
      const u = ctx.units?.get(w.unit);
      return { kind: "unit", unit: w.unit, isEnabled: u?.isEnabled ?? false, isActive: u?.isActive ?? false, state: u?.state ?? "unknown" };
    }
    case "sshd":
      return {
        kind: "sshd",
        key: w.key,
        effective: ctx.sshdT === null ? null : readEffectiveSshd(w.key, ctx.sshdT) ?? null,
        ours: sshdOurs(deps.readFile(SSHD_DROPIN_FILE), w.key),
      };
  }
}

/** Por qué sshd no se queda con nuestro valor: quién lo fija antes (sshd-dropin.ts). */
function sshdOverrideWhy(key: string, actual: string, deps: GenericDeps): string {
  const dropins = deps.readdir(SSHD_DROPIN_DIR).map((name) => ({ name, content: deps.readFile(pathMod.join(SSHD_DROPIN_DIR, name)) ?? "" }));
  return explainSshdOverride(key, actual, sshdEarlierDefinitions(deps.readFile(SSHD_MAIN_CONFIG) ?? "", dropins, key));
}

/** ¿Está como pide la escritura? Y si no, por qué, en una frase. */
export function satisfied(w: LinuxWrite, e: StateEntry): { ok: boolean; why: string | null } {
  if (w.kind === "sysctl" && e.kind === "sysctl") {
    const v = normSysctl(w.value);
    if (e.runtime !== v) return { ok: false, why: `${w.key} is ${e.runtime ?? "absent"} at runtime, expected ${v}` };
    if (!w.persist) return e.ours === null ? { ok: true, why: null } : { ok: false, why: `${w.key} is still set in ${SYSCTL_DROPIN}` };
    if (e.ours !== v) return { ok: false, why: `${w.key} is not set in ${SYSCTL_DROPIN}` };
    if (e.boot !== v) return { ok: false, why: `${e.bootSource} sets ${w.key} = ${e.boot} after ${SYSCTL_DROPIN}; it wins at boot` };
    return { ok: true, why: null };
  }
  if (w.kind === "kmod" && e.kind === "kmod") {
    if (!w.disable) return e.blocked ? { ok: false, why: `${w.module} is still blocked in ${MODPROBE_DROPIN}` } : { ok: true, why: null };
    if (!e.blocked) return { ok: false, why: `${w.module} is not blocked in ${MODPROBE_DROPIN}` };
    if (e.loaded) return { ok: false, why: `${w.module} is blocked but still loaded (in use); it is gone after a restart` };
    return { ok: true, why: null };
  }
  if (w.kind === "audit_rule" && e.kind === "audit_rule") {
    return e.present === w.present ? { ok: true, why: null } : { ok: false, why: `audit rule ${w.present ? "missing from" : "still in"} ${AUDIT_RULES_FILE}` };
  }
  if (w.kind === "conf" && e.kind === "conf") {
    if (w.value === null) return e.ours === null ? { ok: true, why: null } : { ok: false, why: `${w.key} is still set in ${confOursPath(w.file)}` };
    if (e.ours !== w.value) return { ok: false, why: `${w.key} is not set in ${confOursPath(w.file)}` };
    if (e.effective !== w.value) return { ok: false, why: `${e.effectiveSource} sets ${w.key} = ${e.effective} after ours` };
    return { ok: true, why: null };
  }
  if (w.kind === "banner" && e.kind === "banner") {
    const want = w.restore !== undefined ? w.restore : BANNER_TEXT + "\n";
    return e.content === want ? { ok: true, why: null } : { ok: false, why: `${w.file} does not have the expected text` };
  }
  if (w.kind === "grub_audit" && e.kind === "grub_audit") {
    if (!w.present) return e.ours ? { ok: false, why: `${GRUB_AUDIT_DROPIN} is still there` } : { ok: true, why: null };
    if (!e.ours) return { ok: false, why: `${GRUB_AUDIT_DROPIN} is missing` };
    if (e.entriesWithoutAudit1 === null) return { ok: false, why: "grub.cfg could not be read" };
    if (e.entriesWithoutAudit1 || e.entriesWithoutBacklogLimit || e.entriesBacklogBelow8192) return { ok: false, why: "some boot entries in grub.cfg still lack audit=1 audit_backlog_limit=8192 (another setting overrides it?)" };
    return { ok: true, why: null };
  }
  if (w.kind === "perm" && e.kind === "perm") {
    if (w.restore) {
      const bad = w.restore.find((r) => { const x = e.entries.find((y) => y.file === r.file); return !x || parseInt(x.mode, 8) !== parseInt(r.mode, 8) || x.uid !== r.uid || x.gid !== r.gid; });
      return bad ? { ok: false, why: `${bad.file} is not back to ${bad.mode} ${bad.uid}:${bad.gid}` } : { ok: true, why: null };
    }
    const max = parseInt(w.maxMode, 8);
    const bad = e.entries.find((x) => (parseInt(x.mode, 8) & ~max) !== 0 || x.uid !== 0 || x.gid !== 0);
    return bad ? { ok: false, why: `${bad.file} is ${bad.mode} ${bad.uid}:${bad.gid}, expected at most ${w.maxMode} root:root` } : { ok: true, why: null };
  }
  if (w.kind === "pkg" && e.kind === "pkg") {
    return e.installed === w.installed ? { ok: true, why: null } : { ok: false, why: `${w.name} is ${e.installed ? "still installed" : "not installed"}` };
  }
  if (w.kind === "unit" && e.kind === "unit") {
    if (e.isEnabled === w.enabled && e.isActive === w.enabled) return { ok: true, why: null };
    // Una unidad «static» no se puede deshabilitar: sólo enmascarar, y eso lo decide una persona.
    if (!w.enabled && e.state === "static") return { ok: false, why: `${w.unit} is static: it cannot be disabled, only masked` };
    return { ok: false, why: `${w.unit} is ${e.state} and ${e.isActive ? "active" : "inactive"}` };
  }
  if (w.kind === "line" && e.kind === "line") {
    return e.present === w.present ? { ok: true, why: null } : { ok: false, why: `"${w.line}" ${w.present ? "missing from" : "still in"} ${w.file}` };
  }
  if (w.kind === "sshd" && e.kind === "sshd") {
    const same = (a: string | null, b: string | null) => (a ?? "").toLowerCase() === (b ?? "").toLowerCase();
    if (w.value === null) return e.ours === null ? { ok: true, why: null } : { ok: false, why: `${w.key} is still set in ${SSHD_DROPIN_FILE}` };
    if (!same(e.ours, w.value)) return { ok: false, why: `${w.key} is not set in ${SSHD_DROPIN_FILE}` };
    if (e.effective === null) return { ok: false, why: `could not read the effective sshd configuration (sshd -T failed)` };
    if (!same(e.effective, w.value)) return { ok: false, why: `effective ${w.key} is ${e.effective}` };
    return { ok: true, why: null };
  }
  return { ok: false, why: "state does not match the write" };
}

export async function readGenericState(params: unknown, deps: GenericDeps = realDeps): Promise<Check<{ state: { writes: StateEntry[] }; isCompliant: boolean }>> {
  const parsed = parseWrites(params);
  if (!parsed.ok) return parsed;
  const ctx = await readContext(parsed.value, deps);
  const entries = parsed.value.map((w) => readEntry(w, deps, ctx));
  const isCompliant = parsed.value.every((w, i) => satisfied(w, entries[i]).ok);
  return { ok: true, value: { state: { writes: entries }, isCompliant } };
}

/** Lo que toca una escritura de permisos: la ruta, o los ficheros regulares de su directorio (sin enlaces). */
export function permTargets(path: string, deps: GenericDeps): string[] {
  const st = deps.stat(path);
  if (!st || st.isLink) return [];
  if (PERM_POLICY[path].scope === "path") return [path];
  if (!st.isDir) return [];
  return deps.readdir(path).sort().map((n) => pathMod.posix.join(path, n)).filter((f) => deps.stat(f)?.isFile === true);
}

// ── Edición de ficheros (puras: texto → texto) ───────────────────────

/** Deja `key = value` una sola vez en NUESTRO fichero de sysctl, o la quita (value null). */
export function editSysctlDropin(text: string | null, key: string, value: string | null): string {
  const kept = (text ?? "").split("\n").filter((l) => {
    const m = /^\s*-?([^=#\s]+)\s*=/.exec(l);
    return !(m && m[1].replace(/\//g, ".") === key);
  });
  while (kept.length && kept[kept.length - 1].trim() === "") kept.pop();
  if (!kept.length) kept.push("# Managed by Tracenium — compliance fixes. Remove a line to hand it back.");
  if (value !== null) kept.push(`${key} = ${value}`);
  return kept.join("\n") + "\n";
}

export function editModprobeDropin(text: string | null, mod: string, block: boolean): string {
  const drop = new Set([`install ${mod} /bin/false`, `blacklist ${mod}`]);
  const kept = (text ?? "").split("\n").filter((l) => !drop.has(l.trim()));
  while (kept.length && kept[kept.length - 1].trim() === "") kept.pop();
  if (!kept.length) kept.push("# Managed by Tracenium — kernel modules blocked by compliance fixes.");
  if (block) kept.push(`install ${mod} /bin/false`, `blacklist ${mod}`);
  return kept.join("\n") + "\n";
}

/**
 * ¿Son la misma regla para el kernel? `-w /etc/apparmor/` y `-w /etc/apparmor`
 * lo son: el catálogo pedía una con barra (CIS 22/24) y otra sin ella (CIS 26),
 * y con las dos en el fichero `augenrules --load` fallaba con «Rule exists»
 * (jobs 36c24a50 / 846f7486, 29-sep). La barra final no cuenta; la raíz sí.
 */
export function sameAuditRule(a: string, b: string): boolean {
  if (a === b) return true;
  const wa = WATCH_RULE.exec(a);
  const wb = WATCH_RULE.exec(b);
  if (!wa || !wb) return false;
  const norm = (p: string) => (p.length > 1 ? p.replace(/\/+$/, "") : p);
  return norm(wa[1]) === norm(wb[1]) && wa[2] === wb[2] && wa[3] === wb[3];
}

export function editAuditRules(text: string | null, line: string, present: boolean): string {
  // Ya está (en esta forma o en la equivalente): no se toca ni se recarga.
  if (present && text !== null && activeLines(text).some((l) => sameAuditRule(l, line))) return text;
  const kept = (text ?? "").split("\n").filter((l) => !sameAuditRule(l.trim(), line));
  while (kept.length && kept[kept.length - 1].trim() === "") kept.pop();
  if (!kept.length) kept.push("## Managed by Tracenium — audit rules added by compliance fixes.");
  if (present) kept.push(line);
  return kept.join("\n") + "\n";
}

function formatConf(style: ConfPolicy["style"], key: string, value: string): string {
  if (style === "bare") return `${key}\t${value}`;
  if (style === "shell" || style === "systemd") return `${key}=${value}`;
  return `${key} = ${value}`;
}

/**
 * Una clave en un fichero «clave = valor». Se sustituye la ÚLTIMA línea
 * activa (la que gana) y se comentan las anteriores; sin ninguna, se añade
 * al final (en un drop-in de systemd, bajo su sección). value null = quitar
 * las líneas activas de esa clave.
 */
export function editConf(text: string | null, policy: ConfPolicy, key: string, value: string | null, isDropin: boolean): string {
  const lines = (text ?? "").split("\n");
  const re = new RegExp(`^\\s*${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*(=|\\s)`, "i");
  const hits = lines.map((l, i) => (re.test(l) && !/^\s*#/.test(l) ? i : -1)).filter((i) => i >= 0);
  if (value === null) {
    const out = lines.filter((_, i) => !hits.includes(i));
    return out.join("\n").replace(/\n*$/, "\n");
  }
  const newLine = formatConf(policy.style, key, value);
  if (hits.length) {
    const last = hits[hits.length - 1];
    for (const i of hits) lines[i] = i === last ? newLine : `# ${lines[i].trim()}  # superseded by Tracenium`;
    return lines.join("\n").replace(/\n*$/, "\n");
  }
  const out = lines.slice();
  while (out.length && out[out.length - 1].trim() === "") out.pop();
  if (isDropin && policy.section && !out.some((l) => l.trim() === `[${policy.section}]`)) {
    if (!out.length) out.push("# Managed by Tracenium — compliance fixes.");
    out.push(`[${policy.section}]`);
  }
  out.push(newLine);
  return out.join("\n") + "\n";
}

// ── auditd: comprobar antes de escribir ──────────────────────────────

/** Nombre de máquina de ausyscall para cada arch de auditd, o null si no sabemos. */
export function ausyscallMachine(arch: "32" | "64", machine: string): string | null {
  if (machine === "x86_64" || machine === "amd64" || machine === "x64") return arch === "64" ? "x86_64" : "i386";
  if (machine === "aarch64" || machine === "arm64") return arch === "64" ? "aarch64" : null;
  return null;
}

const AUSYSCALL = ["/usr/sbin/ausyscall", "/sbin/ausyscall", "/usr/bin/ausyscall"];
const SYSTEMD_RUN = "/usr/bin/systemd-run";
const APT_GET = "/usr/bin/apt-get";
// Sin preguntas y en inglés (los mensajes se parsean). apt-get corre sin
// confinar (Ux en el perfil), como el parcheo.
const APT_ENV = { DEBIAN_FRONTEND: "noninteractive", LANG: "C", LC_ALL: "C" };

// ── Metapaquetes que caen de rebote ──────────────────────────────────
//
// Quitar algo que apt no pidió quitar no se hace (se rechaza antes). Con UNA
// excepción medida: `ubuntu-standard` exige «ftp | tnftp», así que CIS 2.2.6
// («ftp client is not installed») no se puede cumplir sin quitarlo — el propio
// `apt purge ftp tnftp` de CIS lo quita (job f6029718, VPS, 1-oct). Es un
// metapaquete vacío: en ubuntu:24.04, de 201 dependencias automáticas, 0 quedaron
// para autoremove. Aun así, antes de quitarlo sus dependencias instaladas se
// marcan como instaladas a mano, para que ningún `autoremove` futuro se lleve
// nada en ningún servidor; y se apunta, para que el revert lo reinstale.

/** Metapaquete → los ÚNICOS paquetes cuya retirada puede arrastrarlo. */
export const METAPACKAGE_COLLATERAL: Readonly<Record<string, readonly string[]>> = Object.freeze({
  "ubuntu-standard": ["ftp", "tnftp"],
});

/** De lo que apt quitaría además de `names`, qué se acepta y qué no. */
export function splitCollateral(names: readonly string[], extra: readonly string[]): { allowed: string[]; blocked: string[] } {
  const allowed: string[] = [];
  const blocked: string[] = [];
  for (const p of extra) {
    const only = METAPACKAGE_COLLATERAL[p];
    (only && names.length > 0 && names.every((n) => only.includes(n)) ? allowed : blocked).push(p);
  }
  return { allowed, blocked };
}

/** «a, b | c (>= 1), d:any» → [a, b, c, d]. */
export function parseDpkgDepends(field: string): string[] {
  const out = new Set<string>();
  for (const alt of field.split(/[,|]/)) {
    const name = alt.trim().split(/[\s(]/)[0]?.replace(/:[a-z0-9]+$/, "");
    if (name && /^[a-z0-9][a-z0-9+.-]*$/.test(name)) out.add(name);
  }
  return [...out];
}

export const REMOVED_META_FILE = "/var/lib/tracenium/pmp-removed-metapackages.json";
const DPKG_QUERY = "/usr/bin/dpkg-query";
const APT_MARK = "/usr/bin/apt-mark";

type RemovedMeta = Record<string, { removedAt: string; with: string[] }>;
function readRemovedMeta(deps: GenericDeps): RemovedMeta {
  try {
    const v = JSON.parse(deps.readFile(REMOVED_META_FILE) ?? "{}");
    return v && typeof v === "object" && !Array.isArray(v) ? v : {};
  } catch {
    return {};
  }
}

/** Sus dependencias instaladas (Depends + Recommends), sin las que se van a quitar. */
async function installedDepsOf(meta: string, except: readonly string[], deps: GenericDeps): Promise<string[] | null> {
  const f = await deps.exec(DPKG_QUERY, ["-W", "-f=${Depends}, ${Recommends}", meta], 30_000, APT_ENV);
  if (f.code !== 0) return null;
  const wanted = parseDpkgDepends(f.stdout).filter((n) => !except.includes(n));
  if (!wanted.length) return [];
  // Los que no existen hacen que dpkg-query salga con error, pero lista los demás.
  const st = await deps.exec(DPKG_QUERY, ["-W", "-f=${Package}\t${Status}\n", ...wanted], 30_000, APT_ENV);
  return st.stdout.split("\n").filter((l) => /\tinstall ok installed$/.test(l)).map((l) => l.split("\t")[0]);
}

/** Paquetes que `apt-get -s` quitaría (líneas «Remv <paquete> …»). */
export function aptRemovals(simOutput: string): string[] {
  const out: string[] = [];
  for (const line of simOutput.split("\n")) {
    const m = /^Remv (\S+)/.exec(line.trim());
    if (m) out.push(m[1].replace(/:[a-z0-9]+$/, ""));
  }
  return out;
}
const AUGENRULES = ["/usr/sbin/augenrules", "/sbin/augenrules"];
const AUDITCTL = ["/usr/sbin/auditctl", "/sbin/auditctl"];

function firstExisting(paths: string[], deps: GenericDeps): string | null {
  return paths.find((p) => deps.fileMode(p) !== null) ?? null;
}

/**
 * Un comando que necesita capacidades que el perfil no concede, por
 * systemd-run. Sin systemd (raro en las distros que soportamos) se lanza
 * tal cual: fallará igual que antes, con su error.
 */
function privileged(bin: string, args: string[], deps: GenericDeps, timeoutMs = 60_000) {
  if (deps.fileMode(SYSTEMD_RUN) === null) return deps.exec(bin, args, timeoutMs);
  return deps.exec(SYSTEMD_RUN, ["--wait", "--pipe", "--collect", "--quiet", "--", bin, ...args], timeoutMs);
}

/**
 * Por qué falló `augenrules --load`, en una línea. auditctl escribe «Old style
 * watch rules are slower» por CADA regla -w antes del error de verdad, así
 * que los primeros 200 caracteres eran sólo avisos y el motivo («Rule
 * exists», «There was an error in line 57…») no llegaba al job (36c24a50,
 * 29-sep). Se quitan los avisos y, si hay líneas de error, sólo esas.
 */
export function augenrulesFailure(r: { stdout: string; stderr: string }): string {
  const lines = `${r.stderr ?? ""}\n${r.stdout ?? ""}`
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !/^old style watch rules are slower$/i.test(l));
  const errors = lines.filter((l) => /error|rule exists|invalid|unknown|no such|not supported|failed/i.test(l));
  const picked = [...new Set(errors.length ? errors : lines)];
  return picked.join(" | ").slice(0, 300) || "no output";
}

/** Motivo por el que una regla haría fallar la carga en ESTA máquina, o null. */
export async function auditRuleProblem(line: string, deps: GenericDeps): Promise<string | null> {
  const watch = WATCH_RULE.exec(line);
  if (watch) {
    const dir = watch[1].endsWith("/") ? watch[1] : pathMod.dirname(watch[1]);
    return deps.isDir(dir) ? null : `${dir} does not exist on this machine, so auditd cannot watch ${watch[1]}`;
  }
  const sc = SYSCALL_RULE.exec(line);
  if (!sc) return "unrecognised audit rule";
  const machine = ausyscallMachine(sc[1] as "32" | "64", deps.machine());
  if (!machine) return `auditd has no ${sc[1]}-bit syscall table Tracenium can check on ${deps.machine()}`;
  const bin = firstExisting(AUSYSCALL, deps);
  if (!bin) return "ausyscall is not installed (auditd package missing)";
  for (const name of sc[2].split(",")) {
    const r = await deps.exec(bin, [machine, name, "--exact"], 10_000);
    if (r.code !== 0 || !/^\d+\s*$/.test(r.stdout.trim())) return `syscall ${name} does not exist for arch=b${sc[1]} on this machine (${deps.machine()})`;
  }
  return null;
}

// ── Aplicar ──────────────────────────────────────────────────────────

export type GenericOutcome = {
  exitCode: number;
  stderrExcerpt?: string;
  durationMs: number;
  requiresReboot: boolean;
  changesApplied: string[];
};

function stamp(d: Date): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "").replace("T", "-");
}

export async function applyGeneric(params: unknown, deps: GenericDeps = realDeps): Promise<Check<GenericOutcome>> {
  const t0 = Date.now();
  const parsed = parseWrites(params);
  if (!parsed.ok) return parsed;
  const writes = parsed.value;
  const changes: string[] = [];
  const problems: string[] = [];
  let requiresReboot = false;
  const done = (exitCode: number): Check<GenericOutcome> => ({
    ok: true,
    value: { exitCode, stderrExcerpt: problems.length ? problems.join("; ").slice(0, 1024) : undefined, durationMs: Date.now() - t0, requiresReboot, changesApplied: changes },
  });

  // ── Antes de tocar nada: lo que sabemos que no puede salir bien ──
  const auditAdds = writes.filter((w): w is Extract<LinuxWrite, { kind: "audit_rule" }> => w.kind === "audit_rule" && w.present);
  if (writes.some((w) => w.kind === "audit_rule") && !deps.isDir(AUDIT_RULES_DIR)) {
    problems.push(`${AUDIT_RULES_DIR} does not exist — auditd is not installed`);
    return done(2);
  }
  for (const w of auditAdds) {
    if (activeLines(deps.readFile(AUDIT_RULES_FILE)).some((l) => sameAuditRule(l, w.line))) continue;
    const p = await auditRuleProblem(w.line, deps);
    if (p) problems.push(p);
  }
  if (problems.length) return done(2);

  // Líneas: el directorio de nuestro fichero tiene que existir. No se crea:
  // /etc/audit/rules.d sin auditd daba un «applied» con reglas que nadie
  // carga (SRVOC-MainAgent, 29-sep), y el siguiente escaneo las contaba.
  for (const w of writes) {
    if (w.kind !== "line" || !w.present || LINE_FILES[w.file].mode !== "ours") continue;
    const dir = pathMod.dirname(w.file);
    if (deps.isDir(dir)) continue;
    problems.push(dir === AUDIT_RULES_DIR ? `${AUDIT_RULES_DIR} does not exist — auditd is not installed` : `${dir} does not exist on this machine`);
  }
  if (problems.length) return done(2);

  // sshd: la configuración de ahora tiene que ser válida (si no, `sshd -t`
  // rechazaría también la nuestra), los algoritmos que este OpenSSH no conoce
  // se quitan de la lista (salvo los que el check necesita), y el banner
  // tiene que existir. Todo antes de escribir nada.
  const sshdWrites = writes.filter((w): w is Extract<LinuxWrite, { kind: "sshd" }> => w.kind === "sshd");
  const sshdValue = new Map<Extract<LinuxWrite, { kind: "sshd" }>, string | null>();
  if (sshdWrites.length) {
    if (deps.fileMode(SSHD_BIN) === null) {
      problems.push("the OpenSSH server (sshd) is not installed");
      return done(2);
    }
    const baseline = await deps.exec(SSHD_BIN, ["-t"], 15_000);
    if (baseline.code !== 0) {
      problems.push(`the current sshd configuration is already invalid, so no change can be validated: ${(baseline.stderr || baseline.stdout).trim().slice(0, 200)}`);
      return done(2);
    }
    for (const w of sshdWrites) {
      if (w.value === null || !SSHD_DIRECTIVES[w.key.toLowerCase()].list) {
        if (w.key === "Banner" && w.value !== null && w.value !== "none" && deps.readFile(w.value) === null) problems.push(`${w.value} does not exist, so sshd has no banner to show`);
        sshdValue.set(w, w.value);
        continue;
      }
      const kept: string[] = [];
      const dropped: string[] = [];
      for (const item of w.value.split(",")) {
        const r = await deps.exec(SSHD_BIN, ["-t", "-o", `${w.key}=${item}`], 15_000);
        (r.code === 0 ? kept : dropped).push(item);
      }
      const missing = (w.required ?? []).filter((r) => dropped.includes(r));
      if (missing.length) problems.push(`this OpenSSH does not support ${missing.join(", ")}, which the check needs; upgrade OpenSSH`);
      else if (!kept.length) problems.push(`this OpenSSH supports none of the ${w.key} Tracenium sets`);
      else if (dropped.length) changes.push(`${w.key}: left out ${dropped.join(", ")} (not supported by this OpenSSH)`);
      sshdValue.set(w, kept.join(","));
    }
    if (problems.length) return done(2);
  }

  // GRUB: sólo el de Debian/Ubuntu, y con auditd (audit=1 sin él vuelca el
  // registro de auditoría en el log del kernel).
  const grub = writes.find((w): w is Extract<LinuxWrite, { kind: "grub_audit" }> => w.kind === "grub_audit");
  if (grub) {
    if (deps.fileMode(UPDATE_GRUB) === null || deps.readFile("/boot/grub/grub.cfg") === null) {
      problems.push("this machine does not boot with the Debian/Ubuntu GRUB (no update-grub or /boot/grub/grub.cfg)");
      return done(2);
    }
    if (grub.present && deps.fileMode("/usr/sbin/auditd") === null && deps.fileMode("/sbin/auditd") === null) {
      problems.push("auditd is not installed: install it first (audit=1 without auditd sends every audit record to the kernel log)");
      return done(2);
    }
  }

  // Paquetes: sólo apt, y lo que apt haría se mira antes (simulación, sin tocar nada).
  const pkgWrites = writes.filter((w): w is Extract<LinuxWrite, { kind: "pkg" }> => w.kind === "pkg");
  // Metapaquetes que se aceptan de rebote (METAPACKAGE_COLLATERAL).
  const collateral: string[] = [];
  if (pkgWrites.length) {
    if (deps.fileMode(APT_GET) === null) {
      problems.push("only apt (Debian/Ubuntu) is supported for package fixes");
      return done(2);
    }
    for (const [verb, names] of [["install", pkgWrites.filter((w) => w.installed).map((w) => w.name)], ["remove", pkgWrites.filter((w) => !w.installed).map((w) => w.name)]] as const) {
      if (!names.length) continue;
      const sim = await deps.exec(APT_GET, ["-s", verb, ...(verb === "install" ? ["--no-install-recommends"] : []), ...names], 120_000, APT_ENV);
      if (sim.code !== 0) {
        problems.push(`apt-get -s ${verb} ${names.join(" ")} failed: ${(sim.stderr || sim.stdout).trim().slice(0, 200)}`);
        continue;
      }
      const extra = aptRemovals(sim.stdout).filter((p) => verb === "install" || !names.includes(p));
      const { allowed, blocked } = verb === "remove" ? splitCollateral(names, extra) : { allowed: [], blocked: extra };
      if (blocked.length) problems.push(`${verb === "install" ? "installing" : "removing"} ${names.join(", ")} would also remove ${blocked.slice(0, 8).join(", ")}${blocked.length > 8 ? "…" : ""} — not done`);
      else collateral.push(...allowed);
    }
    if (problems.length) return done(2);
  }

  // ── sysctl ──
  const sysctl = writes.filter((w): w is Extract<LinuxWrite, { kind: "sysctl" }> => w.kind === "sysctl");
  if (sysctl.length) {
    const before = deps.readFile(SYSCTL_DROPIN);
    let text = before;
    for (const w of sysctl) text = editSysctlDropin(text, w.key, w.persist ? w.value : null);
    if (text !== before) {
      deps.mkdirp(pathMod.dirname(SYSCTL_DROPIN));
      deps.writeFile(SYSCTL_DROPIN, text!, 0o644);
      changes.push(`wrote ${SYSCTL_DROPIN}`);
    }
    for (const w of sysctl) {
      if (sysctlRuntime(w.key, deps) === normSysctl(w.value)) continue;
      const r = await privileged("/usr/sbin/sysctl", ["-q", "-w", `${w.key}=${w.value}`], deps, 30_000);
      if (r.code === 0) changes.push(`sysctl ${w.key}=${w.value}`);
      else problems.push(`sysctl -w ${w.key} failed: ${(r.stderr || r.stdout).trim().slice(0, 160)}`);
    }
  }

  // ── módulos ──
  const kmods = writes.filter((w): w is Extract<LinuxWrite, { kind: "kmod" }> => w.kind === "kmod");
  if (kmods.length) {
    const before = deps.readFile(MODPROBE_DROPIN);
    let text = before;
    for (const w of kmods) text = editModprobeDropin(text, w.module, w.disable);
    if (text !== before) {
      deps.mkdirp(pathMod.dirname(MODPROBE_DROPIN));
      deps.writeFile(MODPROBE_DROPIN, text!, 0o644);
      changes.push(`wrote ${MODPROBE_DROPIN}`);
    }
    const loaded = loadedModules(deps);
    for (const w of kmods) {
      if (!w.disable || !(loaded.has(w.module) || loaded.has(w.module.replace(/-/g, "_")))) continue;
      const r = await privileged("/usr/sbin/modprobe", ["-r", w.module], deps, 30_000);
      if (r.code === 0) changes.push(`unloaded ${w.module}`);
      else requiresReboot = true; // en uso: bloqueado en disco, se va al reiniciar
    }
  }

  // ── auditd ──
  const audit = writes.filter((w): w is Extract<LinuxWrite, { kind: "audit_rule" }> => w.kind === "audit_rule");
  if (audit.length) {
    const before = deps.readFile(AUDIT_RULES_FILE);
    let text = before;
    for (const w of audit) text = editAuditRules(text, w.line, w.present);
    if (text !== before) {
      deps.writeFile(AUDIT_RULES_FILE, text!, 0o640);
      changes.push(`wrote ${AUDIT_RULES_FILE}`);
      const auditctl = firstExisting(AUDITCTL, deps);
      const status = auditctl ? await privileged(auditctl, ["-s"], deps, 30_000) : null;
      const immutable = !!status && /\benabled\s+2\b/.test(status.stdout);
      const augenrules = firstExisting(AUGENRULES, deps);
      if (immutable) {
        requiresReboot = true;
      } else if (augenrules) {
        const r = await privileged(augenrules, ["--load"], deps);
        if (r.code !== 0) {
          // Una regla que no carga para la carga entera en el próximo
          // arranque: se deja el fichero como estaba y se recarga.
          if (before === null) deps.unlink(AUDIT_RULES_FILE);
          else deps.writeFile(AUDIT_RULES_FILE, before, 0o640);
          await privileged(augenrules, ["--load"], deps);
          changes.push(`restored ${AUDIT_RULES_FILE}`);
          problems.push(`augenrules --load failed, rules restored: ${augenrulesFailure(r)}`);
          return done(1);
        }
        changes.push("augenrules --load");
      }
    }
  }

  // ── clave = valor ──
  const restarts = new Set<string>();
  const backedUp = new Set<string>();
  for (const w of writes) {
    if (w.kind !== "conf") continue;
    const policy = CONF_FILES[w.file];
    const target = confOursPath(w.file);
    const isDropin = policy.mode === "dropin";
    const before = deps.readFile(target);
    if (before === null && w.value === null) continue; // nada nuestro que quitar
    if (!isDropin && before === null) {
      problems.push(`${w.file} does not exist on this machine`);
      continue;
    }
    const text = editConf(before, policy, w.key, w.value, isDropin);
    if (text === (before ?? "")) continue;
    if (!isDropin && !backedUp.has(target)) {
      deps.copyFile(target, `${target}.tracenium.${stamp(deps.now())}.bak`);
      backedUp.add(target);
    }
    if (isDropin) deps.mkdirp(pathMod.dirname(target));
    deps.writeFile(target, text, deps.fileMode(target) ?? 0o644);
    changes.push(`${w.key} in ${target}`);
    if (policy.effect === "reboot") requiresReboot = true;
    if (policy.effect === "service" && policy.restart) restarts.add(policy.restart);
  }
  for (const unit of restarts) {
    const r = await deps.exec("/usr/bin/systemctl", ["restart", unit], 30_000);
    if (r.code === 0) changes.push(`restarted ${unit}`);
    else problems.push(`systemctl restart ${unit} failed: ${(r.stderr || r.stdout).trim().slice(0, 160)}`);
  }

  // ── líneas ──
  // Por fichero: se quita/añade la línea exacta. En los ficheros del sistema
  // (`append`) sólo la línea pedida, y con copia antes del primer cambio.
  const lineWrites = writes.filter((w): w is Extract<LinuxWrite, { kind: "line" }> => w.kind === "line");
  for (const file of [...new Set(lineWrites.map((w) => w.file))]) {
    const policy = LINE_FILES[file];
    const before = deps.readFile(file);
    if (policy.mode === "append" && before === null) {
      problems.push(`${file} does not exist on this machine`);
      continue;
    }
    let text = before ?? "";
    for (const w of lineWrites.filter((x) => x.file === file)) {
      const kept = text.split("\n").filter((l) => l.trim() !== w.line);
      while (kept.length && kept[kept.length - 1].trim() === "") kept.pop();
      if (!kept.length && policy.mode === "ours") kept.push("# Managed by Tracenium — compliance fixes. Remove a line to hand it back.");
      if (w.present) kept.push(w.line);
      text = kept.join("\n") + "\n";
    }
    // Un fichero nuestro que se queda sólo con la cabecera sobra.
    const empty = policy.mode === "ours" && activeLines(text).length === 0;
    if ((empty ? null : text) === before || (empty && before === null)) continue;
    if (policy.mode === "append") deps.copyFile(file, `${file}.tracenium.${stamp(deps.now())}.bak`);
    if (empty) deps.unlink(file);
    else deps.writeFile(file, text, policy.mode === "append" ? deps.fileMode(file) ?? policy.perms : policy.perms);
    changes.push(`${empty ? "removed" : "wrote"} ${file}`);
    if (policy.reload === "augenrules") {
      const augenrules = firstExisting(AUGENRULES, deps);
      if (augenrules) {
        const r = await privileged(augenrules, ["--load"], deps);
        if (r.code === 0) changes.push("augenrules --load");
        else problems.push(`augenrules --load failed: ${augenrulesFailure(r)}`);
      }
    }
  }

  // ── sshd ──
  if (sshdWrites.length) {
    const orig = { primary: deps.readFile(SSHD_DROPIN_FILE), legacy: deps.readFile(LEGACY_SSHD_DROPIN_FILE) };
    const next = { ...orig };
    for (const w of sshdWrites) {
      for (const c of planSshDropinChanges({ primary: next.primary ?? "", legacy: next.legacy ?? "" }, w.key, sshdValue.get(w) ?? null)) {
        if (c.file === SSHD_DROPIN_FILE) next.primary = c.newContent;
        else next.legacy = c.newContent;
      }
    }
    const touched = ([[SSHD_DROPIN_FILE, "primary"], [LEGACY_SSHD_DROPIN_FILE, "legacy"]] as const).filter(([, k]) => (next[k] ?? null) !== (orig[k] ?? null) && !(next[k] === "" && orig[k] === null));
    if (touched.length) {
      const ts = stamp(deps.now());
      for (const [file, k] of touched) if (orig[k] !== null) deps.copyFile(file, `${file}.tracenium.${ts}.bak`);
      const restore = () => {
        for (const [file, k] of touched) {
          if (orig[k] === null) deps.unlink(file);
          else deps.writeFile(file, orig[k]!, 0o600);
        }
      };
      deps.mkdirp(SSHD_DROPIN_DIR);
      for (const [file, k] of touched) {
        if (next[k] === null) deps.unlink(file);
        // 0600: CIS lo pide a cada fichero de sshd_config.d, el nuestro incluido.
        else deps.writeFile(file, next[k]!, 0o600);
      }
      const check = await deps.exec(SSHD_BIN, ["-t"], 15_000);
      if (check.code !== 0) {
        restore();
        problems.push(`sshd -t rejected the new configuration, files restored: ${(check.stderr || check.stdout).trim().slice(0, 200)}`);
        return done(1);
      }
      changes.push(`wrote ${touched.map(([f]) => f).join(", ")}`);
      // Recargar es gracioso: las sesiones abiertas siguen. Sin sshd en marcha
      // (socket de systemd sin conexiones aún) lo lee al arrancar.
      let reloaded = false;
      for (const unit of ["ssh.service", "sshd.service"]) {
        if ((await deps.exec("/usr/bin/systemctl", ["reload", unit], 30_000)).code === 0) {
          changes.push(`reloaded ${unit}`);
          reloaded = true;
          break;
        }
      }
      if (!reloaded) {
        const active = await deps.exec("/usr/bin/systemctl", ["is-active", "ssh.service", "sshd.service"], 10_000);
        if (/^active$/m.test(active.stdout)) problems.push("sshd is running but could not be reloaded: the change applies when it restarts");
        else changes.push("sshd is not running: the change applies when it starts");
      }
    }
  }

  // ── paquetes ──
  const removedMeta = readRemovedMeta(deps);
  for (const [verb, asked] of [["install", pkgWrites.filter((w) => w.installed).map((w) => w.name)], ["remove", pkgWrites.filter((w) => !w.installed).map((w) => w.name)]] as const) {
    if (!asked.length) continue;
    let names: string[] = [...asked];
    // Revert: un metapaquete que quitamos con estos vuelve con ellos.
    const reinstall = verb === "install" ? Object.keys(removedMeta).filter((m) => removedMeta[m].with.some((n) => asked.includes(n))) : [];
    if (verb === "install") names = [...names, ...reinstall];
    if (verb === "remove" && collateral.length) {
      // Antes de quitarlo, lo que traía queda como instalado a mano: ningún
      // autoremove posterior se lo lleva.
      let marked = true;
      for (const meta of collateral) {
        const keep = await installedDepsOf(meta, asked, deps);
        if (keep === null) { marked = false; problems.push(`could not read the dependencies of ${meta} — not removed`); break; }
        if (!keep.length) continue;
        const m = await deps.exec(APT_MARK, ["manual", ...keep], 120_000, APT_ENV);
        if (m.code !== 0) { marked = false; problems.push(`apt-mark manual (dependencies of ${meta}) failed: ${(m.stderr || m.stdout).trim().slice(0, 200)}`); break; }
        changes.push(`apt-mark manual ${keep.length} dependencies of ${meta}`);
      }
      if (!marked) continue;
      names = [...names, ...collateral];
    }
    const args = [
      verb, "-y",
      ...(verb === "install" ? ["--no-install-recommends"] : []),
      "-o", "DPkg::Lock::Timeout=120",
      "-o", "Dpkg::Options::=--force-confdef",
      "-o", "Dpkg::Options::=--force-confold",
      ...names,
    ];
    const r = await deps.exec(APT_GET, args, 900_000, APT_ENV);
    if (r.code === 0) {
      changes.push(`apt-get ${verb} ${names.join(" ")}`);
      const before = JSON.stringify(removedMeta);
      if (verb === "remove") for (const meta of collateral) removedMeta[meta] = { removedAt: deps.now().toISOString(), with: [...asked] };
      for (const meta of reinstall) delete removedMeta[meta];
      if (JSON.stringify(removedMeta) !== before) {
        deps.mkdirp(pathMod.dirname(REMOVED_META_FILE));
        deps.writeFile(REMOVED_META_FILE, JSON.stringify(removedMeta, null, 1) + "\n", 0o600);
      }
    } else problems.push(`apt-get ${verb} ${names.join(" ")} failed: ${(r.stderr || r.stdout).trim().split("\n").slice(-3).join(" ").slice(0, 300)}`);
  }

  // ── unidades ── (después de instalar: auditd tiene que existir para arrancarlo)
  for (const w of writes) {
    if (w.kind !== "unit") continue;
    const units = [w.unit, ...(UNIT_POLICY[w.unit].with ?? [])];
    const r = await privileged("/usr/bin/systemctl", [w.enabled ? "enable" : "disable", "--now", ...units], deps, 60_000);
    if (r.code === 0) changes.push(`systemctl ${w.enabled ? "enable" : "disable"} --now ${units.join(" ")}`);
    else problems.push(`systemctl ${w.enabled ? "enable" : "disable"} ${w.unit} failed: ${(r.stderr || r.stdout).trim().slice(0, 200)}`);
  }

  // ── avisos ──
  for (const w of writes) {
    if (w.kind !== "banner") continue;
    const before = deps.readFile(w.file);
    const want = w.restore !== undefined ? w.restore : BANNER_TEXT + "\n";
    if (before === want) continue;
    if (before !== null) deps.copyFile(w.file, `${w.file}.tracenium.${stamp(deps.now())}.bak`);
    if (want === null) deps.unlink(w.file);
    else deps.writeFile(w.file, want, 0o644);
    changes.push(`${want === null ? "removed" : "wrote"} ${w.file}`);
  }

  // ── GRUB ── (update-grub escribe en /boot, negado en el perfil: por systemd-run)
  if (grub) {
    const before = deps.readFile(GRUB_AUDIT_DROPIN);
    const want = grub.present ? GRUB_AUDIT_LINE + "\n" : null;
    if (before !== want) {
      if (want === null) deps.unlink(GRUB_AUDIT_DROPIN);
      else {
        deps.mkdirp(pathMod.dirname(GRUB_AUDIT_DROPIN));
        deps.writeFile(GRUB_AUDIT_DROPIN, want, 0o644);
      }
      const r = await privileged(UPDATE_GRUB, [], deps, 300_000);
      if (r.code === 0) {
        changes.push(`${want === null ? "removed" : "wrote"} ${GRUB_AUDIT_DROPIN}`, "update-grub");
        requiresReboot = true;
      } else {
        // grub-mkconfig escribe grub.cfg.new y lo mueve: si falla, grub.cfg no cambió. Se deja el drop-in como estaba.
        if (before === null) deps.unlink(GRUB_AUDIT_DROPIN);
        else deps.writeFile(GRUB_AUDIT_DROPIN, before, 0o644);
        problems.push(`update-grub failed, ${GRUB_AUDIT_DROPIN} restored: ${(r.stderr || r.stdout).trim().split("\n").slice(-2).join(" ").slice(0, 200)}`);
        return done(1);
      }
    }
  }

  // ── permisos ── (por systemd-run: el perfil no concede chown ni fowner)
  for (const w of writes) {
    if (w.kind !== "perm") continue;
    const plan: Array<{ file: string; mode: number; uid: number; gid: number }> = w.restore
      ? w.restore.map((r) => ({ file: r.file, mode: parseInt(r.mode, 8), uid: r.uid, gid: r.gid }))
      : permTargets(w.path, deps).map((file) => {
          const st = deps.stat(file)!;
          return { file, mode: st.mode & 0o7777 & parseInt(w.maxMode, 8), uid: 0, gid: 0 };
        });
    for (const p of plan) {
      const st = deps.stat(p.file);
      if (!st || st.isLink) continue; // desapareció o es un enlace: no se sigue
      if (st.uid !== p.uid || st.gid !== p.gid) {
        const r = await privileged("/usr/bin/chown", [`${p.uid}:${p.gid}`, p.file], deps, 30_000);
        if (r.code === 0) changes.push(`chown ${p.uid}:${p.gid} ${p.file}`);
        else problems.push(`chown ${p.file} failed: ${(r.stderr || r.stdout).trim().slice(0, 160)}`);
      }
      // chown puede quitar setuid/setgid: el modo va después.
      if ((deps.stat(p.file)?.mode ?? st.mode) !== p.mode) {
        const octal = "0" + p.mode.toString(8).padStart(3, "0");
        const r = await privileged("/usr/bin/chmod", [octal, p.file], deps, 30_000);
        if (r.code === 0) changes.push(`chmod ${octal} ${p.file}`);
        else problems.push(`chmod ${p.file} failed: ${(r.stderr || r.stdout).trim().slice(0, 160)}`);
      }
    }
  }

  // ── Releer con el mismo criterio que la sonda ──
  const ctx = await readContext(writes, deps);
  for (const w of writes) {
    if (w.kind === "sshd") {
      const applied = { ...w, value: sshdValue.get(w) ?? null };
      const e = readEntry(applied, deps, ctx);
      const s = satisfied(applied, e);
      if (s.ok) continue;
      // Otro fichero la fija antes que el nuestro: se dice cuál y en qué línea.
      problems.push(e.kind === "sshd" && e.effective !== null && e.ours !== null ? sshdOverrideWhy(w.key, e.effective, deps) : s.why ?? "not applied");
      continue;
    }
    const s = satisfied(w, readEntry(w, deps, ctx));
    // Un módulo en uso es un «aplicado, falta reiniciar», no un fallo.
    if (!s.ok && !(w.kind === "kmod" && w.disable && requiresReboot)) problems.push(s.why ?? "not applied");
  }
  return done(problems.length ? 1 : 0);
}
