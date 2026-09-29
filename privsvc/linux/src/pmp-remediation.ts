// privsvc/linux/src/pmp-remediation.ts
//
// PMP v2 — non-patch security remediation handlers for Linux.
// Phase 8 ships 4 checkIds:
//
//   linux.ssh.root_login_disabled
//   linux.ssh.password_auth_disabled
//   linux.cryptography.weak_ssh_kex_disabled
//   linux.firewall.enabled
//
// Same wire contract as macOS / Windows handlers:
//   * pmp.read_check_state → returns { state, isCompliant, supported }
//   * pmp.remediate        → returns { exitCode, stderrExcerpt,
//                                       durationMs, requiresReboot,
//                                       changesApplied[] }
//   * pmp.revert           → misma respuesta que pmp.remediate; deshace
//                            el fix a partir del `state` que devolvió
//                            pmp.read_check_state ANTES de aplicarlo
//                            (ver el bloque «pmp.revert» al final).
//
// Design choices documented inline. Two patterns dominate this file
// and are worth pulling out up here:
//
// 1. SSH config edits use the DROP-IN approach.
//    Escribimos las directivas en /etc/ssh/sshd_config.d/00-tracenium-
//    hardening.conf y nunca tocamos el /etc/ssh/sshd_config del
//    operador. En las distros modernas (Debian 11+, Ubuntu 20.04+,
//    RHEL 9+) el principal lleva `Include /etc/ssh/sshd_config.d/*.conf`
//    arriba del todo.
//
//    ⚠️ El nombre empieza por 00- A PROPÓSITO. sshd_config(5): «for
//    each keyword, the first obtained value will be used», y el glob
//    del Include se procesa «in lexical order». Gana el PRIMER fichero,
//    no el último. Hasta sep-2026 el drop-in se llamaba 99-…, que es
//    justo el que PIERDE: la imagen cloud de Ubuntu trae 50-cloud-init.conf
//    con `PasswordAuthentication yes`, RHEL 9 trae 01-permitrootlogin.conf
//    (Anaconda) y 50-redhat.conf incluye los KexAlgorithms de
//    crypto-policies. El fix se validaba, se recargaba… y no cambiaba
//    nada: el agente lo veía como failed/post_state_mismatch sin saber
//    por qué. Ver «Drop-in: nombre, migración y precedencia» abajo.
//
//    Ni siquiera 00- garantiza ganar (un 00-aaa.conf, o una directiva
//    en sshd_config ANTES del Include). Por eso, tras el fix, se relee
//    el efectivo con `sshd -T` y, si no quedó como se pidió, se devuelve
//    exitCode 1 diciendo QUÉ fichero y línea lo fija antes que nosotros.
//
// 2. Every remediation that mutates a config file follows this
//    safety pattern:
//      a. Read existing managed file (or empty if first time).
//      b. Apply directive change in-memory.
//      c. If new content == old content → return success early
//         with empty changesApplied (no-op idempotent).
//      d. Backup current file to <file>.tracenium.<ts>.bak.
//      e. Write new content to <file>.pending (mode 0644).
//      f. Validate via `sshd -t` (which loads main + ALL drop-ins).
//      g. If valid: atomic rename pending → managed file, then
//         `systemctl reload sshd`.
//      h. If invalid: unlink pending, restore from backup if needed,
//         return failure with sshd -t stderr as the reason.
//    Steps (d)..(h) viven en `commitSshdDropins`: el revert (quitar
//    nuestra directiva, o borrar el drop-in entero) y la migración del
//    99- viejo tienen que pasar por la MISMA validación que el fix, no
//    por una copia que diverja.
import { execFile } from "child_process";
import fs from "fs";
import path from "path";
import { promisify } from "util";
import { detectFamily } from "./distro";
import { applyGeneric, readGenericState } from "./generic-config";
import {
  LEGACY_SSHD_DROPIN_FILE,
  SAFE_SSH_KEX_ALGORITHMS,
  SSHD_DROPIN_DIR,
  SSHD_DROPIN_FILE,
  SSHD_MAIN_CONFIG,
  explainSshdOverride,
  planSshDropinChanges,
  planSshRevert,
  readEffectiveSshd,
  sshdEarlierDefinitions,
  type DropinChange,
  type SshdPrecedence,
} from "./sshd-dropin";
import { logger } from "./logger";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";

const execFileAsync = promisify(execFile);

// Per-handler timeout. sshd validation + reload is fast (<1s);
// firewall enable can take 2-3s on a busy host. 10s is a generous
// cap that still bounds runaway processes.
const HANDLER_TIMEOUT_MS = 10_000;

// Lo puro del drop-in vive en sshd-dropin.ts (lo comparte la forma `sshd`
// de la remediación genérica); se reexporta para quien lo importaba de aquí.
export { explainSshdOverride, planSshDropinChanges, planSshRevert, sshdEarlierDefinitions };
export type { DropinChange, SshdDefinition, SshdPrecedence, SshRevertPlan } from "./sshd-dropin";

// ── Generic helpers ───────────────────────────────────────────────

async function runCmd(
  bin: string,
  args: string[],
  timeoutMs = HANDLER_TIMEOUT_MS
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  try {
    const { stdout, stderr } = await execFileAsync(bin, args, {
      timeout: timeoutMs,
      maxBuffer: 1 * 1024 * 1024,
      // ⚠️ Igual que en security-posture y en patch-management: lo que sale de
      // aquí se decide con expresiones en inglés (`Status: active` de ufw,
      // `running` de firewall-cmd) y esas herramientas traducen su salida. Un
      // equipo en español reportaría el cortafuegos deshabilitado estándolo.
      // Visto en campo el 28-sep-2026 con el escaneo de apt en T118.
      env: { ...process.env, LANG: "C", LC_ALL: "C" },
    });
    return { stdout: stdout || "", stderr: stderr || "", code: 0 };
  } catch (err: any) {
    return {
      stdout: err?.stdout || "",
      stderr: err?.stderr || "",
      code: typeof err?.code === "number" ? err.code : null,
    };
  }
}

// Read a file, returning empty string on ENOENT. Other errors throw
// — those represent permissions issues we want to surface, not
// silently swallow.
function readFileSafe(file: string): string {
  try {
    return fs.readFileSync(file, "utf8");
  } catch (err: any) {
    if (err?.code === "ENOENT") return "";
    throw err;
  }
}

function backupTimestamp(): string {
  // YYYYMMDD-HHMMSS in UTC. Ascii-only, sortable, file-system safe.
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return [
    d.getUTCFullYear(),
    pad(d.getUTCMonth() + 1),
    pad(d.getUTCDate()),
    "-",
    pad(d.getUTCHours()),
    pad(d.getUTCMinutes()),
    pad(d.getUTCSeconds()),
  ].join("");
}

// Truncate stderr/stdout for the wire response. We don't want to
// dump multi-MB sshd debug output across IPC + gRPC.
function excerpt(s: string, max = 1024): string {
  if (!s) return "";
  return s.length <= max ? s : s.slice(0, max) + "…[truncated]";
}

// Run `sshd -T` once and cache the parsed map within a single
// handler call (avoids re-running for every read_check). The cache
// is per-call (no module-level state) so a remediation that
// reloads sshd never sees stale values.
async function loadSshdEffective(): Promise<{
  ok: boolean;
  rendered: string;
  stderr: string;
}> {
  const r = await runCmd("/usr/sbin/sshd", ["-T"]);
  return {
    ok: r.code === 0,
    rendered: r.stdout,
    stderr: r.stderr,
  };
}

// cuando se queda sin directivas.

function readOurDropins(): { primary: string; legacy: string } {
  return { primary: readFileSafe(SSHD_DROPIN_FILE), legacy: readFileSafe(LEGACY_SSHD_DROPIN_FILE) };
}

// Apply a single directive change to our drop-ins. Returns the
// changes committed ([] = no-op idempotente). Caller is responsible
// for reloading.
async function editSshdDropin(directive: string, value: string): Promise<DropinChange[]> {
  // Make sure the directory exists. On modern distros it does, but
  // an extremely stripped image (Alpine, scratch + manual openssh)
  // might not have created it.
  await fs.promises.mkdir(SSHD_DROPIN_DIR, { recursive: true, mode: 0o755 }).catch(() => {});

  const changes = planSshDropinChanges(readOurDropins(), directive, value);
  if (changes.length) await commitSshdDropins(changes);
  return changes;
}

// Pasos (d)..(h) para todos los ficheros a la vez: backup de cada uno,
// dejar en su sitio el contenido nuevo (o quitar el fichero si
// `newContent` es null), UN `sshd -t` sobre el conjunto, y restaurarlos
// TODOS si sshd lo rechaza. Todo o nada: el 00- escrito con el 99-
// a medio quitar es una pila que nadie validó. Lanza con `stderrExcerpt`
// si la validación falla.
async function commitSshdDropins(changes: DropinChange[]): Promise<void> {
  // Backup first (only if the original file existed — first-time
  // create has nothing to back up).
  const backups = new Map<string, string>();
  for (const c of changes) {
    if (c.oldContent.length > 0 && fs.existsSync(c.file)) {
      const backupPath = `${c.file}.tracenium.${backupTimestamp()}.bak`;
      fs.copyFileSync(c.file, backupPath);
      fs.chmodSync(backupPath, 0o600);
      backups.set(c.file, backupPath);
    }
  }

  // Roll back: restore from backup OR delete the file we created.
  const rollback = () => {
    for (const c of changes) {
      const backupPath = backups.get(c.file);
      try {
        if (backupPath) fs.copyFileSync(backupPath, c.file);
        else fs.unlinkSync(c.file);
      } catch {}
    }
  };

  try {
    for (const c of changes) {
      if (c.newContent === null) {
        // Revert (o migración) que deja el fichero sin directivas: se
        // borra en vez de dejar un fichero vacío con nuestro nombre. Se
        // valida igual — quitar un fichero también puede dejar la pila
        // inválida (p. ej. un Match de otro drop-in que dependía del orden).
        try { fs.unlinkSync(c.file); } catch (err: any) { if (err?.code !== "ENOENT") throw err; }
        continue;
      }
      // Write to .pending, then atomic rename. `.pending` no casa con el
      // glob `*.conf` del Include: sshd nunca lo lee a medio escribir.
      const pending = `${c.file}.pending`;
      // 0600: CIS lo pide a cada fichero de sshd_config.d, el nuestro incluido.
      fs.writeFileSync(pending, c.newContent, { encoding: "utf8", mode: 0o600 });
      fs.chmodSync(pending, 0o600);
      fs.renameSync(pending, c.file);
    }
  } catch (err) {
    rollback();
    throw err;
  }

  // Validate by running `sshd -t` against the would-be combined
  // config. We can't pass a single drop-in to `-f`; what we do
  // instead is rename the pending into place, run `sshd -t` (which
  // parses the entire stack), and revert if validation fails. This
  // is the only way to validate a drop-in change against the drop-in
  // loader's own logic.
  //
  // The window between rename-in and validate-out is small (< 100ms
  // typically) and during this window any new sshd CHILD processes
  // (incoming ssh sessions) would see the new config. Existing
  // sessions are unaffected. The risk is bounded: the worst case is
  // a 100ms window where new connections briefly see the proposed
  // (and possibly broken) config — but a broken config means
  // CHILD processes refuse to start, not that the running sshd
  // crashes. So during a bad validation window, new ssh attempts
  // get "connection closed" errors and recover when we revert.
  //
  // An alternative would be to assemble the full effective config
  // ourselves and pipe it via `sshd -T -f -`, but that loses
  // include resolution accuracy and reintroduces every parser-
  // incompatibility we'd otherwise dodge.
  //
  // We accept the tradeoff. Most remediations land within seconds
  // and run far from peak ssh-attempt windows.
  const validate = await runCmd("/usr/sbin/sshd", ["-t"]);
  if (validate.code !== 0) {
    rollback();
    const err: any = new Error(`sshd -t rejected the new config: ${validate.stderr.trim()}`);
    err.stderrExcerpt = excerpt(validate.stderr);
    throw err;
  }
}

// Lee de disco lo que necesita sshdEarlierDefinitions. Nunca lanza: es
// para el mensaje de error, no puede tapar el error que explica.
function readSshdPrecedence(directive: string): SshdPrecedence | null {
  try {
    let names: string[] = [];
    try { names = fs.readdirSync(SSHD_DROPIN_DIR).map(String); } catch {}
    const dropins = names.map((name) => {
      let content = "";
      try { content = readFileSafe(path.join(SSHD_DROPIN_DIR, name)); } catch {}
      return { name, content };
    });
    return sshdEarlierDefinitions(readFileSafe(SSHD_MAIN_CONFIG), dropins, directive);
  } catch {
    return null;
  }
}

async function reloadSshd(): Promise<{ ok: boolean; stderr: string }> {
  // `systemctl reload sshd` is graceful — existing sessions
  // unaffected, new connections pick up the new config. Both
  // `ssh.service` (Debian) and `sshd.service` (RHEL) are
  // SIGHUP-driven and reload cleanly.
  //
  // We try the unit name conventional to each family. Failure
  // surfaces as a non-zero exit — the caller decides whether
  // that's worth a roll-back.
  const distro = detectFamily();
  const unit = distro.family === "rhel" ? "sshd.service" : "ssh.service";
  const r = await runCmd("/usr/bin/systemctl", ["reload", unit]);
  if (r.code === 0) return { ok: true, stderr: "" };
  // Fall back to the OTHER unit name in case the distro labelled it
  // unconventionally (e.g. someone running RHEL with an Ubuntu-
  // style override).
  const altUnit = unit === "ssh.service" ? "sshd.service" : "ssh.service";
  const r2 = await runCmd("/usr/bin/systemctl", ["reload", altUnit]);
  if (r2.code === 0) return { ok: true, stderr: "" };
  return { ok: false, stderr: r.stderr || r2.stderr };
}

// ── Per-checkId READ handlers ─────────────────────────────────────

async function readSshDirective(
  directive: string,
  desiredValue: string,
  caseInsensitive = false
): Promise<{ state: any; isCompliant: boolean }> {
  const sshd = await loadSshdEffective();
  const current = readEffectiveSshd(directive, sshd.rendered);
  const norm = (v: string | undefined) => caseInsensitive ? String(v || "").toLowerCase() : String(v || "");
  return {
    state: { directive, current, expected: desiredValue, sshdEffective: sshd.ok },
    isCompliant: norm(current) === norm(desiredValue),
  };
}

// La lista `current` del estado de KEX. Compartida con el revert, que
// compara contra ella: si cada uno la parsease a su manera, un revert
// correcto podría dar post_state_mismatch.
function kexListFromSshdT(rendered: string): string[] {
  const current = readEffectiveSshd("kexalgorithms", rendered) || "";
  return current.split(",").map(s => s.trim()).filter(Boolean);
}

// Sin flag `g`: con `test()` repetido, lastIndex haría fallar entradas alternas.
const WEAK_KEX_RE = /(group1-sha1|group14-sha1|group-exchange-sha1|.+-sha1$)/i;

async function readSshKex(): Promise<{ state: any; isCompliant: boolean }> {
  const sshd = await loadSshdEffective();
  const list = kexListFromSshdT(sshd.rendered);
  // Compliance: NO weak entries present. We don't require an exact
  // match to SAFE_SSH_KEX_ALGORITHMS (operators may have sane
  // additions of their own).
  const offenders = list.filter(a => WEAK_KEX_RE.test(a));
  return {
    state: { current: list, offenders, expectedNoMatch: WEAK_KEX_RE.toString() },
    isCompliant: offenders.length === 0,
  };
}

async function readFirewallEnabled(): Promise<{ state: any; isCompliant: boolean }> {
  const distro = detectFamily();
  if (distro.family === "debian") {
    const r = await runCmd("/usr/sbin/ufw", ["status"]);
    const active = /^Status:\s*active/im.test(r.stdout);
    return { state: { impl: "ufw", active }, isCompliant: active };
  }
  if (distro.family === "rhel") {
    const r = await runCmd("/usr/bin/firewall-cmd", ["--state"]);
    const running = /^running/i.test(r.stdout.trim());
    return { state: { impl: "firewalld", running }, isCompliant: running };
  }
  return {
    state: { impl: "unknown", note: `unsupported family: ${distro.family}` },
    isCompliant: false,
  };
}

// ── Per-checkId REMEDIATE handlers ────────────────────────────────

type RemediateOutcome = {
  exitCode: number;
  stderrExcerpt?: string;
  durationMs: number;
  requiresReboot?: boolean;
  changesApplied?: string[];
};

// ¿Quedó el valor EFECTIVO (el de `sshd -T`) como pide el check? Mismo
// criterio que el read handler: lo que el agente releerá después.
type EffectiveCheck = (sshdT: string) => { ok: boolean; actual: string };

function directiveIs(directive: string, value: string): EffectiveCheck {
  return (rendered) => {
    const actual = readEffectiveSshd(directive, rendered);
    return { ok: String(actual || "").toLowerCase() === value.toLowerCase(), actual: actual ?? "(unset)" };
  };
}

const kexHasNoWeak: EffectiveCheck = (rendered) => {
  const list = kexListFromSshdT(rendered);
  return { ok: list.length > 0 && !list.some(a => WEAK_KEX_RE.test(a)), actual: list.join(",") || "(unset)" };
};

async function remediateSshDirective(
  directive: string,
  value: string,
  check: EffectiveCheck = directiveIs(directive, value)
): Promise<RemediateOutcome> {
  const t0 = Date.now();
  const done = (exitCode: number, changesApplied: string[], stderr?: string): RemediateOutcome => ({
    exitCode,
    stderrExcerpt: stderr ? excerpt(stderr) : undefined,
    durationMs: Date.now() - t0,
    requiresReboot: false,
    changesApplied,
  });

  let committed: DropinChange[];
  try {
    committed = await editSshdDropin(directive, value);
  } catch (err: any) {
    return done(1, [], err?.stderrExcerpt || err?.message || String(err));
  }

  const changes: string[] = [];
  if (committed.length) {
    changes.push(`${directive}=${value}`);
    if (committed.some(c => c.file === LEGACY_SSHD_DROPIN_FILE)) changes.push("moved-from-99-dropin");

    const reload = await reloadSshd();
    if (!reload.ok) {
      // The new directive is on disk but sshd reload failed. The
      // catch path here is "best effort" — if sshd is currently up
      // it'll pick the change up at next start; the new config is
      // already validated by `sshd -t` so it's safe.
      logger.warn("sshd_reload_failed_post_remediate", { directive, stderr: reload.stderr });
      return done(1, [...changes, "config-staged-not-reloaded"], reload.stderr || "sshd reload failed");
    }
    changes.push("sshd-reloaded");
  }

  // Comprobar SIEMPRE, también en el no-op: que nuestro fichero ya lleve
  // la directiva no significa que gane (antes del 00- era justo el caso
  // del 99-). `sshd -t` sólo dice que la configuración es VÁLIDA, no que
  // sea la nuestra la que manda.
  const post = await loadSshdEffective();
  if (!post.ok) return done(1, changes, `could not verify ${directive}: sshd -T failed: ${post.stderr}`);
  const m = check(post.rendered);
  if (m.ok) return done(0, changes);

  // Otro fichero la fija antes que nosotros. Nuestra directiva se DEJA
  // (validada, inofensiva, y el revert la quita): borrarla no devuelve
  // nada al operador, y si retira el conflicto, entra en vigor el fix
  // que pidió. Lo que no se hace es tocar el fichero ajeno: no es
  // nuestro, y 50-cloud-init.conf lo regenera cloud-init de todos modos.
  const precedence = readSshdPrecedence(directive);
  const why = precedence
    ? explainSshdOverride(directive, m.actual, precedence)
    : `Effective ${directive} is ${m.actual} although ${SSHD_DROPIN_FILE} sets it (could not read the sshd configuration to find out why).`;
  logger.warn("sshd_directive_overridden", { directive, actual: m.actual, earlier: precedence?.earlier, dropinIncluded: precedence?.dropinIncluded });
  return done(1, [...changes, "effective-value-overridden"], why);
}

async function remediateSshKex(): Promise<RemediateOutcome> {
  return remediateSshDirective("KexAlgorithms", SAFE_SSH_KEX_ALGORITHMS, kexHasNoWeak);
}

// ── ufw: SSH antes que el candado ──────────────────────────────────
//
// `ufw --force enable` con la política por defecto (deny incoming) y sin
// reglas corta TODA conexión entrante nueva, SSH incluido. La versión
// anterior de este handler asumía que ufw «traía permitido OpenSSH de
// fábrica»; no es así en Ubuntu: ufw se instala sin reglas y sólo tiene
// la de OpenSSH si un administrador la añadió. Las sesiones vivas
// sobreviven (y el gRPC del agente es saliente), así que el equipo
// seguiría alcanzable desde el shell remoto de Tracenium, pero a un
// cliente le habríamos cortado el SSH en nombre del cumplimiento.
//
// Regla: si hay un sshd activo, se permite su puerto (el EFECTIVO, de
// `sshd -T`, no el 22 por costumbre) ANTES de activar. `ufw allow` es
// idempotente («Skipping adding existing rule»). Si no hay sshd, no se
// abre nada: abrir 22 «por si acaso» sería inventarse superficie.

/** Puertos que sshd escucha según `sshd -T` (líneas `port N`); [22] si no dice ninguno. */
export function sshPortsFromSshdT(rendered: string): number[] {
  const ports: number[] = [];
  for (const line of String(rendered || "").split("\n")) {
    const m = /^\s*port\s+(\d{1,5})\s*$/i.exec(line);
    if (!m) continue;
    const n = Number(m[1]);
    if (n >= 1 && n <= 65535 && !ports.includes(n)) ports.push(n);
  }
  return ports.length ? ports : [22];
}

export type UfwStep = { bin: string; args: string[]; change: string | null };

/**
 * La secuencia de comandos para activar ufw sin cortar SSH. Pura, para
 * poder fijarla en tests: primero las reglas de SSH (si sshd está
 * activo), y el enable SIEMPRE el último.
 */
export function planUfwEnable(input: { sshdActive: boolean; sshdRendered: string }): UfwStep[] {
  const steps: UfwStep[] = [];
  if (input.sshdActive) {
    for (const port of sshPortsFromSshdT(input.sshdRendered)) {
      steps.push({
        bin: "/usr/sbin/ufw",
        args: ["allow", `${port}/tcp`, "comment", "Tracenium: keep SSH reachable"],
        change: `ufw-allow-${port}/tcp`,
      });
    }
  }
  steps.push({ bin: "/usr/sbin/ufw", args: ["--force", "enable"], change: "ufw-enabled" });
  return steps;
}

async function isSshdActive(): Promise<boolean> {
  // Debian/Ubuntu llaman a la unidad `ssh`; el resto, `sshd`.
  for (const unit of ["ssh", "sshd"]) {
    const r = await runCmd("/usr/bin/systemctl", ["is-active", "--quiet", unit]);
    if (r.code === 0) return true;
  }
  return false;
}

async function remediateFirewallEnable(): Promise<RemediateOutcome> {
  const t0 = Date.now();
  const distro = detectFamily();

  if (distro.family === "debian") {
    const sshdActive = await isSshdActive();
    const sshd = sshdActive ? await loadSshdEffective() : { ok: false, rendered: "", stderr: "" };
    const steps = planUfwEnable({ sshdActive, sshdRendered: sshd.ok ? sshd.rendered : "" });

    const changes: string[] = [];
    for (const step of steps) {
      const r = await runCmd(step.bin, step.args);
      if (r.code !== 0) {
        // Si falla la regla de SSH NO se activa el firewall: activar sin
        // la regla es exactamente lo que este bloque existe para evitar.
        return {
          exitCode: 1,
          stderrExcerpt: excerpt(`${step.args.join(" ")}: ${r.stderr || r.stdout}`),
          durationMs: Date.now() - t0,
          requiresReboot: false,
          changesApplied: changes,
        };
      }
      if (step.change) changes.push(step.change);
    }
    return {
      exitCode: 0,
      stderrExcerpt: undefined,
      durationMs: Date.now() - t0,
      requiresReboot: false,
      changesApplied: changes,
    };
  }

  if (distro.family === "rhel") {
    // systemctl enable --now: enables at next boot AND starts now.
    // firewalld with default zone "public" allows ssh, dhcpv6-client.
    // Any operator who's customized the zone is preserved (firewalld
    // persists state in /etc/firewalld/, separate from the unit
    // file we're enabling).
    const r = await runCmd("/usr/bin/systemctl", ["enable", "--now", "firewalld.service"]);
    return {
      exitCode: r.code === 0 ? 0 : 1,
      stderrExcerpt: r.code === 0 ? undefined : excerpt(r.stderr),
      durationMs: Date.now() - t0,
      requiresReboot: false,
      changesApplied: r.code === 0 ? ["firewalld-enabled-and-started"] : [],
    };
  }

  // suse/unknown family — bounce.
  return {
    exitCode: 1,
    stderrExcerpt: `firewall remediation not implemented for family=${distro.family}`,
    durationMs: Date.now() - t0,
    requiresReboot: false,
    changesApplied: [],
  };
}

// ── Dispatch tables ───────────────────────────────────────────────

// `params` es `req.params.params`: sólo lo usa el genérico (las escrituras
// que pidió el backend); los dedicados lo ignoran.
type ReadHandler = (params: unknown) => Promise<{ state: any; isCompliant: boolean }>;
type RemediateHandler = (params: unknown) => Promise<RemediateOutcome>;

/** Un payload inválido para el genérico es bad_request, no un fallo del equipo. */
class BadGenericParams extends Error {}

async function readGeneric(params: unknown): Promise<{ state: any; isCompliant: boolean }> {
  const r = await readGenericState(params);
  if (!r.ok) throw new BadGenericParams(r.message);
  return r.value;
}

async function remediateGeneric(params: unknown): Promise<RemediateOutcome> {
  const r = await applyGeneric(params);
  if (!r.ok) throw new BadGenericParams(r.message);
  return r.value;
}

const READ_HANDLERS: Record<string, ReadHandler> = {
  "linux.ssh.root_login_disabled": () => readSshDirective("PermitRootLogin", "no", true),
  "linux.ssh.password_auth_disabled": () => readSshDirective("PasswordAuthentication", "no", true),
  "linux.cryptography.weak_ssh_kex_disabled": () => readSshKex(),
  "linux.firewall.enabled": () => readFirewallEnabled(),
  // Genérico (desired-state-linux.ts en el backend): sysctl, módulos,
  // reglas de auditd y «clave = valor». Ver generic-config.ts.
  "linux.config.set_value": (params) => readGeneric(params),
};

const REMEDIATE_HANDLERS: Record<string, RemediateHandler> = {
  "linux.ssh.root_login_disabled": () => remediateSshDirective("PermitRootLogin", "no"),
  "linux.ssh.password_auth_disabled": () => remediateSshDirective("PasswordAuthentication", "no"),
  "linux.cryptography.weak_ssh_kex_disabled": () => remediateSshKex(),
  "linux.firewall.enabled": () => remediateFirewallEnable(),
  "linux.config.set_value": (params) => remediateGeneric(params),
};

// ── pmp.read_check_state ─────────────────────────────────────────

export async function handlePmpReadCheckState(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const checkId = String(req.params?.checkId || "").trim();
  if (!checkId) return fail(req.id, "bad_request", "checkId required");

  const handler = READ_HANDLERS[checkId];
  if (!handler) {
    logger.info("pmp_read_check_state_unsupported", { checkId });
    return fail(req.id, "unsupported_check", `no read handler for checkId ${checkId} on linux`);
  }

  try {
    const result = await handler(req.params?.params);
    return success(req.id, {
      state: result.state,
      isCompliant: result.isCompliant === true,
      supported: true,
    });
  } catch (err: any) {
    if (err instanceof BadGenericParams) return fail(req.id, "bad_request", err.message);
    logger.error("pmp_read_check_state_failed", {
      checkId,
      error: err?.message || String(err),
    });
    return fail(req.id, "read_state_failed", err?.message || String(err));
  }
}

// ── pmp.remediate ────────────────────────────────────────────────

export async function handlePmpRemediate(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const checkId = String(req.params?.checkId || "").trim();
  if (!checkId) return fail(req.id, "bad_request", "checkId required");

  const handler = REMEDIATE_HANDLERS[checkId];
  if (!handler) {
    logger.info("pmp_remediate_unsupported", { checkId });
    return fail(req.id, "unsupported_check", `no remediation handler for checkId ${checkId} on linux`);
  }

  try {
    logger.info("pmp_remediate_start", { checkId });
    const result = await handler(req.params?.params);
    logger.info("pmp_remediate_complete", {
      checkId,
      exitCode: result.exitCode,
      changesApplied: result.changesApplied,
    });
    return success(req.id, outcomeToWire(result));
  } catch (err: any) {
    if (err instanceof BadGenericParams) return fail(req.id, "bad_request", err.message);
    logger.error("pmp_remediate_failed", {
      checkId,
      error: err?.message || String(err),
    });
    return fail(req.id, "remediate_failed", err?.message || String(err));
  }
}

// Una sola forma de respuesta para pmp.remediate y pmp.revert: el agente
// las lee con el mismo código.
function outcomeToWire(result: RemediateOutcome) {
  return {
    exitCode: result.exitCode,
    stderrExcerpt: result.stderrExcerpt ?? null,
    durationMs: result.durationMs,
    requiresReboot: result.requiresReboot === true,
    changesApplied: Array.isArray(result.changesApplied) ? result.changesApplied : [],
  };
}

// ── pmp.revert ───────────────────────────────────────────────────
//
// Deshacer un fix = volver al `state` que leyó pmp.read_check_state
// ANTES de aplicarlo (`params.stateBefore`). Tras la llamada el agente
// relee el estado y exige que cada clave de stateBefore coincida
// (listas como conjuntos); si no, reporta failed/post_state_mismatch.
// Por eso cada revert restaura el valor EFECTIVO y lo comprueba él
// mismo al final: su exitCode tiene que decir lo mismo que dirá el
// agente.
//
// SSH: no se escribe el valor antiguo. Se QUITA nuestra directiva de
// nuestros drop-ins (el 00- y, si aún existe, el 99- de antes de
// sep-2026) y el valor efectivo vuelve a ser el que dicte el resto de la
// configuración — que es lo que había antes del fix, salvo que alguien
// haya tocado sshd_config desde entonces. En ese caso NO se inventa un
// valor: se deja quitada y se devuelve exitCode 1 con el porqué.
// Escribir `PermitRootLogin yes` en nuestro fichero convertiría el
// revert en una configuración que nadie pidió y de la que nadie es
// dueño.
//
// Firewall: sólo se apaga si antes estaba apagado. Las reglas de SSH que
// añade el fix (`ufw allow <puerto>/tcp`) se DEJAN: `ufw allow` es
// idempotente y stateBefore no dice si la regla ya existía, así que
// borrarla podría llevarse una del operador — y el día que vuelva a
// activar ufw se quedaría sin SSH. Con ufw apagado una regla no filtra
// nada: no cambia el estado efectivo ni lo que compara el agente.

// Sin timeoutSeconds, 2 min: el peor caso SSH son ~6 comandos de ≤10 s.
// Con él, se respeta dentro de [5, 600] s.
const DEFAULT_REVERT_TIMEOUT_MS = 120_000;

export type RevertCheck<T> = { ok: true; value: T } | { ok: false; message: string };

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);

const isStringArray = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every(x => typeof x === "string");

// Claves que no son del shape de read_check_state → bad_request. Un
// stateBefore de otro checkId (o de otra plataforma) no debe llegar a
// tocar nada.
function unknownKeys(obj: Record<string, unknown>, allowed: string[]): string | null {
  const extra = Object.keys(obj).filter(k => !allowed.includes(k));
  return extra.length ? `stateBefore has unknown keys: ${extra.join(", ")}` : null;
}

/** Shape de `readSshDirective`: { directive, current, expected, sshdEffective }. */
export function validateSshDirectiveBefore(
  stateBefore: unknown,
  directive: string
): RevertCheck<{ current: string }> {
  if (!isPlainObject(stateBefore)) return { ok: false, message: "stateBefore must be an object" };
  const extra = unknownKeys(stateBefore, ["directive", "current", "expected", "sshdEffective"]);
  if (extra) return { ok: false, message: extra };
  const { directive: d, current, expected, sshdEffective } = stateBefore;
  if (typeof d !== "string" || d.toLowerCase() !== directive.toLowerCase()) {
    return { ok: false, message: `stateBefore.directive must be ${directive}` };
  }
  if (expected !== undefined && typeof expected !== "string") {
    return { ok: false, message: "stateBefore.expected must be a string" };
  }
  if (sshdEffective !== undefined && typeof sshdEffective !== "boolean") {
    return { ok: false, message: "stateBefore.sshdEffective must be a boolean" };
  }
  // Sin `sshd -T` válido antes del fix no hay valor que restaurar ni
  // contra el que comprobar: cualquier cosa que hiciéramos sería a ciegas.
  if (sshdEffective === false) {
    return { ok: false, message: "stateBefore was read while sshd -T was failing; there is no value to restore" };
  }
  if (typeof current !== "string" || !current.trim() || /[\r\n]/.test(current)) {
    return { ok: false, message: "stateBefore.current must be a non-empty single-line string" };
  }
  return { ok: true, value: { current } };
}

/** Shape de `readSshKex`: { current: string[], offenders: string[], expectedNoMatch }. */
export function validateSshKexBefore(stateBefore: unknown): RevertCheck<{ current: string[] }> {
  if (!isPlainObject(stateBefore)) return { ok: false, message: "stateBefore must be an object" };
  const extra = unknownKeys(stateBefore, ["current", "offenders", "expectedNoMatch"]);
  if (extra) return { ok: false, message: extra };
  const { current, offenders, expectedNoMatch } = stateBefore;
  // Lista vacía = `sshd -T` no respondió al leer (sshd siempre compila
  // una lista de KEX). Mismo caso que sshdEffective:false arriba.
  if (!isStringArray(current) || current.length === 0 || current.some(a => !a.trim())) {
    return { ok: false, message: "stateBefore.current must be a non-empty array of algorithm names" };
  }
  if (offenders !== undefined && !isStringArray(offenders)) {
    return { ok: false, message: "stateBefore.offenders must be an array of strings" };
  }
  if (expectedNoMatch !== undefined && typeof expectedNoMatch !== "string") {
    return { ok: false, message: "stateBefore.expectedNoMatch must be a string" };
  }
  return { ok: true, value: { current } };
}

export type FirewallBefore =
  | { impl: "ufw"; active: boolean }
  | { impl: "firewalld"; running: boolean };

/** Shape de `readFirewallEnabled`: { impl:"ufw", active } | { impl:"firewalld", running }. */
export function validateFirewallBefore(stateBefore: unknown): RevertCheck<FirewallBefore> {
  if (!isPlainObject(stateBefore)) return { ok: false, message: "stateBefore must be an object" };
  const impl = stateBefore.impl;
  if (impl === "ufw") {
    const extra = unknownKeys(stateBefore, ["impl", "active"]);
    if (extra) return { ok: false, message: extra };
    if (typeof stateBefore.active !== "boolean") return { ok: false, message: "stateBefore.active must be a boolean" };
    return { ok: true, value: { impl, active: stateBefore.active } };
  }
  if (impl === "firewalld") {
    const extra = unknownKeys(stateBefore, ["impl", "running"]);
    if (extra) return { ok: false, message: extra };
    if (typeof stateBefore.running !== "boolean") return { ok: false, message: "stateBefore.running must be a boolean" };
    return { ok: true, value: { impl, running: stateBefore.running } };
  }
  // impl:"unknown" (familia sin soporte): el fix no pudo aplicarse, así
  // que tampoco hay nada que deshacer.
  return { ok: false, message: `stateBefore.impl must be "ufw" or "firewalld" (got ${JSON.stringify(impl)})` };
}

/**
 * Comandos para devolver el firewall a stateBefore. Pura. [] si ya
 * estaba activo antes del fix (el fix no cambió nada que deshacer).
 * El apagado replica al revés el mecanismo del fix: `ufw disable` frente
 * a `ufw --force enable`; `systemctl disable --now` frente a `enable
 * --now` (el estado anterior sólo dice «running», no si arrancaba con
 * el equipo; lo normal es que ninguna de las dos, y quedarse en `stop`
 * dejaría el firewall volviendo en el siguiente reinicio).
 */
export function planFirewallRevert(before: FirewallBefore, family: string): RevertCheck<UfwStep[]> {
  if (before.impl === "ufw") {
    if (family !== "debian") return { ok: false, message: `stateBefore is from ufw but this host is family=${family}` };
    if (before.active) return { ok: true, value: [] };
    return { ok: true, value: [{ bin: "/usr/sbin/ufw", args: ["disable"], change: "ufw-disabled" }] };
  }
  if (family !== "rhel") return { ok: false, message: `stateBefore is from firewalld but this host is family=${family}` };
  if (before.running) return { ok: true, value: [] };
  return {
    ok: true,
    value: [{ bin: "/usr/bin/systemctl", args: ["disable", "--now", "firewalld.service"], change: "firewalld-disabled-and-stopped" }],
  };
}

// Igual que compara el agente (stateMatchesBefore): multiconjunto.
function sameList(a: string[], b: string[]): boolean {
  return JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
}

async function revertSshDropinDirective(
  directive: string,
  matchesBefore: EffectiveCheck,
  expectedDesc: string
): Promise<RemediateOutcome> {
  const t0 = Date.now();
  const done = (exitCode: number, changesApplied: string[], stderr?: string): RemediateOutcome => ({
    exitCode,
    stderrExcerpt: stderr ? excerpt(stderr) : undefined,
    durationMs: Date.now() - t0,
    requiresReboot: false,
    changesApplied,
  });

  // Ya está como antes: quitar la directiva ahora lo DESHARÍA (p. ej. el
  // fix fue no-op porque un fix anterior ya la había escrito).
  const pre = await loadSshdEffective();
  if (pre.ok && matchesBefore(pre.rendered).ok) return done(0, []);

  // De los DOS ficheros nuestros: el fix pudo escribirla en el 99- (antes
  // de sep-2026) o en el 00-, y basta que quede en uno para que el
  // revert no surta efecto.
  const plan = planSshDropinChanges(readOurDropins(), directive, null);
  if (!plan.length) {
    const actual = pre.ok ? matchesBefore(pre.rendered).actual : "unknown (sshd -T failed)";
    return done(
      1,
      [],
      `${directive} is not set by Tracenium in ${SSHD_DROPIN_FILE} or ${LEGACY_SSHD_DROPIN_FILE}; effective value is ${actual}, ` +
        `expected ${expectedDesc}. It was changed outside Tracenium; not overwriting it.`
    );
  }

  try {
    await commitSshdDropins(plan);
  } catch (err: any) {
    return done(1, [], err?.stderrExcerpt || err?.message || String(err));
  }
  const removed = (file: string) => plan.some(c => c.file === file && c.newContent === null);
  const changes = [`${directive}-unset`];
  if (removed(SSHD_DROPIN_FILE)) changes.push("dropin-removed");
  if (removed(LEGACY_SSHD_DROPIN_FILE)) changes.push("legacy-99-dropin-removed");

  const reload = await reloadSshd();
  if (!reload.ok) {
    logger.warn("sshd_reload_failed_post_revert", { directive, stderr: reload.stderr });
    return done(1, [...changes, "config-staged-not-reloaded"], reload.stderr || "sshd reload failed");
  }
  changes.push("sshd-reloaded");

  // Lo mismo que leerá el agente. Si no cuadra, la base cambió después
  // del fix: se informa y se deja así (ver cabecera del bloque).
  const post = await loadSshdEffective();
  if (!post.ok) return done(1, changes, `sshd -T failed after revert: ${post.stderr}`);
  const m = matchesBefore(post.rendered);
  if (!m.ok) {
    return done(
      1,
      changes,
      `After removing the Tracenium ${directive} directive the effective value is ${m.actual}, ` +
        `expected ${expectedDesc}. The base sshd configuration changed after the fix; not overwriting it.`
    );
  }
  return done(0, changes);
}

function revertSshDirective(directive: string, current: string): Promise<RemediateOutcome> {
  return revertSshDropinDirective(
    directive,
    rendered => {
      const actual = readEffectiveSshd(directive, rendered);
      return { ok: actual === current, actual: actual ?? "(unset)" };
    },
    current
  );
}

function revertSshKex(current: string[]): Promise<RemediateOutcome> {
  return revertSshDropinDirective(
    "KexAlgorithms",
    rendered => {
      const list = kexListFromSshdT(rendered);
      return { ok: sameList(list, current), actual: list.join(",") || "(unset)" };
    },
    current.join(",")
  );
}

async function revertFirewall(before: FirewallBefore, steps: UfwStep[]): Promise<RemediateOutcome> {
  const t0 = Date.now();
  const done = (exitCode: number, changesApplied: string[], stderr?: string): RemediateOutcome => ({
    exitCode,
    stderrExcerpt: stderr ? excerpt(stderr) : undefined,
    durationMs: Date.now() - t0,
    requiresReboot: false,
    changesApplied,
  });
  const wanted = before.impl === "ufw" ? before.active : before.running;
  const isBack = (s: any) =>
    s?.impl === before.impl && (before.impl === "ufw" ? s?.active : s?.running) === wanted;

  // Estaba activo antes: el fix no cambió nada que deshacer.
  if (!steps.length) return done(0, []);
  // Ya apagado (alguien lo apagó a mano): no se repite el comando.
  if (isBack((await readFirewallEnabled()).state)) return done(0, []);

  const changes: string[] = [];
  for (const step of steps) {
    const r = await runCmd(step.bin, step.args);
    if (r.code !== 0) return done(1, changes, `${step.args.join(" ")}: ${r.stderr || r.stdout}`);
    if (step.change) changes.push(step.change);
  }
  const after = await readFirewallEnabled();
  if (!isBack(after.state)) {
    return done(1, changes, `firewall state after revert is ${JSON.stringify(after.state)}, expected ${JSON.stringify(before)}`);
  }
  return done(0, changes);
}

type RevertPlanner = (stateBefore: unknown) => RevertCheck<() => Promise<RemediateOutcome>>;

function sshDirectivePlanner(directive: string): RevertPlanner {
  return (stateBefore) => {
    const v = validateSshDirectiveBefore(stateBefore, directive);
    return v.ok ? { ok: true, value: () => revertSshDirective(directive, v.value.current) } : v;
  };
}

// Validar y planificar ANTES de tocar nada: un bad_request no puede
// dejar el equipo a medio revertir.
const REVERT_PLANNERS: Record<string, RevertPlanner> = {
  "linux.ssh.root_login_disabled": sshDirectivePlanner("PermitRootLogin"),
  "linux.ssh.password_auth_disabled": sshDirectivePlanner("PasswordAuthentication"),
  "linux.cryptography.weak_ssh_kex_disabled": (stateBefore) => {
    const v = validateSshKexBefore(stateBefore);
    return v.ok ? { ok: true, value: () => revertSshKex(v.value.current) } : v;
  },
  "linux.firewall.enabled": (stateBefore) => {
    const v = validateFirewallBefore(stateBefore);
    if (!v.ok) return v;
    const p = planFirewallRevert(v.value, detectFamily().family);
    return p.ok ? { ok: true, value: () => revertFirewall(v.value, p.value) } : p;
  },
};

function revertTimeoutMs(raw: unknown): number {
  const n = Number(raw);
  if (raw === undefined || raw === null || !Number.isFinite(n) || n <= 0) return DEFAULT_REVERT_TIMEOUT_MS;
  return Math.min(Math.max(n, 5), 600) * 1000;
}

export async function handlePmpRevert(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const checkId = String(req.params?.checkId || "").trim();
  if (!checkId) return fail(req.id, "bad_request", "checkId required");

  const planner = REVERT_PLANNERS[checkId];
  if (!planner) {
    logger.info("pmp_revert_unsupported", { checkId });
    return fail(req.id, "unsupported_check", `no revert handler for checkId ${checkId} on linux`);
  }

  const stateBefore = req.params?.params?.stateBefore;
  if (!isPlainObject(stateBefore)) {
    return fail(req.id, "bad_request", "params.stateBefore (object) required");
  }

  let plan: RevertCheck<() => Promise<RemediateOutcome>>;
  try {
    plan = planner(stateBefore);
  } catch (err: any) {
    return fail(req.id, "revert_failed", err?.message || String(err));
  }
  if (!plan.ok) {
    logger.info("pmp_revert_bad_state_before", { checkId, reason: plan.message });
    return fail(req.id, "bad_request", plan.message);
  }

  // El timeout no cancela lo que esté corriendo (cada comando lleva su
  // propio tope de HANDLER_TIMEOUT_MS), sólo deja de esperarlo: el
  // agente lo reporta timed_out y la relectura dirá dónde quedó.
  const timeoutMs = revertTimeoutMs(req.params?.timeoutSeconds);
  let timer: NodeJS.Timeout | undefined;
  const timedOut = new Promise<"timeout">(resolve => {
    timer = setTimeout(() => resolve("timeout"), timeoutMs);
  });

  try {
    logger.info("pmp_revert_start", { checkId });
    const work = plan.value();
    // Si pierde la carrera y luego falla, que no sea un rechazo sin
    // manejar: tumbaría el daemon entero.
    work.catch(() => {});
    const result = await Promise.race([work, timedOut]);
    if (result === "timeout") {
      logger.warn("pmp_revert_timeout", { checkId, timeoutMs });
      return fail(req.id, "revert_timeout", `revert of ${checkId} did not finish within ${Math.round(timeoutMs / 1000)}s`);
    }
    logger.info("pmp_revert_complete", {
      checkId,
      exitCode: result.exitCode,
      changesApplied: result.changesApplied,
    });
    return success(req.id, outcomeToWire(result));
  } catch (err: any) {
    logger.error("pmp_revert_failed", { checkId, error: err?.message || String(err) });
    return fail(req.id, "revert_failed", err?.message || String(err));
  } finally {
    if (timer) clearTimeout(timer);
  }
}
