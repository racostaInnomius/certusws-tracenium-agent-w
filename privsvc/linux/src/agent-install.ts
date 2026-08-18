// privsvc/linux/src/agent-install.ts
//
// Handler for `agent.install` — installs an agent self-upgrade package
// (.deb or .rpm) as root.
//
// Why this exists at all (vs the agent invoking dpkg/rpm directly): on
// Linux the agent daemon runs as the unprivileged `tracenium` user
// (see packaging/linux/systemd/tracenium-agent.service:User=tracenium).
// dpkg / apt-get / dnf all require root to install system packages.
// The previous Linux update path in src/update/updater-runner.ts called
// `spawn("/usr/bin/dpkg", ...)` from the agent process itself and the
// kernel immediately rejected it with EPERM — but the spawn() returned
// successfully (the child started, then exited 1), the agent reported
// `{ started: true }` upstream, and the server-side update job ACK'd
// as success. The Ubuntu host stayed on the old version forever while
// the dashboard insisted the update had "started".
//
// privsvc runs as User=root, so this handler can do the install
// directly. Same pattern as `sdp.install` / `patch.install` — both
// already in this module — but specialized for the agent self-upgrade
// flow.
//
// Special concerns for AGENT self-upgrade (vs SDP/patch):
//
//   1. dpkg's postinstall script (packaging/linux/scripts/postinstall.sh)
//      restarts both tracenium-privsvc AND tracenium-agent units on the
//      upgrade path. If dpkg runs as a CHILD of the privsvc process,
//      systemd's KillMode=control-group default would kill dpkg along
//      with privsvc when the unit gets restarted, leaving the install
//      half-complete (the dpkg postinst trigger would never finish).
//
//      Fix: launch dpkg via `systemd-run --scope`, which creates a
//      transient systemd scope that lives OUTSIDE privsvc's cgroup. The
//      scope persists across the privsvc restart and finishes on its
//      own. systemd-run is part of the systemd suite — available on
//      every distro we ship to (Ubuntu, Debian, RHEL/Rocky/Alma, SUSE).
//
//   2. The handler returns "started" immediately and does NOT wait for
//      the install to finish. The agent that called us is about to be
//      restarted by systemd as part of the upgrade — there's nobody to
//      receive a completion response. The orchestrator on the server
//      side confirms success on the agent's next HELLO (new
//      `agentVersion` field matches the requested target version).
//
//   3. Path validation: only accept paths inside /var/lib/tracenium/
//      updates/, which is owned by `tracenium:tracenium` 0750. The
//      agent writes its download there. Refusing anything else
//      prevents a compromised agent from talking us into running
//      /etc/init.d/whatever as root.

import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import { detectFamily } from "./distro";
import { logger } from "./logger";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { DATA_DIR } from "./paths";

// Agent download staging dir, mirrors src/update/update-service.ts where
// the agent writes the .deb/.rpm. We validate that any path the agent
// asks us to install lives under here.
const UPDATES_DIR = path.join(DATA_DIR, "updates");

// Margen para que llegue 'spawn' o 'error'. Ambos disparan en el mismo tick
// de I/O, asi que 2s es holgado; existe solo para no dejar el broker colgado
// si el runtime no emitiera ninguno.
const SPAWN_CONFIRM_TIMEOUT_MS = 2000;

export async function handleAgentInstall(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const params = req.params || {};
  const packagePath = String(params.path || "");
  const format = String(params.format || "");
  const targetVersion = String(params.version || "");

  // ── Validate path ──────────────────────────────────────────────
  // Defense in depth: the kernel already gates this IPC behind the
  // socket's root:tracenium 0660 mode (only the agent user, who is
  // tracenium, can connect), so we trust the CALLER's identity but
  // not necessarily the CONTENT of the call. A compromised agent (or
  // a future bug in update-task) shouldn't be able to make us install
  // an arbitrary package — refuse anything not in our updates dir.
  const absPath = path.resolve(packagePath);
  const absUpdatesDir = path.resolve(UPDATES_DIR);
  if (!absPath.startsWith(absUpdatesDir + path.sep)) {
    return fail(req.id, "bad_request", `path outside updates dir: ${absPath}`);
  }
  if (!fs.existsSync(absPath)) {
    return fail(req.id, "bad_request", `package not found: ${absPath}`);
  }

  // ── Format ↔ distro family ─────────────────────────────────────
  const distro = detectFamily();
  if (format === "deb" && distro.family !== "debian") {
    return fail(req.id, "format_unsupported", `deb on non-debian (${distro.family})`);
  }
  if (format === "rpm" && distro.family !== "rhel" && distro.family !== "suse") {
    return fail(req.id, "format_unsupported", `rpm on non-rpm family (${distro.family})`);
  }
  if (format !== "deb" && format !== "rpm") {
    return fail(req.id, "format_unsupported", `unknown format: ${format}`);
  }

  // ── Build the install command ───────────────────────────────────
  // For .deb we use `dpkg -i` directly rather than `apt-get install
  // ./<file>.deb` because:
  //   * dpkg is deterministic — it installs the bytes we downloaded
  //     and sha-verified. apt could in theory swap in a "better" file
  //     from cache.
  //   * The agent's .deb has no external deps (we bundle our own node
  //     and better-sqlite3), so apt's dep-resolution adds nothing.
  //   * --force-confold + --force-confdef preserves the operator's
  //     /etc/tracenium/agent.env across upgrades. nfpm marked it as
  //     `type: config|noreplace` so dpkg already knows, but the flags
  //     are belt-and-braces.
  //
  // For .rpm we use `rpm -U` similarly (upgrade, not reinstall).
  // --nodeps because we bundle everything. --force gets us past any
  // residual conflicts from a previous half-failed install.
  let installCmd: string;
  let installArgs: string[];
  if (format === "deb") {
    installCmd = "/usr/bin/dpkg";
    installArgs = ["-E", "--force-confold", "--force-confdef", "-i", absPath];
  } else {
    // format === "rpm"
    installCmd = "/usr/bin/rpm";
    installArgs = ["-U", "--force", "--nodeps", absPath];
  }

  // ── Detach via systemd-run --scope ──────────────────────────────
  // The dpkg/rpm we're about to launch will, via its postinst, ask
  // systemd to restart tracenium-privsvc and tracenium-agent. If we
  // ran the installer as a normal child of THIS process, KillMode=
  // control-group on the privsvc unit would kill the installer
  // mid-postinst when systemd stops the unit. systemd-run --scope
  // creates a transient systemd scope outside our cgroup; the
  // installer continues running there independently of what systemd
  // does to our unit.
  //
  // --collect: clean up the scope record after exit so we don't leak
  //   systemctl-visible units.
  // --quiet: no "Running as unit: ..." line to stdout; we log
  //   ourselves.
  // --slice=system.slice: park the scope at the same hierarchy level
  //   as other system services (default would be the calling user's
  //   slice).
  const scopeUnit = `tracenium-agent-update-${process.pid}-${Date.now()}.scope`;
  const systemdRunArgs = [
    "--scope",
    "--collect",
    "--quiet",
    "--slice=system.slice",
    `--unit=${scopeUnit}`,
    "--",
    installCmd,
    ...installArgs,
  ];

  logger.info("agent_install_start", {
    targetVersion,
    format,
    family: distro.family,
    path: absPath,
    scopeUnit,
  });

  // ── Por que esto NO es un try/catch a secas ─────────────────────
  //
  // `spawn` no lanza de forma sincrona cuando el binario no se puede
  // ejecutar: emite un evento 'error' ASINCRONO. Un try/catch alrededor de
  // la llamada no lo captura nunca, y sin listener de 'error' Node lo trata
  // como excepcion no capturada y MATA EL PROCESO.
  //
  // Eso es exactamente lo que ocurrio en produccion (2026-08-15): un perfil
  // de AppArmor sin regla para systemd-run hacia que el spawn fallara con
  // EACCES; privsvc moria entero, se llevaba por delante el socket IPC —
  // tirando compliance, inventario y CDP, que no tienen nada que ver con
  // actualizar— y systemd lo reiniciaba. 364 reinicios acumulados antes de
  // detectarlo, y el agente sin actualizarse desde 1.1.21.
  //
  // Ademas esperamos al evento 'spawn' antes de responder: devolver
  // `started: true` cuando el proceso ni siquiera arranco le hacia creer al
  // agente que la instalacion iba en marcha.
  const viaScope = await trySpawnDetached("/usr/bin/systemd-run", systemdRunArgs);

  if (viaScope.ok) {
    logger.info("agent_install_dispatched", {
      targetVersion,
      pid: viaScope.pid,
      scopeUnit,
    });

    return success(req.id, {
      started: true,
      command: installCmd,
      args: installArgs,
      scopeUnit,
      detached: "systemd-run",
    });
  }

  // ── Fallback: lanzar el instalador DIRECTAMENTE ──────────────────
  //
  // Solo se llega aqui si systemd-run no se pudo EJECUTAR (EACCES de un
  // perfil AppArmor/SELinux, ENOENT en una distro sin systemd-run). No es
  // un fallo del paquete ni de dpkg.
  //
  // ⚠️ POR QUE ESTO EXISTE, aunque sea peor que el scope:
  //
  // El perfil de AppArmor lo instala NUESTRO PROPIO .deb y es un allowlist.
  // Cuando en 1.1.35 le falto la regla de systemd-run, el host quedo
  // ATRAPADO: el arreglo del perfil viajaba dentro del update que el propio
  // perfil bloqueaba. SRVOC-MainAgent estuvo cuatro dias congelado bajando
  // nueve versiones (1.1.36→1.1.42, 730 MB) sin instalar ninguna, y solo
  // salio con un `dpkg -i` manual por SSH. Un hueco en el allowlist no
  // puede volver a ser capaz de inutilizar el mecanismo que entrega su
  // propia correccion.
  //
  // ⚠️ EN QUE ES PEOR: sin el scope, el instalador queda en el cgroup de
  // privsvc. El postinst pide `systemctl restart tracenium-privsvc`, y
  // KillMode=control-group mata al dpkg en ese punto — cerca del final,
  // con el unpack ya hecho. El paquete puede quedar half-configured, que se
  // recupera con `dpkg --configure -a`. Es un resultado malo; quedarse sin
  // poder actualizar nunca es peor.
  //
  // `detached` abre sesion propia (setsid), lo que aisla de señales
  // dirigidas al grupo de procesos. NO escapa del cgroup: eso solo lo hace
  // el scope, y es justo lo que no tenemos aqui.
  logger.warn("agent_install_scope_unavailable", {
    error: viaScope.error,
    targetVersion,
    scopeUnit,
    hint:
      "no se pudo ejecutar /usr/bin/systemd-run; revisar AppArmor/SELinux " +
      "en el host (aa-status, dmesg | grep DENIED) y que el binario exista. " +
      "Se intenta el instalador directo (degradado): si el postinst muere al " +
      "reiniciar el servicio, recuperar con `dpkg --configure -a`",
  });

  const direct = await trySpawnDetached(installCmd, installArgs);

  if (!direct.ok) {
    logger.error("agent_install_spawn_failed", {
      scopeError: viaScope.error,
      directError: direct.error,
      targetVersion,
      hint:
        "fallaron AMBOS caminos (systemd-run y el instalador directo). El " +
        "host bloquea la ejecucion de binarios de sistema desde privsvc: " +
        "revisar el perfil de AppArmor/SELinux",
    });
    return fail(req.id, "install_failed", direct.error);
  }

  logger.warn("agent_install_dispatched_degraded", {
    targetVersion,
    pid: direct.pid,
    command: installCmd,
  });

  return success(req.id, {
    started: true,
    command: installCmd,
    args: installArgs,
    scopeUnit: null,
    // Viaja hasta el agente para que el resultado sea visible en el control
    // plane: "se instalo, pero por el camino degradado" merece un ticket,
    // no el silencio de un exito normal.
    detached: "direct",
    degraded: true,
    degradedReason: viaScope.error,
  });
}

/**
 * Lanzar un proceso desacoplado y confirmar que ARRANCO de verdad.
 *
 * `spawn` no lanza de forma sincrona cuando el binario no se puede ejecutar:
 * emite un evento 'error' ASINCRONO. Un try/catch alrededor de la llamada no
 * lo captura nunca, y sin listener de 'error' Node lo trata como excepcion no
 * capturada y MATA EL PROCESO.
 *
 * Eso es exactamente lo que ocurrio en produccion (2026-08-15): un perfil de
 * AppArmor sin regla para systemd-run hacia que el spawn fallara con EACCES;
 * privsvc moria entero, se llevaba por delante el socket IPC —tirando
 * compliance, inventario y CDP, que no tienen nada que ver con actualizar— y
 * systemd lo reiniciaba. 364 reinicios acumulados antes de detectarlo, y el
 * agente sin actualizarse desde 1.1.21.
 *
 * Esperar al evento 'spawn' antes de responder es lo que permite ENCADENAR un
 * fallback: sin esa confirmacion no habria forma de saber que el primer
 * camino no arranco, y devolver `started: true` a ciegas le hacia creer al
 * agente que la instalacion iba en marcha.
 */
export async function trySpawnDetached(
  command: string,
  args: string[]
): Promise<{ ok: true; pid?: number } | { ok: false; error: string }> {
  const child = spawn(command, args, {
    detached: true,
    stdio: "ignore",
    env: {
      ...process.env,
      DEBIAN_FRONTEND: "noninteractive",
      LANG: "C",
      LC_ALL: "C",
    },
  });

  const result = await new Promise<
    { ok: true; pid?: number } | { ok: false; error: string }
  >((resolve) => {
    let settled = false;
    const done = (r: { ok: true; pid?: number } | { ok: false; error: string }) => {
      if (settled) return;
      settled = true;
      resolve(r);
    };

    // 'error' cubre EACCES, ENOENT y demas fallos de exec. Registrarlo es lo
    // que impide que Node tumbe el proceso.
    child.on("error", (err: any) =>
      done({ ok: false, error: err?.message || String(err) })
    );
    // 'spawn' confirma que el proceso arranco de verdad.
    child.on("spawn", () => done({ ok: true, pid: child.pid }));

    // Red de seguridad: si ninguno de los dos llega, no bloqueamos el broker.
    // Se asume arrancado — el resultado real se vera en el siguiente HELLO
    // del agente con su nueva version.
    setTimeout(
      () => done({ ok: true, pid: child.pid }),
      SPAWN_CONFIRM_TIMEOUT_MS
    ).unref();
  });

  // unref so this process won't keep the event loop alive waiting for the
  // installer. Fire and forget from privsvc's POV — success/failure shows up
  // via the agent's next HELLO carrying the new agentVersion (or failing to).
  if (result.ok) child.unref();

  return result;
}
