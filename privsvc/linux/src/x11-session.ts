// privsvc/linux/src/x11-session.ts
//
// Descubrimiento de la sesión gráfica activa y salto a ella, COMPARTIDO por
// todo lo que PrivSvc necesita poner o leer en el escritorio del usuario.
//
// ── Por qué existe este módulo ───────────────────────────────────────
//
//   PrivSvc corre como servicio root de systemd, fuera de cualquier sesión
//   gráfica. Para tocar el escritorio hacen falta tres cosas que un demonio
//   sin cara no tiene: el DISPLAY, una cookie XAUTHORITY que autorice la
//   conexión, y correr como el usuario de la sesión.
//
//   Esa maniobra la inventó screen-capture.ts para la captura de pantalla.
//   Ahora la necesita también el indicador de sesión remota (ADR-0012), y
//   copiarla habría dejado dos implementaciones que se separan con el tiempo:
//   la de captura arreglada y la del indicador no, o al revés. Justo el tipo
//   de divergencia que hace que un control de privacidad funcione en las
//   pruebas y no en el equipo de alguien.
//
// ── Qué es puro y qué no ─────────────────────────────────────────────
//
//   `selectGraphicalSession` es una función pura sobre la salida ya leída de
//   loginctl, y por eso se puede probar. El resto —ejecutar loginctl, buscar
//   la cookie, lanzar procesos— toca el sistema y no se presta a un test
//   honesto; se mantiene lo más delgado posible alrededor de la parte pura.
//
//   Este código llevaba en campo desde M3.S1 sin un solo test. Se extrae con
//   la lógica de selección cubierta ANTES de que dependa de ella un segundo
//   llamador.

import { execFile } from "child_process";
import path from "path";
import fs from "fs";

export type GraphicalSession = {
  uid: number;
  user: string;
  display: string;
  /** "x11" | "wayland" | "tty" | … */
  type: string;
};

export type SessionProps = Record<string, string>;

export function execText(
  cmd: string,
  args: string[],
  timeout = 2500
): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout, maxBuffer: 1024 * 1024 }, (err, stdout) => {
      if (err) return resolve(null);
      resolve(String(stdout || ""));
    });
  });
}

/** Parsea la salida `Key=Value` de `loginctl show-session <id> -p Key`. */
export function parseLoginctlProps(text: string): SessionProps {
  const out: SessionProps = {};
  for (const raw of text.split("\n")) {
    const idx = raw.indexOf("=");
    if (idx <= 0) continue;
    out[raw.slice(0, idx).trim()] = raw.slice(idx + 1).trim();
  }
  return out;
}

/** Extrae los ids de sesión de `loginctl list-sessions --no-legend`. */
export function parseSessionIds(list: string): string[] {
  const ids: string[] = [];
  for (const line of list.split("\n")) {
    const cols = line.trim().split(/\s+/);
    if (cols[0]) ids.push(cols[0]);
  }
  return ids;
}

/**
 * Elige la sesión gráfica a partir de las propiedades YA LEÍDAS de cada
 * sesión, en el mismo orden en que las devolvió loginctl.
 *
 * Reglas, y el porqué de cada una:
 *
 *  - **Las remotas se descartan.** Una sesión SSH no tiene framebuffer local;
 *    capturarla no significa nada.
 *  - **Wayland se conserva en vez de saltarlo.** Devolverlo permite al
 *    llamador decir "wayland_unsupported", que es un error honesto. Saltarlo
 *    diría "no hay escritorio" en una máquina que sí lo tiene — un mensaje
 *    falso que manda a quien lo lea a investigar lo que no es.
 *  - **Activa gana a inactiva.** Una sesión inactiva sirve de último recurso
 *    (el usuario cambió de TTY), pero la activa es la que alguien mira.
 */
export function selectGraphicalSession(
  sessions: SessionProps[]
): GraphicalSession | null {
  let fallback: GraphicalSession | null = null;

  for (const p of sessions) {
    if (p.Remote === "yes") continue;

    const uid = Number(p.User);
    const user = p.Name || "";
    const type = (p.Type || "").toLowerCase();
    const display = p.Display || "";

    if (!Number.isInteger(uid) || !user) continue;

    if (type === "wayland") {
      const candidate = { uid, user, display, type };
      if (p.Active === "yes") return candidate;
      fallback ||= candidate;
      continue;
    }

    if (type === "x11" || display) {
      const candidate = { uid, user, display: display || ":0", type: type || "x11" };
      if (p.Active === "yes") return candidate;
      fallback ||= candidate;
    }
  }

  return fallback;
}

/** Lee las propiedades de una sesión concreta. */
export async function readSessionProps(id: string): Promise<SessionProps | null> {
  const props = await execText("loginctl", [
    "show-session", id,
    "-p", "Active",
    "-p", "Remote",
    "-p", "Type",
    "-p", "Display",
    "-p", "Name",
    "-p", "User"
  ]);
  return props ? parseLoginctlProps(props) : null;
}

/**
 * Encuentra la sesión gráfica activa vía logind.
 *
 * `onNoLoginctl` deja al llamador registrar el caso con su propio código de
 * log: este módulo no importa el logger a propósito, para que la parte pura
 * siga siendo probable sin arrastrar el resto de PrivSvc.
 */
export async function activeGraphicalSession(
  onNoLoginctl?: () => void
): Promise<GraphicalSession | null> {
  const list = await execText("loginctl", ["list-sessions", "--no-legend"]);
  if (!list) {
    onNoLoginctl?.();
    return null;
  }

  const all: SessionProps[] = [];
  for (const id of parseSessionIds(list)) {
    const p = await readSessionProps(id);
    if (p) all.push(p);
  }

  return selectGraphicalSession(all);
}

/**
 * Busca la cookie XAUTHORITY de una sesión X11, de lo más fiable a lo menos.
 *
 *   1. El `-auth <path>` del propio proceso Xorg — los gestores de sesión
 *      (gdm/lightdm/sddm) siempre lo pasan, y es la cookie que de verdad nos
 *      autoriza.
 *   2. Ubicaciones conocidas por gestor.
 *   3. Rendirse: el helper prueba entonces $HOME/.Xauthority por su cuenta y,
 *      como último recurso, una conexión local sin autenticar.
 */
export async function resolveXauthority(
  session: GraphicalSession,
  home: string | null
): Promise<string | null> {
  const ps = await execText("pgrep", ["-a", "-x", "Xorg"]);
  const psFallback = ps || (await execText("pgrep", ["-af", "X"]));
  if (psFallback) {
    for (const line of psFallback.split("\n")) {
      const m = line.match(/-auth\s+(\S+)/);
      if (m && fs.existsSync(m[1])) return m[1];
    }
  }

  const candidates = [
    `/run/user/${session.uid}/gdm/Xauthority`,
    `/run/user/${session.uid}/.Xauthority`,
    session.display ? `/var/run/lightdm/root/${session.display}` : "",
    home ? path.join(home, ".Xauthority") : ""
  ].filter(Boolean) as string[];

  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }

  return null;
}

export function homeForUser(user: string): Promise<string | null> {
  return new Promise((resolve) => {
    execFile("getent", ["passwd", user], { timeout: 2000 }, (err, stdout) => {
      if (err) return resolve(null);
      // name:x:uid:gid:gecos:home:shell
      const parts = String(stdout).trim().split(":");
      resolve(parts[5] || null);
    });
  });
}

/**
 * Construye los argumentos para correr algo como el usuario de la sesión con
 * DISPLAY y XAUTHORITY puestos:
 *
 *   runuser -u <user> -- env DISPLAY=<d> [XAUTHORITY=<x>] <argv...>
 *
 * `runuser` (util-linux) baja privilegios sin PAM cuando quien llama es root
 * — más limpio que `su -c`: sin comillas de shell y sin scripts de login.
 * Separado en su propia función para poder comprobar la forma del comando sin
 * ejecutar nada.
 */
export function buildRunuserArgs(
  session: GraphicalSession,
  xauthority: string | null,
  argv: string[],
  extraEnv: string[] = []
): string[] {
  return [
    "-u", session.user, "--", "env",
    ...buildEnvAssignments(session, xauthority),
    ...extraEnv,
    ...argv
  ];
}

/**
 * Las asignaciones `CLAVE=valor` para `env`.
 *
 * Se exporta aparte porque el camino de respaldo con `su` recibe una línea de
 * shell en vez de un argv y necesita las mismas asignaciones. Sacarlas de la
 * lista ya construida —troceando por índice— funcionaba y se rompía en cuanto
 * alguien añadiera una variable.
 *
 * ⚠️ Cuando no hay cookie se OMITE la variable, no se pasa vacía:
 * `XAUTHORITY=""` hace que Xlib busque una ruta vacía y falle, en vez de
 * recurrir a $HOME/.Xauthority como hace cuando no está definida.
 */
export function buildEnvAssignments(
  session: GraphicalSession,
  xauthority: string | null
): string[] {
  const env = [`DISPLAY=${session.display || ":0"}`];
  if (xauthority) env.push(`XAUTHORITY=${xauthority}`);
  return env;
}
