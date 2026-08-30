// src/status/remote-session-revoke.ts
//
// Canal bandeja → núcleo para CORTAR una sesión de control remoto desde el
// equipo del usuario (ADR-0012).
//
// POR QUÉ ES SU PROPIO MÓDULO Y NO REUSA EL SONDEO EXISTENTE
//
//   Ya hay un canal bandeja → núcleo por fichero: catalog-install-request.json,
//   que grpc-stream.ts sondea cada 5 segundos. Ese ritmo es correcto para
//   "instálame esta aplicación" y es INACEPTABLE aquí.
//
//   Esto es un control de revocación: la persona pulsa "detener" porque no
//   quiere que sigan viendo su pantalla. Cinco segundos de sondeo son hasta
//   cinco segundos más de pantalla compartida después de haberlo pedido. Un
//   consentimiento que tarda en retirarse no es un consentimiento, y el retraso
//   se nota justo en el peor momento — cuando alguien se ha arrepentido.
//
//   Así que se sondea rápido (ver POLL_MS en screen-session.ts) pero SOLO
//   mientras hay una sesión viva. Fuera de sesión no se mira el fichero
//   siquiera: el coste es cero cuando nadie está compartiendo nada.
//
// DÓNDE ESCRIBE LA BANDEJA
//
//   Mismo sitio y mismo motivo que catalog-install-request.json: la bandeja
//   corre como el usuario de consola y no puede escribir en el directorio de
//   estado compartido, cuya ACL es solo SYSTEM/Admin. Escribe en su propio
//   %LOCALAPPDATA%\\Tracenium\\ (o ~/Library/Application Support/Tracenium en
//   macOS), donde el servicio privilegiado sí puede leer.
//
// POR QUÉ SE COMPARA EL sessionId
//
//   Una petición de corte vale para LA sesión que la persona estaba viendo. Si
//   se guardara un fichero suelto y llegara una sesión nueva minutos después,
//   ese resto la mataría nada más abrirse y el operador vería una desconexión
//   sin causa. Se consume el fichero y se comprueba a qué sesión apunta.

import fs from "fs";
import path from "path";
import os from "os";

const FILE_NAME = "remote-session-revoke.json";

/**
 * Una petición de corte caduca rápido. Es una acción inmediata sobre algo que
 * está pasando ahora; si lleva minutos parada, la sesión a la que se refería ya
 * terminó y actuar sobre ella solo puede equivocarse.
 */
const MAX_AGE_MS = 60_000;

export type RevokeRequest = {
  sessionId: string;
  atUtc: string;
  /** Lo escribe la bandeja para el registro de auditoría: quién cortó. */
  by?: string;
};

/**
 * Directorios donde puede estar el fichero. En Windows no sabemos de antemano
 * QUÉ usuario está en consola, así que se miran todos los perfiles: el coste es
 * un readdir sobre C:\\Users y la alternativa —resolver el usuario interactivo
 * por PowerShell, como hace el watcher del catálogo— cuesta cientos de ms, que
 * es justo lo que este camino no puede permitirse.
 */
function candidateDirs(): string[] {
  if (process.platform === "win32") {
    const root = path.join(process.env.SystemDrive || "C:", "\\Users");
    try {
      return fs
        .readdirSync(root)
        .map((u) => path.win32.join(root, u, "AppData", "Local", "Tracenium"));
    } catch {
      return [];
    }
  }

  if (process.platform === "darwin") {
    try {
      return fs
        .readdirSync("/Users")
        .map((u) =>
          path.join("/Users", u, "Library", "Application Support", "Tracenium")
        );
    } catch {
      return [];
    }
  }

  // ⚠️ Un readdir fallido NO puede descartar el resto de candidatos. La primera
  // versión hacía `return []` aquí, así que en cualquier sistema sin /home
  // legible —macOS lo tiene como autofs vacío— se perdía también el homedir del
  // propio usuario y la revocación no habría funcionado NUNCA, en silencio.
  // Lo encontró un test, no el campo.
  const dirs: string[] = [];
  try {
    for (const u of fs.readdirSync("/home")) {
      dirs.push(path.join("/home", u, ".config", "tracenium"));
    }
  } catch {
    /* sin /home legible: seguimos con el homedir de abajo */
  }
  dirs.push(path.join(os.homedir(), ".config", "tracenium"));
  return dirs;
}

/**
 * Busca y CONSUME una petición de corte para `sessionId`.
 *
 * Consume siempre que encuentra el fichero, aunque sea de otra sesión o esté
 * caduco: dejarlo ahí lo convertiría en una mina para la siguiente sesión.
 *
 * Nunca lanza. Este camino corre en el bucle de captura, y un fallo leyendo un
 * fichero opcional no puede tumbar la sesión que intenta proteger.
 */
export function consumeRevokeRequest(sessionId: string): RevokeRequest | null {
  for (const dir of candidateDirs()) {
    const file = path.join(dir, FILE_NAME);
    let raw: string;
    try {
      raw = fs.readFileSync(file, "utf8");
    } catch {
      continue; // no existe en este perfil, que es el caso normal
    }

    try {
      fs.unlinkSync(file);
    } catch {
      // Si no se puede borrar, seguir adelante igualmente: es preferible
      // atender el corte dos veces que no atenderlo.
    }

    let parsed: RevokeRequest | null = null;
    try {
      parsed = JSON.parse(raw) as RevokeRequest;
    } catch {
      continue; // fichero corrupto: ya lo hemos borrado, nada más que hacer
    }
    if (!parsed?.sessionId) continue;

    if (parsed.sessionId !== sessionId) continue;

    const at = Date.parse(parsed.atUtc || "");
    if (Number.isFinite(at) && Date.now() - at > MAX_AGE_MS) continue;

    return parsed;
  }
  return null;
}
