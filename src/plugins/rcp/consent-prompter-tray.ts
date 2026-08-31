// src/plugins/rcp/consent-prompter-tray.ts
//
// ConsentPrompter para las plataformas QUE YA TIENEN algo en la sesión del
// usuario: Windows (bandeja .NET) y macOS (app de estado Swift). ADR-0012.
//
// ── Por qué aquí no se lanza un helper, como en Linux ────────────────
//
//   En Linux no hay nada nuestro en la sesión gráfica, así que PrivSvc lanza
//   un binario X11 a propósito. Aquí sí lo hay, ya firmado y ya corriendo —
//   y eso importa especialmente en macOS: un binario nuevo sin firmar lo
//   bloquea Gatekeeper, y meter el diálogo dentro del helper de captura
//   arriesgaría el baile de atribución TCC que hoy funciona.
//
//   Así que se usa el canal que ya existe entre agente y bandeja: un fichero
//   de petición en el directorio de estado compartido, y uno de respuesta en
//   el perfil del usuario. El mismo par de sentidos que ya mueven
//   tray-status.json y remote-session-revoke.json.
//
// ── Por qué se sondea y no se espera un evento ───────────────────────
//
//   El agente corre como servicio y la bandeja como usuario; no comparten un
//   bus. La bandeja YA vigila ese directorio (FileSystemWatcher en Windows,
//   DispatchSource en macOS), así que la petición le llega en ~150 ms. La
//   respuesta vuelve por sondeo porque montar un canal a la inversa para un
//   evento que ocurre una vez por sesión no se paga.
//
// ── El fichero de petición CADUCA ────────────────────────────────────
//
//   Lleva su propio plazo dentro. Sin eso, una petición que quedara sin
//   consumir —el agente reinicia mientras el diálogo está abierto— haría que
//   la bandeja enseñara, minutos u horas después, un aviso pidiendo permiso
//   para una sesión que ya terminó. La persona diría que sí a algo que ya no
//   existe, y aprendería que estos avisos no significan nada.

import fs from "fs";
import path from "path";
import os from "os";
import type { AgentContext } from "../../core/agent-context";
import type {
  ConsentDecision,
  ConsentPrompter,
  ConsentRequest
} from "./consent-prompt";
import { consentButtons, consentLines, consentTitle, kindForCapability } from "./consent-text";
import { getTrayStatusFilePath } from "../../bootstrap/paths";

const REQUEST_FILE = "consent-request.json";
const RESPONSE_FILE = "consent-response.json";

/** Cada cuánto se mira si la persona ya contestó. */
const POLL_MS = 300;

export type TrayConsentRequestFile = {
  requestId: string;
  sessionId: string;
  kind: "view" | "control";
  title: string;
  lines: string[];
  allowLabel: string;
  denyLabel: string;
  /** ISO. La bandeja NO debe enseñar una petición vencida. */
  expiresAtUtc: string;
};

export type TrayConsentResponseFile = {
  requestId: string;
  decision: "approved" | "denied";
  atUtc: string;
};

/** Directorio de estado compartido: donde vive tray-status.json. */
export function consentRequestPath(): string {
  return path.join(path.dirname(getTrayStatusFilePath()), REQUEST_FILE);
}

/**
 * Dónde busca el agente la respuesta.
 *
 * La bandeja corre como el usuario y no puede escribir en el directorio de
 * estado (ACL SYSTEM/admin), así que escribe en su propio perfil — igual que
 * la petición de corte. Se miran todos los perfiles porque el servicio no
 * sabe de antemano quién está en consola.
 */
export function consentResponseCandidates(): string[] {
  if (process.platform === "win32") {
    const root = path.join(process.env.SystemDrive || "C:", "\\Users");
    const dirs: string[] = [];
    try {
      for (const u of fs.readdirSync(root)) {
        dirs.push(path.win32.join(root, u, "AppData", "Local", "Tracenium", RESPONSE_FILE));
      }
    } catch {
      /* sin C:\Users legible: queda el homedir de abajo */
    }
    dirs.push(path.join(os.homedir(), "AppData", "Local", "Tracenium", RESPONSE_FILE));
    return dirs;
  }

  // macOS. Mismo cuidado que en remote-session-revoke.ts: un readdir fallido
  // no puede descartar el homedir propio.
  const dirs: string[] = [];
  try {
    for (const u of fs.readdirSync("/Users")) {
      dirs.push(path.join("/Users", u, "Library", "Application Support", "Tracenium", RESPONSE_FILE));
    }
  } catch {
    /* seguimos con el homedir */
  }
  dirs.push(path.join(os.homedir(), "Library", "Application Support", "Tracenium", RESPONSE_FILE));
  return dirs;
}

/**
 * Busca y CONSUME una respuesta para `requestId`.
 *
 * Consume siempre que encuentra el fichero, aunque sea de otra petición:
 * dejarlo ahí lo convertiría en una mina para la siguiente, que se resolvería
 * sola con una decisión que nadie tomó para ella.
 */
export function consumeConsentResponse(requestId: string): ConsentDecision | null {
  for (const file of consentResponseCandidates()) {
    let raw: string;
    try {
      raw = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    try {
      fs.unlinkSync(file);
    } catch {
      /* mejor atenderla dos veces que quedarse esperando */
    }

    let parsed: TrayConsentResponseFile | null = null;
    try {
      parsed = JSON.parse(raw) as TrayConsentResponseFile;
    } catch {
      continue;
    }
    if (!parsed || parsed.requestId !== requestId) continue;
    return parsed.decision === "approved" ? "approved" : "denied";
  }
  return null;
}

export function createTrayConsentPrompter(ctx: AgentContext): ConsentPrompter {
  return {
    available(): boolean {
      // Se puede escribir la petición donde la bandeja mira. NO se comprueba
      // que la bandeja esté corriendo: eso cambia mientras el agente vive —el
      // usuario cierra sesión, la abre— y una comprobación al arrancar
      // mentiría el resto del día. Si no hay nadie que la lea, el plazo vence
      // y eso ya cuenta como negativa.
      try {
        return Boolean(path.dirname(getTrayStatusFilePath()));
      } catch {
        return false;
      }
    },

    async request(req: ConsentRequest): Promise<ConsentDecision> {
      const kind = kindForCapability(req.capability);
      const buttons = consentButtons(kind);
      const requestId = `${req.sessionId}.${kind}.${Date.now()}`;
      const file = consentRequestPath();

      const payload: TrayConsentRequestFile = {
        requestId,
        sessionId: req.sessionId,
        kind,
        title: consentTitle(kind),
        lines: consentLines({
          kind,
          operator: req.operator,
          // TODO(ADR-0012 paso 3): pasar el toggle de grabación del tenant
          // cuando exista. Hoy no se graba, y decir que sí sería mentir en la
          // otra dirección.
          recording: false
        }),
        allowLabel: buttons.allow,
        denyLabel: buttons.deny,
        expiresAtUtc: new Date(Date.now() + req.timeoutSeconds * 1000).toISOString()
      };

      try {
        const tmp = `${file}.tmp`;
        // 0644: la bandeja corre como el usuario y tiene que poder leerlo.
        fs.writeFileSync(tmp, JSON.stringify(payload), { encoding: "utf8", mode: 0o644 });
        fs.renameSync(tmp, file);
      } catch (err: any) {
        ctx.logger?.error?.("[rcp] no se pudo publicar la petición de consentimiento", {
          file,
          err: err?.message || String(err)
        });
        return "denied";
      }

      try {
        const deadline = Date.now() + req.timeoutSeconds * 1000;
        while (Date.now() < deadline) {
          const decision = consumeConsentResponse(requestId);
          if (decision) return decision;
          await new Promise((r) => setTimeout(r, POLL_MS));
        }
        return "timeout";
      } finally {
        // Retirar la petición pase lo que pase. Si venció sin respuesta, no
        // puede quedarse ahí para que la bandeja la enseñe más tarde.
        try {
          fs.unlinkSync(file);
        } catch {
          /* ya no está */
        }
      }
    }
  };
}
