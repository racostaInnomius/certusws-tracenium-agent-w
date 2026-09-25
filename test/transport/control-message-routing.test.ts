// test/transport/control-message-routing.test.ts
//
// ⚠️ Un mensaje del agente sin ruta muere en silencio.
//
// `ctx.sendControl({ <campo>: … })` no escribe en el stream: busca el campo en
// una TABLA de variantes de `grpc-stream.ts` y lo manda por el método IPC que
// le corresponda, porque PrivSvc es el único dueño de la conexión gRPC. Un
// campo que no esté en esa tabla cae al final:
//
//     ctx.logger?.warn?.("[rcp] sendControl: unknown message shape", …)
//
// Un `warn` en el equipo. Nada en el control plane. Nada que mirar.
//
// Así se perdieron las grabaciones de pantalla: `remoteRecordingReady` —el
// mensaje que lleva la CLAVE con la que se descifra el vídeo, que no se
// persiste en el equipo— nunca estuvo en la tabla. El backend tenía su extremo
// implementado desde el principio; el agente grababa, cifraba, y la clave no
// salía. Resultado medido el 25-sep-2026: 81 sesiones de pantalla en T1 con la
// grabación ENCENDIDA y `remote_session_recordings` vacía en los cinco
// tenants, mientras la franja del equipo le decía a la persona que la estaban
// grabando.
//
// Por eso este test no comprueba un mensaje: comprueba que NINGUNO se quede
// sin ruta. Lee los dos ficheros y los cruza.

import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import path from "path";

const ROOT = path.resolve(__dirname, "../..");
const STREAM = path.join(ROOT, "src/transport/grpc-stream.ts");
const SESSION_MANAGER = path.join(ROOT, "src/plugins/rcp/session-manager.ts");

/** Los campos que la tabla de variantes sabe encaminar. */
function camposConRuta(): Set<string> {
  const src = readFileSync(STREAM, "utf8");
  const tabla = src.slice(
    src.indexOf("const variants: Array<[string, string]> = ["),
    src.indexOf("for (const [field, method] of variants)")
  );
  const out = new Set<string>();
  for (const m of tabla.matchAll(/\["(\w+)",\s*"([\w.]+)"\]/g)) out.add(m[1]);
  return out;
}

/** Los campos que el plugin de RCP llega a mandar. */
function camposQueSeMandan(): Set<string> {
  const src = readFileSync(SESSION_MANAGER, "utf8");
  const out = new Set<string>();
  // `this.ctx.sendControl?.({ campo: …` y `sendControl?.({ campo, …`
  for (const m of src.matchAll(/sendControl\?\.\(\{\s*\n?\s*(\w+)\s*[:,]/g)) out.add(m[1]);
  return out;
}

describe("⚠️ todo mensaje que el agente manda tiene ruta", () => {
  it("ningún campo de sendControl se queda fuera de la tabla de variantes", () => {
    const conRuta = camposConRuta();
    const mandados = [...camposQueSeMandan()];
    const huérfanos = mandados.filter((c) => !conRuta.has(c));

    expect(
      huérfanos,
      "Estos mensajes salen de session-manager y NO están en la tabla de " +
        "variantes de grpc-stream.ts. No fallan: se pierden con un warn en el " +
        "equipo y nada llega al control plane. Así se perdieron 81 " +
        "grabaciones de pantalla:\n" +
        huérfanos.map((c) => `  - ${c}`).join("\n")
    ).toEqual([]);
  });

  it("la clave de la grabación tiene ruta — el caso que faltaba", () => {
    expect(camposConRuta().has("remoteRecordingReady")).toBe(true);
  });

  it("el detector ve de verdad los dos lados", () => {
    // Sin esto, una expresión regular rota daría verde para siempre y el test
    // de arriba sería decorativo.
    const conRuta = camposConRuta();
    const mandados = camposQueSeMandan();
    expect(conRuta.size).toBeGreaterThanOrEqual(8);
    expect(mandados.size).toBeGreaterThanOrEqual(5);
    // Uno que se sabe que está en los dos lados desde M1.
    expect(conRuta.has("remoteSessionAnswer")).toBe(true);
    expect(mandados.has("remoteSessionAnswer")).toBe(true);
  });
});
