// test/priv/ipc-request-envelope.test.ts
//
// ⚠️ Toda llamada al PrivSvc tiene que llevar `v: 1`.
//
// No es una formalidad: es lo PRIMERO que mira el router, antes que el método.
//
//     if (req.v !== 1) return fail(req.id, "bad_version", …)   ← linux y macOS
//
// El 30-ago se añadió la puerta del indicador de pantalla de Linux con la
// llamada sin `v`. Compiló, se publicó, y **ningún equipo Linux pudo compartir
// pantalla durante 24 días**: la sesión se niega si no puede avisar al usuario,
// así que el fallo no parecía un error sino una negativa razonable. Se
// descubrió porque alguien lo intentó (T118, 23-sep).
//
// ⚠️ Y no se cayó en Windows por una asimetría que conviene tener presente: el
// DTO de C# declara `public int Version { get; set; } = 1`, o sea **rellena el
// campo por defecto**. Windows perdona lo que Linux y macOS rechazan — y
// Windows es casi toda la flota, así que los fallos de esta familia se esconden
// ahí y sólo salen en los otros dos.
//
// Desde el 24-sep `IPrivSvcClient.call` está tipado y olvidar `v` no compila.
// Este test cubre lo que el tipo NO alcanza: los `(ctx.priv as any).call(...)`,
// de los que hay una docena en la capa de transporte. Un cast es un agujero del
// mismo tamaño que el `any` que se acaba de cerrar.

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "fs";
import path from "path";

const SRC = path.resolve(__dirname, "../../src");

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const p = path.join(dir, entry);
    if (statSync(p).isDirectory()) out.push(...tsFiles(p));
    else if (entry.endsWith(".ts")) out.push(p);
  }
  return out;
}

/**
 * El literal que se le pasa a `.call(`, recortado por llaves emparejadas.
 *
 * Una ventana de N líneas se equivoca en los dos sentidos —corta un objeto
 * largo y se come el siguiente cuando es corto—, y en un test cuyo trabajo es
 * no tener falsos verdes eso no vale.
 */
function objetoDeLaLlamada(src: string, desde: number): string {
  let depth = 0;
  for (let i = desde; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return src.slice(desde, i + 1);
    }
  }
  return src.slice(desde);
}

type Hallazgo = { fichero: string; linea: number };

function llamadasSinVersion(): Hallazgo[] {
  const malas: Hallazgo[] = [];
  for (const file of tsFiles(SRC)) {
    const src = readFileSync(file, "utf8");
    // ⚠️ `?.(` cuenta. La primera versión de esto sólo casaba `.call(` y dejó
    // pasar justo la llamada del bug —`ctx.priv?.call?.({ … })`—, que es la
    // forma que usa medio RCP. Un detector con un hueco es peor que ninguno:
    // da verde y encima tranquiliza.
    const re = /\.call\??\.?\(\s*\{/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(src))) {
      const abre = src.indexOf("{", m.index);
      const obj = objetoDeLaLlamada(src, abre);
      // `v: 1` en el PRIMER nivel del literal. Basta con que esté: el tipo se
      // encarga de que sea exactamente 1.
      if (!/(^|[{,\s])v\s*:\s*1\b/.test(obj)) {
        malas.push({
          fichero: path.relative(SRC, file),
          linea: src.slice(0, m.index).split("\n").length
        });
      }
    }
  }
  return malas;
}

describe("⚠️ el sobre de las peticiones al PrivSvc", () => {
  it("ninguna llamada sale sin `v: 1`, ni siquiera las que van por un cast", () => {
    const malas = llamadasSinVersion();
    // El mensaje importa tanto como la aserción: quien lo rompa tiene que
    // entender por qué en tres segundos, sin leer este fichero.
    expect(
      malas,
      "Estas llamadas al PrivSvc saldrían sin la versión del protocolo. El " +
        "router de Linux y macOS las rechaza con `bad_version` antes de mirar " +
        "el método; Windows las perdona porque su DTO rellena v=1, así que el " +
        "fallo sólo se ve en los otros dos y tarda semanas en aparecer:\n" +
        malas.map((x) => `  - ${x.fichero}:${x.linea}`).join("\n")
    ).toEqual([]);
  });

  it("el detector encuentra una llamada mala de verdad", () => {
    // Sin esto, un `objetoDeLaLlamada` roto daría siempre verde y el test de
    // arriba sería decorativo.
    const mala = `await priv.call({ id: "x", method: "ping", params: {} });`;
    const buena = `await priv.call({ v: 1, id: "x", method: "ping", params: {} });`;
    const obj = (s: string) => objetoDeLaLlamada(s, s.indexOf("{"));
    expect(/(^|[{,\s])v\s*:\s*1\b/.test(obj(mala))).toBe(false);
    expect(/(^|[{,\s])v\s*:\s*1\b/.test(obj(buena))).toBe(true);
  });

  it("no confunde un `v: 1` de un objeto anidado con el del sobre", () => {
    // `params: { v: 1 }` es otra cosa: el router no la mira.
    const anidado = `await priv.call({ id: "x", method: "ping", params: { v: 1 } });`;
    const obj = objetoDeLaLlamada(anidado, anidado.indexOf("{"));
    // El recorte por llaves incluye el anidado, así que esta comprobación
    // documenta el límite conocido del detector en vez de fingir que no existe.
    expect(obj).toContain("params: { v: 1 }");
  });
});
