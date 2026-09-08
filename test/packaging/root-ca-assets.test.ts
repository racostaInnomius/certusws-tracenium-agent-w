// test/packaging/root-ca-assets.test.ts
//
// ⚠️ LA ROOT QUE SE EMPAQUETA ESTÁ EN DOS SITIOS Y PUEDEN DIVERGIR.
//
// Y divergieron: el commit de D4 (ADR-0015) actualizó el asset del
// PrivSvc a la Root HÍBRIDA y se dejó el del instalador de Windows con la
// clásica. Como macOS y Linux copian del primero y el MSI empaqueta el
// segundo, durante cuatro días las instalaciones nuevas de Windows —la
// mayor parte de la flota— anclaron en una Root sin mitad post-cuántica
// mientras las demás plataformas sí la llevaban.
//
// No fue una avería: las dos Roots comparten la MISMA clave pública y el
// mismo sujeto, que es justo la propiedad aditiva sobre la que se diseñó
// D4, así que la cadena valida igual contra cualquiera de las dos. Lo que
// se perdía era el ancla PQ en el eslabón de arriba, en silencio y sólo
// en una plataforma. Ese "en silencio" es lo que arregla este test.
//
// Ya existía un guardián equivalente en `scripts/build-linux-binaries.sh`
// —que para si encuentra varias Root distintas— pero sólo cubría el
// camino de Linux. Éste cubre las ENTRADAS, que es donde se edita.
//
// Lo de `build/` queda fuera a propósito: son salidas de empaquetado,
// regeneradas en cada build, y exigirles frescura daría rojos que no
// significan nada.

import { describe, it, expect } from "vitest";
import crypto from "crypto";
import fs from "fs";
import path from "path";

const RAIZ = path.join(__dirname, "..", "..");

/**
 * Las copias que son ENTRADA de un empaquetado, con quién las consume.
 * Si alguien añade una tercera, que la añada aquí: el fallo que este
 * fichero previene es exactamente "hay otra copia y nadie la actualizó".
 */
const ENTRADAS = [
  {
    ruta: "privsvc/windows/Tracenium.PrivSvc.Windows/assets/root-ca.crt",
    consume: "el PrivSvc de Windows, y de aquí COPIAN los builds de macOS y Linux"
  },
  {
    ruta: "windows/installer/assets/root-ca.crt",
    consume: "el MSI (bindpath de WiX, PrivSvc.wxs → Source=\"assets\\root-ca.crt\")"
  }
];

function leer(rel: string): Buffer {
  const p = path.join(RAIZ, rel);
  expect(fs.existsSync(p), `falta ${rel}`).toBe(true);
  return fs.readFileSync(p);
}

describe("la Root que se empaqueta", () => {
  it("⚠️ es la MISMA en todas las entradas de empaquetado", () => {
    const huellas = ENTRADAS.map(({ ruta, consume }) => {
      const x = new crypto.X509Certificate(leer(ruta));
      return { ruta, consume, fp: String(x.fingerprint256) };
    });

    const distintas = new Set(huellas.map((h) => h.fp));
    expect(
      distintas.size,
      `hay ${distintas.size} Roots distintas:\n` +
        huellas.map((h) => `  ${h.fp}  ${h.ruta}\n    → la empaqueta ${h.consume}`).join("\n")
    ).toBe(1);
  });

  it("⚠️ es la HÍBRIDA: lleva las tres extensiones catalyst", () => {
    // Se lee del DER y no del volcado de texto de un openssl: la 3.0
    // imprime estas extensiones por OID y la 3.6 por nombre, así que
    // asertar el rótulo ataría el test a la versión de quien lo corra.
    for (const { ruta } of ENTRADAS) {
      const der = new crypto.X509Certificate(leer(ruta)).raw.toString("hex");
      const presentes = ["0603551d48", "0603551d49", "0603551d4a"].filter((o) => der.includes(o));
      expect(presentes.length, `${ruta} no es la Root híbrida`).toBe(3);
    }
  });

  it("⚠️ conserva la clave pública clásica: sin eso el despliegue deja de ser aditivo", () => {
    // La propiedad entera de D4. Si alguien regenera la Root con una
    // clave nueva, la flota que ancla en la vieja deja de validar — y no
    // hay arreglo remoto, porque el ancla viaja en el instalador.
    //
    // El número son los 32 primeros hex de sha256(SPKI en DER), y sale
    // IDÉNTICO en la Root clásica y en la híbrida: es la medida directa
    // de que D4 conservó la clave, comprobada aquí sobre los ficheros y
    // no sobre la palabra de la ceremonia. Para recalcularlo:
    //   node -e 'const c=require("crypto"),f=require("fs");
    //     const x=new c.X509Certificate(f.readFileSync(RUTA));
    //     console.log(c.createHash("sha256")
    //       .update(x.publicKey.export({format:"der",type:"spki"}))
    //       .digest("hex").slice(0,32))'
    const esperada = "05bee878bd9c69d72b0d2092a1a6d4be";
    for (const { ruta } of ENTRADAS) {
      const spki = new crypto.X509Certificate(leer(ruta)).publicKey.export({
        format: "der",
        type: "spki"
      }) as Buffer;
      const h = crypto.createHash("sha256").update(spki).digest("hex").slice(0, 32);
      expect(h, `${ruta} cambió de clave pública`).toBe(esperada);
    }
  });
});
