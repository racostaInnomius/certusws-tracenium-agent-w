// test/privsvc/cert-renew-forwards-install.test.ts
//
// Censo: la renovación de Windows reenvía al agente lo que la instalación
// devuelve y el agente lee.
//
// 🔴 EL APAGÓN (14-sep, MSIG-VEEAM-PC): `CryptoCertInstall.cs` calculaba
// `issuingCaThumbprints` —todas las intermedias del bundle— y
// `CryptoCertRenew.cs`, que la llama en proceso y arma SU PROPIO objeto de
// respuesta, sólo copiaba la singular. El agente se quedó aceptando únicamente
// la G2, rechazó al servidor (cert en la Issuing vieja) y desapareció sin
// arreglo remoto. «Las tres listas», séptima vez: un campo que existe en un
// eslabón y se pierde en el siguiente.
//
// Tras el arreglo, quitar esa línea NO rompía ningún test (15-sep): lo tapaba
// la unión de `mergeIssuingCaThumbprints`. Y desde que una lista presente
// MANDA, esa línea es la única que lleva la lista autoritativa: sin ella, un
// Windows no podría retirar nunca la Issuing filtrada.
//
// Se lee el FUENTE de los tres ficheros y se derivan los campos, en vez de
// listarlos aquí: el campo que alguien añada mañana a la instalación y el
// agente empiece a leer tiene que aparecer en la renovación, o este test falla.

import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";

const RAIZ = path.resolve(__dirname, "../..");
const leer = (rel: string) => fs.readFileSync(path.join(RAIZ, rel), "utf8");

/** Quita comentarios `//` y `/* *\/`: un comentario que nombra un campo no lo reenvía. */
function sinComentarios(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

/**
 * Las claves del objeto anónimo `var result = new { … };` de un handler C#.
 * Acepta las dos formas: `clave = expresión,` y la abreviada `clave,`.
 */
function clavesDelResultado(rel: string): Set<string> {
  const src = sinComentarios(leer(rel));
  const ini = src.indexOf("var result = new");
  expect(ini, `${rel}: no se encontró «var result = new»`).toBeGreaterThan(0);
  expect(src.indexOf("var result = new", ini + 1), `${rel}: hay más de un «var result = new»`).toBe(-1);
  const cuerpo = src.slice(src.indexOf("{", ini) + 1, src.indexOf("};", ini));
  const claves = new Set<string>();
  for (const linea of cuerpo.split("\n")) {
    const m = /^\s*([A-Za-z_]\w*)\s*(?:=(?!=)|,|$)/.exec(linea);
    if (m) claves.add(m[1]);
  }
  return claves;
}

/** Lo que `cert-renewal.ts` lee de la respuesta de `crypto.cert.renew`. */
function camposQueLeeElAgente(): Set<string> {
  const src = sinComentarios(leer("src/bootstrap/cert-renewal.ts"));
  const campos = new Set<string>();
  for (const m of src.matchAll(/\(?result(?:\s+as\s+any\))?\.(\w+)/g)) campos.add(m[1]);
  // La lista y la singular las lee `mergeIssuingCaThumbprints` a través de su
  // parámetro `renewed`: se derivan de su firma, no se escriben aquí.
  const firma = /renewed:\s*\{([^}]*)\}/.exec(src);
  expect(firma, "no se encontró la firma de mergeIssuingCaThumbprints").toBeTruthy();
  for (const m of firma![1].matchAll(/(\w+)\?:/g)) campos.add(m[1]);
  return campos;
}

describe("la renovación de Windows no pierde lo que la instalación calcula", () => {
  const instala = clavesDelResultado("privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CryptoCertInstall.cs");
  const renueva = clavesDelResultado("privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CryptoCertRenew.cs");
  const leeElAgente = camposQueLeeElAgente();
  const importan = [...instala].filter((k) => leeElAgente.has(k));

  it("el censo mira de verdad: encuentra los campos que sabemos que existen", () => {
    // Sin esto, un regex roto dejaría `importan` vacío y el test de abajo
    // pasaría por vacío — el fallo exacto que un censo existe para evitar.
    expect(importan).toEqual(expect.arrayContaining(["clientCertThumbprint", "issuingCaThumbprint", "issuingCaThumbprints"]));
  });

  it("⭐ todo campo que devuelve la instalación y lee el agente, la renovación lo reenvía", () => {
    const perdidos = importan.filter((k) => !renueva.has(k));
    expect(perdidos, "la renovación de Windows no reenvía estos campos de la instalación").toEqual([]);
  });
});
