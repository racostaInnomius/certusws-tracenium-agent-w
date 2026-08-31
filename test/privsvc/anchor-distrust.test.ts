// test/privsvc/anchor-distrust.test.ts
//
// Emparejar un certificado por huella dentro de la salida de
// `security find-certificate -a -Z -p`. ADR-0011 decision 10.
//
// Por que importa tanto un parser: es lo que decide SOBRE QUE
// certificado se actua. Emparejar mal aqui significa marcar como no
// confiable una CA distinta de la que pidio el operador — en el mejor
// caso una molestia, en el peor romper TLS en el equipo. El resto del
// modulo son dos `security` y comprobaciones; esto es la unica logica.

import { describe, it, expect } from "vitest";
import { extractPemBySha1 } from "../../privsvc/macos/src/anchor-distrust";

const pem = (marker: string) =>
  `-----BEGIN CERTIFICATE-----\n${marker}\n-----END CERTIFICATE-----`;

/** Forma real de la salida: bloques encabezados por "SHA-1 hash:". */
const listing = [
  `SHA-1 hash: AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555`,
  `    "labl"<blob>="Primera CA"`,
  pem("UFJJTUVSQQ=="),
  `SHA-1 hash: FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000`,
  `    "labl"<blob>="Segunda CA"`,
  pem("U0VHVU5EQQ==")
].join("\n");

describe("extractPemBySha1", () => {
  it("devuelve el PEM del bloque cuya huella coincide", () => {
    const r = extractPemBySha1(listing, "FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000");
    expect(r?.pem).toContain("U0VHVU5EQQ==");
    expect(r?.subject).toBe("Segunda CA");
  });

  it("NO devuelve el primer bloque por descuido", () => {
    // El fallo clasico de un parser de bloques: encontrar la huella y
    // devolver el PEM equivocado porque la regex barre todo el texto en
    // vez del bloque. Aqui costaria desconfiar de la CA que no era.
    const r = extractPemBySha1(listing, "FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000");
    expect(r?.pem).not.toContain("UFJJTUVSQQ==");
  });

  it("ignora separadores y mayusculas de la huella pedida", () => {
    // `security` imprime con espacios y la UI puede mandar minusculas o
    // con dos puntos; una diferencia de formato no puede impedir una
    // remediacion.
    const r = extractPemBySha1(listing, "aaaa1111:bbbb2222:cccc3333:dddd4444:eeee5555");
    expect(r?.subject).toBe("Primera CA");
  });

  it("devuelve null si la huella no esta", () => {
    // Es la salvaguarda 2: sin certificado presente no hay confianza que
    // retirar, y el handler se niega en vez de inventarse una operacion.
    expect(extractPemBySha1(listing, "0".repeat(40))).toBeNull();
  });

  it("devuelve null si el bloque no trae PEM", () => {
    const roto = `SHA-1 hash: AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555\n    "labl"<blob>="Sin PEM"`;
    expect(extractPemBySha1(roto, "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555")).toBeNull();
  });

  it("aguanta una salida vacia", () => {
    expect(extractPemBySha1("", "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555")).toBeNull();
  });

  it("tolera que falte la etiqueta", () => {
    // El subject es para el log y la respuesta; su ausencia no puede
    // impedir la operacion.
    const sinLabel = [
      `SHA-1 hash: AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555`,
      pem("U0lOTEFCRUw=")
    ].join("\n");
    const r = extractPemBySha1(sinLabel, "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555");
    expect(r?.pem).toContain("U0lOTEFCRUw=");
    expect(r?.subject).toBeNull();
  });
});
