// test/plugins/cdp-private-key-info.test.ts
//
// Ola 1.1 — claves privadas sueltas: PRESENCIA sin material.
//
// Dos propiedades importan:
//   1. El hash de la parte pública que sacamos de la estructura de la
//      clave es EXACTAMENTE el `publicKeyHash` de su certificado (sha256
//      de la SPKI). Si no, «casa con este certificado» sería inventado.
//      Se compara contra la SPKI que exporta Node de la clave pública,
//      que es la fuente independiente.
//   2. Una clave cifrada se dice cifrada y nada más: ni algoritmo
//      deducido, ni hash, ni intento de descifrar.
//
// Las claves se generan en el test con el crypto de Node: variantes reales
// (PKCS#8, PKCS#1, SEC1, cifradas), no las que nuestro código sabría escribir.

import { describe, it, expect } from "vitest";
import crypto from "crypto";
import { describePrivateKeys, looksLikeDerPrivateKey } from "../../src/plugins/cdp/private-key-info";

const spkiHashOf = (key: crypto.KeyObject) =>
  crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");

describe("describePrivateKeys", () => {
  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const ec = crypto.generateKeyPairSync("ec", { namedCurve: "P-384" });
  const ed = crypto.generateKeyPairSync("ed25519");

  it("⭐ RSA PKCS#8: tipo, tamaño y el MISMO hash que la SPKI de su certificado", () => {
    const pem = rsa.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    const [k] = describePrivateKeys(Buffer.from(pem));
    expect(k).toMatchObject({ format: "pkcs8", encrypted: false, readable: true, keyAlgorithm: "RSA", keySizeBits: 2048 });
    expect(k.publicKeyHash).toBe(spkiHashOf(rsa.publicKey));
  });

  it("RSA PKCS#1 (BEGIN RSA PRIVATE KEY): mismo hash", () => {
    const pem = rsa.privateKey.export({ type: "pkcs1", format: "pem" }) as string;
    const [k] = describePrivateKeys(Buffer.from(pem));
    expect(k).toMatchObject({ format: "pkcs1", keyAlgorithm: "RSA", keySizeBits: 2048 });
    expect(k.publicKeyHash).toBe(spkiHashOf(rsa.publicKey));
  });

  it("EC SEC1 y EC PKCS#8: curva y hash desde la clave PÚBLICA que traen en claro", () => {
    const sec1 = describePrivateKeys(Buffer.from(ec.privateKey.export({ type: "sec1", format: "pem" }) as string))[0];
    expect(sec1).toMatchObject({ format: "sec1", keyAlgorithm: "EC", curve: "P-384", keySizeBits: 384 });
    expect(sec1.publicKeyHash).toBe(spkiHashOf(ec.publicKey));

    const p8 = describePrivateKeys(Buffer.from(ec.privateKey.export({ type: "pkcs8", format: "pem" }) as string))[0];
    expect(p8).toMatchObject({ format: "pkcs8", keyAlgorithm: "EC", curve: "P-384" });
    expect(p8.publicKeyHash).toBe(spkiHashOf(ec.publicKey));
  });

  it("Ed25519 PKCS#8 v1 (sin clave pública): algoritmo sí, hash no — no se deriva de la privada", () => {
    const [k] = describePrivateKeys(Buffer.from(ed.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
    expect(k.keyAlgorithm).toBe("Ed25519");
    expect(k.publicKeyHash).toBeUndefined();
  });

  it("⭐ PKCS#8 cifrado: «cifrada» y nada más", () => {
    const pem = rsa.privateKey.export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase: "x" }) as string;
    const [k] = describePrivateKeys(Buffer.from(pem));
    expect(k).toEqual({ format: "pkcs8-encrypted", encrypted: true, readable: true });
  });

  it("PEM heredado cifrado (Proc-Type): tipo por la etiqueta, sin hash", () => {
    const pem = rsa.privateKey.export({ type: "pkcs1", format: "pem", cipher: "aes-128-cbc", passphrase: "x" }) as string;
    const [k] = describePrivateKeys(Buffer.from(pem));
    expect(k).toEqual({ format: "pem-encrypted", encrypted: true, readable: true, keyAlgorithm: "RSA" });
  });

  it("DER sin armadura: PKCS#8 claro y cifrado", () => {
    const der = rsa.privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
    expect(looksLikeDerPrivateKey(der)).toBe(true);
    expect(describePrivateKeys(der)[0]).toMatchObject({ format: "pkcs8", keySizeBits: 2048, publicKeyHash: spkiHashOf(rsa.publicKey) });
    const enc = rsa.privateKey.export({ type: "pkcs8", format: "der", cipher: "aes-256-cbc", passphrase: "x" }) as Buffer;
    expect(describePrivateKeys(enc)).toEqual([{ format: "pkcs8-encrypted", encrypted: true, readable: true }]);
  });

  it("⭐ nada de la descripción contiene material de la clave", () => {
    const der = rsa.privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
    const jwk = rsa.privateKey.export({ format: "jwk" }) as any;
    const out = JSON.stringify(describePrivateKeys(der));
    // Ni el exponente privado ni los primos, en ninguna codificación habitual.
    for (const secret of [jwk.d, jwk.p, jwk.q]) {
      const hex = Buffer.from(secret, "base64url").toString("hex");
      expect(out).not.toContain(secret);
      expect(out).not.toContain(hex.slice(0, 32));
    }
  });

  it("un certificado o un fichero cualquiera no es una clave", () => {
    expect(describePrivateKeys(Buffer.from("hola"))).toEqual([]);
    const cert = Buffer.from("3003020100", "hex");
    expect(describePrivateKeys(cert)).toEqual([]);
  });
});
