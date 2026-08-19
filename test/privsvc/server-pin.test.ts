import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { X509Certificate } from "crypto";

import {
  publicKeyPin,
  makeCheckServerIdentity,
  readServerKeyPins,
} from "../../privsvc/macos/src/server-pin";

let dir: string;
let certDer: Buffer;
let opensslPin: string;

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "pin-test-"));
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-sha256",
    "-subj", "/CN=grpc.tracenium.com",
    "-addext", "subjectAltName=DNS:grpc.tracenium.com",
    "-keyout", `${dir}/k.pem`, "-out", `${dir}/c.pem`,
  ], { stdio: "ignore" });

  certDer = Buffer.from(new X509Certificate(fs.readFileSync(`${dir}/c.pem`)).raw);

  // El valor que un operador obtendría con la receta habitual de openssl.
  const pub = execFileSync("openssl", ["x509", "-in", `${dir}/c.pem`, "-pubkey", "-noout"]);
  const der = execFileSync("openssl", ["pkey", "-pubin", "-outform", "der"], { input: pub });
  const digest = execFileSync("openssl", ["dgst", "-sha256", "-binary"], { input: der });
  opensslPin = execFileSync("openssl", ["base64"], { input: digest }).toString().trim();
});

describe("cálculo del pin", () => {
  it("❗ coincide con lo que produce openssl — el valor es interoperable", () => {
    // Si divergiera, el operador configuraría un pin que nunca casaría y el
    // equipo quedaría sin conectar sin motivo aparente.
    expect(publicKeyPin({ raw: certDer })).toBe(opensslPin);
  });

  it("prefiere `pubkey` cuando Node lo entrega, y cae a `raw` si no", () => {
    const spki = new X509Certificate(certDer).publicKey.export({
      type: "spki", format: "der",
    }) as Buffer;
    expect(publicKeyPin({ pubkey: spki })).toBe(opensslPin);
    expect(publicKeyPin({ raw: certDer })).toBe(opensslPin);
  });

  it("devuelve null en vez de adivinar cuando no hay clave legible", () => {
    expect(publicKeyPin(null)).toBeNull();
    expect(publicKeyPin({})).toBeNull();
    expect(publicKeyPin({ raw: Buffer.from([1, 2, 3]) })).toBeNull();
  });
});

/** Certificado con la forma que Node entrega en getPeerCertificate(). */
const peerCert = (over: Record<string, unknown> = {}) => ({
  raw: certDer,
  subject: { CN: "grpc.tracenium.com" },
  subjectaltname: "DNS:grpc.tracenium.com",
  ...over,
});

describe("checkServerIdentity", () => {
  it("sin pins configurados no exige nada, pero OBSERVA el valor", () => {
    const seen: (string | null)[] = [];
    const check = makeCheckServerIdentity([], (pin) => seen.push(pin));
    expect(check("grpc.tracenium.com", peerCert() as never)).toBeUndefined();
    expect(seen).toEqual([opensslPin]);
  });

  it("acepta cuando el pin está en la lista", () => {
    const check = makeCheckServerIdentity([opensslPin]);
    expect(check("grpc.tracenium.com", peerCert() as never)).toBeUndefined();
  });

  it("❗ rechaza cuando la clave pública no coincide con ningún pin", () => {
    const check = makeCheckServerIdentity(["pin-de-otro-servidor="]);
    const err = check("grpc.tracenium.com", peerCert() as never);
    expect(err).toBeInstanceOf(Error);
    expect(err!.message).toMatch(/no coincide/);
  });

  it("admite varios pins, para poder rotar sin cortar la flota", () => {
    const check = makeCheckServerIdentity(["pin-viejo=", opensslPin]);
    expect(check("grpc.tracenium.com", peerCert() as never)).toBeUndefined();
  });

  it("❗ NO pierde la verificación de hostname — la trampa de este API", () => {
    // Pasar un checkServerIdentity propio SUSTITUYE al de Node. Un pinning
    // que sólo mirase el pin habría QUITADO la comprobación de nombre,
    // debilitando la conexión mientras aparenta reforzarla.
    const check = makeCheckServerIdentity([opensslPin]);
    const err = check("otro-host.example.com", peerCert() as never);
    expect(err).toBeInstanceOf(Error);
    expect(err!.message).not.toMatch(/no coincide/); // es el error de Node, no el nuestro
  });

  it("❗ con pins configurados, una clave ilegible se rechaza POR SERLO", () => {
    // Comprobar sólo "que hay error" no bastaba: sin la guarda, el pin nulo
    // simplemente no casaba y salía el error de desajuste. El motivo tiene
    // que ser el correcto, o el diagnóstico en campo apunta al sitio
    // equivocado.
    const check = makeCheckServerIdentity([opensslPin]);
    const err = check("grpc.tracenium.com", peerCert({ raw: undefined }) as never);
    expect(err).toBeInstanceOf(Error);
    expect(err!.message).toMatch(/no se pudo leer la clave pública/);
  });
});

describe("lectura de los pins", () => {
  it("admite lista, cadena separada por comas, o nada", () => {
    expect(readServerKeyPins({ serverKeyPins: ["a", " b "] })).toEqual(["a", "b"]);
    expect(readServerKeyPins({ serverKeyPins: "a, b ,," })).toEqual(["a", "b"]);
    expect(readServerKeyPins({})).toEqual([]);
    expect(readServerKeyPins(null)).toEqual([]);
  });
});

describe("las dos copias del helper", () => {
  it("❗ macos y linux son idénticas — si divergen, una queda sin proteger", () => {
    const a = fs.readFileSync("privsvc/macos/src/server-pin.ts", "utf8");
    const b = fs.readFileSync("privsvc/linux/src/server-pin.ts", "utf8");
    expect(a).toBe(b);
  });
});
