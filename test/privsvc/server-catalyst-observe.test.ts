// test/privsvc/server-catalyst-observe.test.ts
//
// ADR-0015 punto 9 — el agente mira la mitad alternativa del SERVIDOR.
//
// ⚠️ LA DIRECCIÓN IMPORTA Y NO ES SIMÉTRICA.
//
// El backend mira el certificado del agente; esto mira el del servidor,
// desde el agente. Lo que protege esta comprobación es la SUPLANTACIÓN
// DEL CONTROL PLANE — el riesgo que dejó abierto la filtración de la
// clave de la Issuing, porque cualquiera que la tenga puede presentar un
// certificado que la CA avala. La mitad post-cuántica no estaba en esa
// filtración, y por eso verificarla vale.
//
// ⚠️ Y ES OBSERVAR, NUNCA CORTAR. Hoy no existe una Issuing híbrida, así
// que ningún servidor puede presentar una mitad alternativa válida. Un
// modo que exigiera algo dejaría a la flota sin canal, y sin canal no hay
// forma de mandarle el arreglo: una visita presencial por equipo. Es el
// mismo criterio con el que se apagó el pinning por defecto.

import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "child_process";
import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";

import {
  classifyCatalyst,
  subjectAltSpkiOf,
  altSignatureValueOf,
  tbsWithoutAltSignatureValue,
  issuerAltSpkiFromBundle
} from "../../privsvc/shared/catalyst";
import { getMlDsaProvider, mlDsaAlgorithmIdentifier } from "../../privsvc/shared/mldsa";
import { seq, tlv, oidFromHex, bitString, octetString, DER_BOOLEAN } from "../../privsvc/shared/der";
import { makeCheckServerIdentity } from "../../privsvc/macos/src/server-pin";

const OPENSSL = process.env.OPENSSL_BIN || "openssl";
let tmp: string;
let caAlt: { spkiDer: Buffer; pkcs8Der: Buffer };

beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "srv-catalyst-"));
  caAlt = getMlDsaProvider().generateKeyPair();
});

// ── Un certificado catalyst, emitido a mano ─────────────────────────
//
// El emisor de verdad vive en el backend. Aquí se construye el mínimo
// necesario para tener un certificado con las tres extensiones y el
// ORDEN correcto, porque lo que se prueba es el LECTOR: que sepa quitar
// la 74 y verificar sobre lo que queda.

function ext(oidHex: string, critical: boolean, value: Buffer): Buffer {
  return seq(
    oidFromHex(oidHex),
    ...(critical ? [tlv(DER_BOOLEAN, Buffer.from([0xff]))] : []),
    octetString(value)
  );
}

function certCatalyst(opts: { conAlt?: boolean; firmaRota?: boolean } = {}): Buffer {
  const conAlt = opts.conAlt !== false;
  const clasica = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = clasica.publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const sujetoAlt = getMlDsaProvider().generateKeyPair();

  const nombre = seq(tlv(0x31, seq(seq(oidFromHex("550403"), tlv(0x0c, Buffer.from("srv"))))));
  const validez = seq(
    tlv(0x17, Buffer.from("260101000000Z", "ascii")),
    tlv(0x17, Buffer.from("270101000000Z", "ascii"))
  );

  const armaTbs = (exts: Buffer[]) =>
    seq(
      tlv(0xa0, tlv(0x02, Buffer.from([0x02]))), // version v3
      tlv(0x02, Buffer.from([0x01])), // serial
      seq(oidFromHex("2a8648ce3d040302")), // ecdsa-with-SHA256
      nombre,
      validez,
      nombre,
      spki,
      tlv(0xa3, seq(...exts))
    );

  const base: Buffer[] = [ext("551d0f", true, tlv(0x03, Buffer.from([0x07, 0x80])))];
  if (!conAlt) {
    const tbs = armaTbs(base);
    return seq(tbs, seq(oidFromHex("2a8648ce3d040302")), bitString(crypto.sign("sha256", tbs, clasica.privateKey)));
  }

  const conAltExts = [
    ...base,
    ext("551d48", false, sujetoAlt.spkiDer),
    ext("551d49", false, mlDsaAlgorithmIdentifier())
  ];
  // El orden catalyst: se firma el TBS SIN la 74.
  const sinAlt74 = armaTbs(conAltExts);
  let firma = getMlDsaProvider().sign(sinAlt74, caAlt.pkcs8Der);
  if (opts.firmaRota) {
    firma = Buffer.from(firma);
    firma[10] ^= 0xff;
  }
  const tbs = armaTbs([...conAltExts, ext("551d4a", false, bitString(firma))]);
  return seq(
    tbs,
    seq(oidFromHex("2a8648ce3d040302")),
    bitString(crypto.sign("sha256", tbs, clasica.privateKey))
  );
}

describe("classifyCatalyst — el veredicto sobre el certificado del servidor", () => {
  it("un certificado CLÁSICO es 'absent', que es todo lo que hay hoy", () => {
    expect(classifyCatalyst(certCatalyst({ conAlt: false }), caAlt.spkiDer)).toBe("absent");
  });

  it("⚠️ uno catalyst firmado por la alt de la CA es 'valid'", () => {
    expect(classifyCatalyst(certCatalyst(), caAlt.spkiDer)).toBe("valid");
  });

  it("⚠️ catalyst SIN alt de CA con la que comparar es 'unverifiable', NO 'invalid'", () => {
    // El estado por el que se pasa: primer servidor híbrido, bundle
    // todavía clásico. Si esto dijera "invalid", el día del cambio el
    // informe diría que el servidor tiene la firma rota y alguien lo
    // creería.
    expect(classifyCatalyst(certCatalyst(), null)).toBe("unverifiable");
  });

  it("⚠️ una firma alternativa corrompida es 'invalid'", () => {
    // Lo que da sentido a 'valid'. Sin esto, 'valid' sólo significaría
    // «trae tres extensiones».
    expect(classifyCatalyst(certCatalyst({ firmaRota: true }), caAlt.spkiDer)).toBe("invalid");
  });

  it("⚠️ la alt de OTRA CA también es 'invalid'", () => {
    const otra = getMlDsaProvider().generateKeyPair();
    expect(classifyCatalyst(certCatalyst(), otra.spkiDer)).toBe("invalid");
  });

  it("basura no lanza", () => {
    expect(classifyCatalyst(Buffer.from([0x30, 0x02, 0x05, 0x00]), null)).toBe("absent");
  });

  it("el TBS sin la 74 conserva las demás extensiones byte a byte", () => {
    // Reconstruir volviendo a codificar los campos anteriores sería
    // «casi» lo mismo, y ese casi es una firma que no verifica sin que
    // nada parezca mal.
    const der = certCatalyst();
    const cuerpo = tbsWithoutAltSignatureValue(der)!;
    expect(cuerpo).not.toBeNull();
    // La SPKI alternativa sigue dentro; la firma alternativa ya no.
    expect(cuerpo.includes(subjectAltSpkiOf(der)!)).toBe(true);
    expect(cuerpo.includes(altSignatureValueOf(der)!)).toBe(false);
  });
});

describe("issuerAltSpkiFromBundle", () => {
  it("un bundle clásico no tiene mitad alternativa, y eso no es un error", () => {
    const p = path.join(tmp, "ca.pem");
    execFileSync(OPENSSL, [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
      "-nodes", "-keyout", path.join(tmp, "ca.key"), "-out", p,
      "-days", "1", "-subj", "/CN=CA clasica"
    ], { stdio: "ignore" });
    expect(issuerAltSpkiFromBundle(fs.readFileSync(p, "utf8"))).toBeNull();
  });

  it("un bundle ilegible tampoco lanza", () => {
    expect(issuerAltSpkiFromBundle("no soy un PEM")).toBeNull();
    expect(issuerAltSpkiFromBundle("")).toBeNull();
  });
});

describe("checkServerIdentity — el cableado", () => {
  it("⚠️ observa la mitad alternativa Y NUNCA corta por ella", () => {
    // La garantía entera del modo observación, probada sobre el peor
    // caso: una firma alternativa inválida. La conexión sigue.
    const vistos: string[] = [];
    const check = makeCheckServerIdentity([], undefined, {
      issuerAltSpki: caAlt.spkiDer,
      observe: (v) => vistos.push(v)
    });

    const cert = {
      raw: certCatalyst({ firmaRota: true }),
      subject: { CN: "localhost" },
      subjectaltname: "DNS:localhost"
    } as never;

    const err = check("localhost", cert);
    expect(vistos).toEqual(["invalid"]);
    // Sin error de identidad ni de pin: el veredicto no participa.
    expect(err).toBeUndefined();
  });

  it("sin la configuración de catalyst no observa nada y se comporta igual", () => {
    // Compatibilidad hacia atrás: los llamadores que no pasen el tercer
    // argumento siguen funcionando exactamente como antes.
    const check = makeCheckServerIdentity([]);
    const cert = { raw: certCatalyst(), subject: { CN: "localhost" }, subjectaltname: "DNS:localhost" } as never;
    expect(check("localhost", cert)).toBeUndefined();
  });

  it("⚠️ la verificación de HOSTNAME de Node sigue mandando", () => {
    // La trampa que server-pin.ts ya documentaba: pasar un
    // checkServerIdentity propio SUSTITUYE al de Node. Añadir la
    // observación catalyst no puede haber abierto ese agujero.
    const check = makeCheckServerIdentity([], undefined, {
      issuerAltSpki: caAlt.spkiDer,
      observe: () => {}
    });
    const cert = { raw: certCatalyst(), subject: { CN: "otro" }, subjectaltname: "DNS:otro-host" } as never;
    expect(check("localhost", cert)).toBeInstanceOf(Error);
  });
});
