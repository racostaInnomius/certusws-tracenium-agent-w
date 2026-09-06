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
  classifyCatalystChain,
  describeCatalystChain,
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
  // Un certificado catalyst cuya 74 firma su PROPIA clave alternativa:
  // es la forma de una raíz autofirmada, y lo que hace que un recorrido
  // sin `vistos` produzca tramos «válidos» que no existen.
  const auto = getMlDsaProvider().generateKeyPair();
  fs.writeFileSync(path.join(tmp, "auto.der"), certConAlt(auto.spkiDer, auto.pkcs8Der));
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

/** Un certificado catalyst cuyo sujeto declara `sujetoAlt` y cuya 74 firma `emisorAltPkcs8`. */
function certConAlt(sujetoAltSpki: Buffer, emisorAltPkcs8: Buffer): Buffer {
  const clasica = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = clasica.publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const nombre = seq(tlv(0x31, seq(seq(oidFromHex("550403"), tlv(0x0c, Buffer.from("x"))))));
  const validez = seq(
    tlv(0x17, Buffer.from("260101000000Z", "ascii")),
    tlv(0x17, Buffer.from("270101000000Z", "ascii"))
  );
  const armaTbs = (exts: Buffer[]) =>
    seq(
      tlv(0xa0, tlv(0x02, Buffer.from([0x02]))),
      tlv(0x02, Buffer.from([0x01])),
      seq(oidFromHex("2a8648ce3d040302")),
      nombre, validez, nombre, spki,
      tlv(0xa3, seq(...exts))
    );
  const base = [
    ext("551d0f", true, tlv(0x03, Buffer.from([0x07, 0x80]))),
    ext("551d48", false, sujetoAltSpki),
    ext("551d49", false, mlDsaAlgorithmIdentifier())
  ];
  const sinAlt74 = armaTbs(base);
  const firma = getMlDsaProvider().sign(sinAlt74, emisorAltPkcs8);
  const tbs = armaTbs([...base, ext("551d4a", false, bitString(firma))]);
  return seq(
    tbs,
    seq(oidFromHex("2a8648ce3d040302")),
    bitString(crypto.sign("sha256", tbs, clasica.privateKey))
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

// ── La CADENA, que es lo que hace que D4 sirva de algo ─────────────

describe("classifyCatalystChain", () => {
  /** Hoja ← Issuing ← Root, con las firmas alternativas encadenadas. */
  function jerarquia() {
    const rootAlt = getMlDsaProvider().generateKeyPair();
    const issuingAlt = getMlDsaProvider().generateKeyPair();
    const hojaAlt = getMlDsaProvider().generateKeyPair();
    return {
      rootAlt,
      root: certConAlt(rootAlt.spkiDer, rootAlt.pkcs8Der),
      issuing: certConAlt(issuingAlt.spkiDer, rootAlt.pkcs8Der),
      hoja: certConAlt(hojaAlt.spkiDer, issuingAlt.pkcs8Der)
    };
  }

  it("⚠️ los DOS tramos verifican: hoja←Issuing e Issuing←Root", () => {
    const j = jerarquia();
    const r = classifyCatalystChain([j.hoja, j.issuing, j.root]);
    expect(r.verdicts).toEqual(["valid", "valid"]);
    expect(r.depth).toBe(2);
    expect(r.anyInvalid).toBe(false);
  });

  it("⚠️ con Root CLÁSICA el tramo de arriba es 'unverifiable', no 'invalid'", () => {
    // El estado por el que se pasa mientras la Root híbrida no esté en
    // campo. Declararlo inválido diría que la Issuing tiene la firma rota.
    const j = jerarquia();
    const r = classifyCatalystChain([j.hoja, j.issuing, certCatalyst({ conAlt: false })]);
    expect(r.verdicts).toEqual(["valid", "unverifiable"]);
    expect(r.depth).toBe(1);
    expect(r.anyInvalid).toBe(false);
  });

  it("un tramo corrompido se ve aunque el otro esté bien", () => {
    const j = jerarquia();
    const rota = Buffer.from(j.issuing);
    const i = rota.indexOf(Buffer.from("551d4a", "hex"));
    rota[i + 40] ^= 0xff;
    expect(classifyCatalystChain([j.hoja, rota, j.root]).anyInvalid).toBe(true);
  });

  it("una cadena de un solo certificado no tiene tramos", () => {
    expect(classifyCatalystChain([certCatalyst()]).verdicts).toHaveLength(0);
    expect(classifyCatalystChain([]).verdicts).toHaveLength(0);
    expect(describeCatalystChain(classifyCatalystChain([]))).toMatch(/sin tramos/);
  });
});

describe("checkServerIdentity — el cableado", () => {
  it("⚠️ observa la mitad alternativa Y NUNCA corta por ella", () => {
    // La garantía entera del modo observación, probada sobre el peor
    // caso: una firma alternativa inválida. La conexión sigue.
    const vistos: string[] = [];
    const check = makeCheckServerIdentity([], undefined, {
      issuerAltSpki: caAlt.spkiDer,
      observe: (resumen) => vistos.push(resumen)
    });

    const cert = {
      raw: certCatalyst({ firmaRota: true }),
      subject: { CN: "localhost" },
      subjectaltname: "DNS:localhost"
    } as never;

    const err = check("localhost", cert);
    // Sin `issuerCertificate` la cadena tiene un solo certificado: cero
    // tramos. Lo que se comprueba aquí es que OBSERVA y no corta.
    expect(vistos).toHaveLength(1);
    expect(vistos[0]).toMatch(/tramos|profundidad/);
    // Sin error de identidad ni de pin: el veredicto no participa.
    expect(err).toBeUndefined();
  });

  it("⚠️ una raíz que se apunta a sí misma NO inventa tramos", () => {
    // Node hace exactamente esto: en la raíz, `issuerCertificate` apunta
    // al propio certificado.
    //
    // ⚠️ ESTE TEST NACIÓ MIDIENDO LA PROPIEDAD EQUIVOCADA. La primera
    // versión comprobaba que no se colgara, y pasaba con el guard quitado
    // — porque el tope de 10 ya garantiza la terminación. Lo que el guard
    // evita es OTRA cosa: que el mismo certificado entre nueve veces y se
    // informe de una profundidad post-cuántica de 9 sobre una cadena que
    // tiene un eslabón. Un número inventado justo donde el número es lo
    // único que sirve para decidir cuándo exigir.
    const raw = fs.readFileSync(path.join(tmp, "auto.der"));
    const raiz: any = { raw, subject: { CN: "localhost" }, subjectaltname: "DNS:localhost" };
    raiz.issuerCertificate = raiz;

    const vistos: string[] = [];
    const check = makeCheckServerIdentity([], undefined, {
      issuerAltSpki: caAlt.spkiDer,
      observe: (resumen) => vistos.push(resumen)
    });

    check("localhost", raiz);
    expect(vistos).toHaveLength(1);
    // Un solo certificado ⇒ CERO tramos. Con el guard quitado saldrían 9.
    expect(vistos[0]).toMatch(/sin tramos/);
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
