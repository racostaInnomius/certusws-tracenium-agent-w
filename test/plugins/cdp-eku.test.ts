// test/plugins/cdp-eku.test.ts
//
// Extended Key Usage llega al cable.
//
// ⚠️ EL FALLO QUE ESTO CAZA ESTUVO EN PRODUCCIÓN DESDE LA FASE A. El
// campo `extendedKeyUsage` existía en `CdpCertItem` y ninguna línea lo
// asignaba: la suite entera pasaba, el backend tenía su columna `eku`,
// y la flota llevaba 0 de 6.735 certificados con propósito. Sin EKU no se
// distingue un servidor TLS de un cliente o de una firma de código —
// la dimensión que ordena cualquier plan de migración PQC.
//
// Por eso se prueba con un certificado REAL (generado con openssl y
// commiteado) y no con un DER a mano: lo que hay que garantizar es que
// la ruta de producción —`parseCertToItem` sobre `cert.raw`— rellene el
// campo, no que exista una función que sepa hacerlo.

import { describe, it, expect } from "vitest";
import crypto from "crypto";
import { extractExtendedKeyUsage } from "../../src/plugins/cdp/der";
import { parseCertToItem } from "../../src/plugins/cdp/parse-cert";
import { EKU_FIXTURE_CERT } from "./eku-fixture";
import { FIXTURE_CERT } from "./tls-fixture";

const store = { id: "test", name: "Test", scope: "machine" as const };

describe("extendedKeyUsage", () => {
  it("⭐ un certificado con EKU la lleva en el item, con nombre", () => {
    const item = parseCertToItem(EKU_FIXTURE_CERT, { store });
    expect(item.extendedKeyUsage).toEqual(["serverAuth", "clientAuth", "codeSigning"]);
  });

  it("los OIDs crudos salen del DER en el orden declarado", () => {
    const der = new crypto.X509Certificate(EKU_FIXTURE_CERT).raw;
    expect(extractExtendedKeyUsage(der)).toEqual([
      "1.3.6.1.5.5.7.3.1",
      "1.3.6.1.5.5.7.3.2",
      "1.3.6.1.5.5.7.3.3"
    ]);
  });

  it("sin la extensión el campo va AUSENTE, no vacío", () => {
    // Un `[]` por cada uno de los ~10.000 certificados de la flota solo
    // engorda un payload que ya tiene tope. Ausente es la forma honesta
    // de «no lo declara».
    const item = parseCertToItem(FIXTURE_CERT, { store });
    expect(item.extendedKeyUsage).toBeUndefined();
    expect(extractExtendedKeyUsage(new crypto.X509Certificate(FIXTURE_CERT).raw)).toEqual([]);
  });

  it("un DER roto devuelve vacío y no lanza", () => {
    // El lector parsea entrada NO confiable; el contrato de todo der.ts
    // es no reventar el escaneo por un certificado malformado.
    expect(extractExtendedKeyUsage(Buffer.from([0x30, 0x82, 0xff]))).toEqual([]);
    expect(extractExtendedKeyUsage(Buffer.alloc(0))).toEqual([]);
  });
});
