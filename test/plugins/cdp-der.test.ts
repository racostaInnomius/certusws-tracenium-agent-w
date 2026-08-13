// test/plugins/cdp-der.test.ts
//
// The DER algorithm-OID reader (ADR-0004, e-F1).
//
// This exists because the previous implementation reported NOTHING: on
// the pilot fleet, 2129 certificates had no signature algorithm recorded,
// so the `weak_sig` hygiene flag could never fire and the compliance
// check reading it passed on evidence that did not exist. The tests
// therefore pin two things equally hard:
//   1. that real certificates now yield their algorithms, and
//   2. that malformed input returns null instead of throwing — this
//      parses untrusted bytes collected from endpoints.

import { describe, it, expect } from "vitest";
import crypto from "crypto";
import { readTlv, children, decodeOid, extractAlgorithmOids } from "../../src/plugins/cdp/der";
import { algorithmName, curveName } from "../../src/plugins/cdp/algorithm-oids";
import { parseCertToItem } from "../../src/plugins/cdp/parse-cert";
import { FIXTURE_CERT } from "./tls-fixture";

const FIXTURE_DER = new crypto.X509Certificate(FIXTURE_CERT).raw;
const STORE = { id: "test/store", name: "Test", scope: "machine" as const };

describe("readTlv", () => {
  it("reads short-form lengths", () => {
    // SEQUENCE, length 3, contents 01 02 03
    const tlv = readTlv(Buffer.from("30030102 03".replace(/\s/g, ""), "hex"), 0)!;
    expect(tlv).toMatchObject({ tag: 0x30, start: 2, end: 5, next: 5 });
  });

  it("reads long-form lengths", () => {
    // SEQUENCE, 0x81 => one length byte, 0x80 = 128 bytes of content
    const buf = Buffer.concat([Buffer.from("308180", "hex"), Buffer.alloc(128)]);
    const tlv = readTlv(buf, 0)!;
    expect(tlv.start).toBe(3);
    expect(tlv.end).toBe(131);
  });

  it("rejects indefinite length (legal in BER, forbidden in DER)", () => {
    expect(readTlv(Buffer.from("3080", "hex"), 0)).toBeNull();
  });

  it("rejects a length that runs past the buffer", () => {
    expect(readTlv(Buffer.from("30ff", "hex"), 0)).toBeNull();
    expect(readTlv(Buffer.from("3005010203", "hex"), 0)).toBeNull();
  });

  it("rejects truncated and out-of-range offsets", () => {
    expect(readTlv(Buffer.from("30", "hex"), 0)).toBeNull();
    expect(readTlv(Buffer.alloc(0), 0)).toBeNull();
    expect(readTlv(Buffer.from("3003010203", "hex"), -1)).toBeNull();
    expect(readTlv(Buffer.from("3003010203", "hex"), 99)).toBeNull();
  });
});

describe("children", () => {
  it("walks direct children in order", () => {
    // SEQUENCE { INTEGER 01, INTEGER 02 }
    const buf = Buffer.from("3006020101020102", "hex");
    const kids = children(buf, readTlv(buf, 0)!);
    expect(kids).toHaveLength(2);
    expect(kids.map((k) => k.tag)).toEqual([0x02, 0x02]);
  });

  it("stops at a child that would overrun its parent instead of reading siblings", () => {
    // Parent claims 3 bytes but the child claims 10.
    const buf = Buffer.from("3003020a01", "hex");
    expect(children(buf, readTlv(buf, 0)!)).toEqual([]);
  });

  it("returns nothing for an empty constructed value", () => {
    const buf = Buffer.from("3000", "hex");
    expect(children(buf, readTlv(buf, 0)!)).toEqual([]);
  });
});

describe("decodeOid", () => {
  const oidOf = (hex: string) => {
    const buf = Buffer.from(hex, "hex");
    return decodeOid(buf, readTlv(buf, 0)!);
  };

  it("decodes single-byte arcs", () => {
    // 2.5.4.3 (commonName)
    expect(oidOf("0603550403")).toBe("2.5.4.3");
  });

  it("decodes multi-byte (base-128) arcs", () => {
    // 1.2.840.113549.1.1.11 — sha256WithRSAEncryption
    expect(oidOf("06092a864886f70d01010b")).toBe("1.2.840.113549.1.1.11");
  });

  it("decodes the NIST CSOR arc used by post-quantum algorithms", () => {
    // 2.16.840.1.101.3.4.3.17 — ML-DSA-44
    expect(oidOf("0609608648016503040311")).toBe("2.16.840.1.101.3.4.3.17");
  });

  it("rejects a non-OID tag, an empty value and a dangling continuation", () => {
    expect(oidOf("020103")).toBeNull(); // INTEGER, not OID
    expect(oidOf("0600")).toBeNull();
    // 0x55 = 85 -> first arc 85/40 = 2, second 85%40 = 5.
    expect(oidOf("060155")).toBe("2.5");
    // 0x80 sets the continuation bit with nothing after it.
    expect(oidOf("0602 5580".replace(/\s/g, ""))).toBeNull();
  });
});

describe("extractAlgorithmOids", () => {
  it("pulls both algorithm OIDs out of a real certificate", () => {
    const oids = extractAlgorithmOids(FIXTURE_DER);
    expect(oids.publicKeyOid).toBe("1.2.840.113549.1.1.1"); // rsaEncryption
    expect(oids.signatureOid).toBe("1.2.840.113549.1.1.11"); // sha256WithRSA
  });

  it("returns nulls — never throws — on junk input", () => {
    for (const bad of [
      Buffer.alloc(0),
      Buffer.from("00", "hex"),
      Buffer.from("deadbeef", "hex"),
      Buffer.from("3080", "hex"),
      Buffer.alloc(64, 0xff),
      FIXTURE_DER.subarray(0, 20) // truncated mid-certificate
    ]) {
      expect(() => extractAlgorithmOids(bad)).not.toThrow();
      expect(extractAlgorithmOids(bad).publicKeyOid).toBeNull();
    }
  });

  it("rejects a non-buffer without throwing", () => {
    expect(extractAlgorithmOids(undefined as any).signatureOid).toBeNull();
  });
});

describe("algorithmName", () => {
  it("names classical and post-quantum algorithms", () => {
    expect(algorithmName("1.2.840.113549.1.1.1")).toBe("RSA");
    expect(algorithmName("1.2.840.113549.1.1.5")).toBe("sha1WithRSAEncryption");
    expect(algorithmName("2.16.840.1.101.3.4.3.17")).toBe("ML-DSA-44");
    expect(algorithmName("2.16.840.1.101.3.4.3.20")).toBe("SLH-DSA-SHA2-128s");
    expect(curveName("1.2.840.10045.3.1.7")).toBe("P-256");
  });

  it("surfaces an uncatalogued OID instead of dropping it", () => {
    // The whole point: an algorithm this build has never heard of must
    // stay visible so the control plane can classify it later.
    expect(algorithmName("1.3.9999.1")).toBe("oid:1.3.9999.1");
    expect(algorithmName(null)).toBeUndefined();
  });
});

describe("parseCertToItem — the blind spot this closes", () => {
  it("now reports the signature algorithm that was previously always missing", () => {
    const item = parseCertToItem(FIXTURE_CERT, { store: STORE })!;
    expect(item.signatureAlgorithm).toBe("sha256WithRSAEncryption");
    expect(item.keyAlgorithm).toBe("RSA");
    expect(item.keySizeBits).toBe(2048);
  });

  it("carries the raw OIDs for server-side classification", () => {
    const item = parseCertToItem(FIXTURE_CERT, { store: STORE })!;
    expect(item.publicKeyOid).toBe("1.2.840.113549.1.1.1");
    expect(item.signatureOid).toBe("1.2.840.113549.1.1.11");
  });
});
