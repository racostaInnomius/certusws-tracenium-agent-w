// test/plugins/cdp-java-stores.test.ts
//
// CDP Java keystore support:
//   1. jks.ts parses trusted-cert AND private-key entries from a JKS
//      binary WITHOUT any password (we build the binary by hand here —
//      no Java needed on the test machine).
//   2. collectJavaStores discovers cacerts under a JVM-home layout,
//      inventories operator-configured keystores, marks scopes and
//      hasPrivateKey correctly, and surfaces unreadable stores as
//      storeErrors instead of failing the scan.

import { describe, it, expect } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { looksLikeJks, parseJks, JksParseError } from "../../src/plugins/cdp/jks";
import { collectJavaStores, discoverJavaCacerts } from "../../src/plugins/cdp/providers/java-stores";
import type { AgentContext } from "../../src/core/agent-context";

// Self-signed fixture generated with openssl (CN=cdp-test-fixture.example.com,
// O=Tracenium Test, RSA 2048, sha256). Public cert only — no key material.
const FIXTURE_PEM = `-----BEGIN CERTIFICATE-----
MIIDYTCCAkmgAwIBAgIUNZqjbex62JY10l2MgHRnBVbnzfIwDQYJKoZIhvcNAQEL
BQAwQDElMCMGA1UEAwwcY2RwLXRlc3QtZml4dHVyZS5leGFtcGxlLmNvbTEXMBUG
A1UECgwOVHJhY2VuaXVtIFRlc3QwHhcNMjYwNzIyMTQzMjMzWhcNMjcwODI2MTQz
MjMzWjBAMSUwIwYDVQQDDBxjZHAtdGVzdC1maXh0dXJlLmV4YW1wbGUuY29tMRcw
FQYDVQQKDA5UcmFjZW5pdW0gVGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMkkjEUfuT9v7/HYdoJlH9XVI7bTOd5qS14G5+a/LMUBPBGVMWCht6+d
NOE1J4sT0PDw5GG36tAV510p5EIk4Y0kpLdNK3NFR0owI/mpZpCtXPGQabE9sgWy
i+Ynp4zE32ljqHOvC57KmhjFilJgb2oP7fwyjDbyVgUcN0dnSA5+HoJtspYf/ePx
CjGINuvBRLWYmIwIOJZmXilSVkRrxiIvqgp9+b0ob3kb6kSAk55od/+NPDQvg+xX
GPYNzFrdAK+qavsL7/NQnsKTP7mA7Tm+GDRSK4J8Kf6c9l5kyhcITDpK+06L6GL7
77IH6NPYMzEZwsbKkD2XZI9r6vPl54kCAwEAAaNTMFEwHQYDVR0OBBYEFO1oAjxg
hY75IEwG88Y40pYjcRDvMB8GA1UdIwQYMBaAFO1oAjxghY75IEwG88Y40pYjcRDv
MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAE7j3wJrh86CUA6j
ARb28HGZ5cfJoSAFPwXFIcRRhrtNXlOYCqbrQJ4g/73cbc2ahOH67YdlUAsCB21U
TunPak/wfSJ7OxTpvy6OJZccoArutey/va8uk5xM1Ssy1JG4loeAg3gIxS9hga9Z
G8MRYXlMpnyC7YDonsi0u4zaFscaEoOVjQOHxGAzbqMkQh2TYMcZmUMGPJ7MyWNl
++RjRdwJcuV03DgXlpqD8O1xWjNzkD/LOH5KJGC6ELRa8YCH288WcjYHntYPMDbL
W0ocGGQX3K84/4x6sweXRjVjXmC4E8hsc3kpZZBk1DnZU79GYIdZwcfud/xpJevJ
0bntNaY=
-----END CERTIFICATE-----`;

const FIXTURE_DER = Buffer.from(
  FIXTURE_PEM.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, ""),
  "base64"
);

// ── tiny JKS v2 writer (mirrors the format doc in src/plugins/cdp/jks.ts) ──

function u2(n: number) { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; }
function u4(n: number) { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; }
function u8(n: number) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; }
function utf(s: string) { const bytes = Buffer.from(s, "utf8"); return Buffer.concat([u2(bytes.length), bytes]); }

function buildJks(entries: Array<
  | { type: "trusted"; alias: string; der: Buffer }
  | { type: "key"; alias: string; chain: Buffer[] }
>): Buffer {
  const parts: Buffer[] = [u4(0xfeedfeed), u4(2), u4(entries.length)];
  for (const e of entries) {
    if (e.type === "trusted") {
      parts.push(u4(2), utf(e.alias), u8(1750000000000), utf("X.509"), u4(e.der.length), e.der);
    } else {
      const fakeEncryptedKey = Buffer.alloc(64, 0xab); // opaque blob, parser must skip it
      parts.push(
        u4(1), utf(e.alias), u8(1750000000000),
        u4(fakeEncryptedKey.length), fakeEncryptedKey,
        u4(e.chain.length),
        ...e.chain.flatMap((der) => [utf("X.509"), u4(der.length), der])
      );
    }
  }
  parts.push(Buffer.alloc(20, 0x00)); // fake trailing MAC — parser ignores it
  return Buffer.concat(parts);
}

function makeCtx(): AgentContext {
  return {
    policyRuntime: { getCdpJavaKeystorePaths: () => [] },
    logger: { warn: () => {}, debug: () => {}, info: () => {} }
  } as unknown as AgentContext;
}

describe("jks parser", () => {
  it("parses trusted and key entries without any password", () => {
    const jks = buildJks([
      { type: "trusted", alias: "rootca", der: FIXTURE_DER },
      { type: "key", alias: "server", chain: [FIXTURE_DER, FIXTURE_DER] }
    ]);

    expect(looksLikeJks(jks)).toBe(true);

    const entries = parseJks(jks);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ alias: "rootca", type: "trusted" });
    expect(entries[0].certsDer).toHaveLength(1);
    expect(entries[1]).toMatchObject({ alias: "server", type: "key" });
    expect(entries[1].certsDer).toHaveLength(2);
    // DER round-trips byte-identical (nothing decrypted, nothing mutated).
    expect(entries[1].certsDer[0].equals(FIXTURE_DER)).toBe(true);
  });

  it("rejects non-JKS input and truncated files", () => {
    expect(looksLikeJks(Buffer.from("3082aabb", "hex"))).toBe(false);
    expect(() => parseJks(Buffer.from("00010203040506070809", "hex"))).toThrow(JksParseError);

    const valid = buildJks([{ type: "trusted", alias: "a", der: FIXTURE_DER }]);
    expect(() => parseJks(valid.subarray(0, 40))).toThrow(JksParseError);
  });
});

describe("collectJavaStores", () => {
  function tmpLayout() {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-java-"));
    const home = path.join(base, "jvms", "testjdk-1.0");
    fs.mkdirSync(path.join(home, "lib", "security"), { recursive: true });
    return { base, home };
  }

  it("discovers cacerts under a JVM layout and parses configured keystores", async () => {
    const { base, home } = tmpLayout();
    const cacertsPath = path.join(home, "lib", "security", "cacerts");
    fs.writeFileSync(cacertsPath, buildJks([{ type: "trusted", alias: "rootca", der: FIXTURE_DER }]));

    const appKeystore = path.join(base, "app-keystore.jks");
    fs.writeFileSync(appKeystore, buildJks([{ type: "key", alias: "tomcat", chain: [FIXTURE_DER] }]));

    const roots = [{ parent: path.join(base, "jvms") }];
    expect(discoverJavaCacerts(roots)).toHaveLength(1);

    const result = await collectJavaStores(makeCtx(), {
      roots,
      keystorePaths: [appKeystore]
    });

    expect(result.storeErrors).toEqual([]);
    expect(result.stores).toHaveLength(2);

    const cacertsStore = result.stores.find((s) => s.id.startsWith("java/cacerts/"))!;
    const appStore = result.stores.find((s) => s.id.startsWith("java/keystore/"))!;
    expect(cacertsStore.scope).toBe("system-roots");
    expect(appStore.scope).toBe("machine");

    expect(result.items).toHaveLength(2);
    for (const item of result.items) {
      expect(item.source).toBe("java-store");
      expect(item.subjectCN).toBe("cdp-test-fixture.example.com");
      expect(item.fingerprint256).toMatch(/^[0-9a-f]{64}$/);
    }

    // The app keystore's key entry marks its leaf as key-bearing; the
    // trusted root in cacerts does not.
    const appItem = result.items.find((i) => i.store.id === appStore.id)!;
    const rootItem = result.items.find((i) => i.store.id === cacertsStore.id)!;
    expect(appItem.hasPrivateKey).toBe(true);
    expect(rootItem.hasPrivateKey).toBe(false);
  });

  it("reports missing/corrupt configured keystores as storeErrors, not failures", async () => {
    const { base } = tmpLayout(); // no cacerts file created → no JVM stores
    const corrupt = path.join(base, "corrupt.jks");
    fs.writeFileSync(corrupt, Buffer.concat([Buffer.from("feedfeed", "hex"), Buffer.from("00", "hex")]));

    const result = await collectJavaStores(makeCtx(), {
      roots: [{ parent: path.join(base, "jvms") }],
      keystorePaths: [corrupt, path.join(base, "does-not-exist.jks")]
    });

    expect(result.items).toEqual([]);
    expect(result.stores).toEqual([]);
    expect(result.storeErrors).toHaveLength(2);
    // storeErrors record the resolved realpath (on macOS /var → /private/var).
    expect(result.storeErrors.map((e) => e.store)).toContain(fs.realpathSync(corrupt));
  });
});
