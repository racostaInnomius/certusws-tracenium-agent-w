// src/plugins/cdp/jks.ts
//
// Minimal pure-JS reader for the Java KeyStore (JKS) binary format.
//
// Why no password is needed: in JKS the store password only feeds the
// trailing integrity MAC and the encryption of PRIVATE KEY blobs.
// Certificates — both trusted-cert entries and the cert chains attached
// to key entries — are stored in PLAINTEXT DER. We read exactly those
// and skip the encrypted key bytes entirely, so this parser can never
// surface key material even by accident (it never decrypts anything).
//
// Format (JDK sun.security.provider.JavaKeyStore):
//   u4  magic   = 0xFEEDFEED
//   u4  version = 1 | 2
//   u4  entryCount
//   entry:
//     u4  tag             1 = private-key entry, 2 = trusted-cert entry
//     UTF alias           (u2 length + modified-UTF-8 bytes)
//     u8  timestampMillis
//     tag 1:
//       u4 keyLength, key bytes          (encrypted — SKIPPED, never read)
//       u4 chainLength
//       chain entry: [v2: UTF certType]  (always "X.509" in practice)
//                    u4 certLength, DER bytes
//     tag 2:
//       [v2: UTF certType]
//       u4 certLength, DER bytes
//   trailing SHA-1 MAC (20 bytes) — ignored, we don't verify integrity.
//
// PKCS12-format stores (JDK 9+ default; cacerts since JDK 18) do NOT
// match the magic and must go through the keytool fallback in
// java-stores.ts.

export const JKS_MAGIC = 0xfeedfeed;

export type JksEntry = {
  alias: string;
  timestampMs: number;
  type: "trusted" | "key";
  /** DER certificates. For key entries: the chain, leaf first. */
  certsDer: Buffer[];
};

export class JksParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JksParseError";
  }
}

class Cursor {
  offset = 0;
  constructor(private readonly buf: Buffer) {}

  private ensure(bytes: number) {
    if (this.offset + bytes > this.buf.length) {
      throw new JksParseError(
        `truncated JKS: need ${bytes} bytes at offset ${this.offset}, have ${this.buf.length - this.offset}`
      );
    }
  }

  u2(): number {
    this.ensure(2);
    const v = this.buf.readUInt16BE(this.offset);
    this.offset += 2;
    return v;
  }

  u4(): number {
    this.ensure(4);
    const v = this.buf.readUInt32BE(this.offset);
    this.offset += 4;
    return v;
  }

  u8ms(): number {
    this.ensure(8);
    // Timestamps are epoch millis — comfortably inside Number range.
    const v = this.buf.readBigUInt64BE(this.offset);
    this.offset += 8;
    return Number(v);
  }

  bytes(len: number): Buffer {
    this.ensure(len);
    const v = this.buf.subarray(this.offset, this.offset + len);
    this.offset += len;
    return v;
  }

  utf(): string {
    const len = this.u2();
    // Aliases are ASCII in practice; plain utf8 decoding of
    // modified-UTF-8 only diverges on NUL and supplementary chars.
    return this.bytes(len).toString("utf8");
  }
}

export function looksLikeJks(buf: Buffer): boolean {
  return buf.length >= 8 && buf.readUInt32BE(0) === JKS_MAGIC;
}

const MAX_ENTRIES = 10000;
const MAX_CHAIN = 32;

export function parseJks(buf: Buffer): JksEntry[] {
  const cur = new Cursor(buf);

  if (cur.u4() !== JKS_MAGIC) {
    throw new JksParseError("not a JKS file (bad magic)");
  }
  const version = cur.u4();
  if (version !== 1 && version !== 2) {
    throw new JksParseError(`unsupported JKS version ${version}`);
  }

  const count = cur.u4();
  if (count > MAX_ENTRIES) {
    throw new JksParseError(`entry count ${count} exceeds sanity cap`);
  }

  const entries: JksEntry[] = [];

  for (let i = 0; i < count; i++) {
    const tag = cur.u4();
    const alias = cur.utf();
    const timestampMs = cur.u8ms();

    if (tag === 1) {
      // Private-key entry: skip the encrypted key blob without reading it
      // into anything we return.
      const keyLen = cur.u4();
      cur.bytes(keyLen);

      const chainLen = cur.u4();
      if (chainLen > MAX_CHAIN) {
        throw new JksParseError(`chain length ${chainLen} exceeds sanity cap`);
      }
      const certsDer: Buffer[] = [];
      for (let c = 0; c < chainLen; c++) {
        if (version === 2) cur.utf(); // certType, always "X.509"
        certsDer.push(cur.bytes(cur.u4()));
      }
      entries.push({ alias, timestampMs, type: "key", certsDer });
    } else if (tag === 2) {
      if (version === 2) cur.utf(); // certType
      const der = cur.bytes(cur.u4());
      entries.push({ alias, timestampMs, type: "trusted", certsDer: [der] });
    } else {
      throw new JksParseError(`unknown entry tag ${tag} at entry ${i}`);
    }
  }

  return entries;
}
