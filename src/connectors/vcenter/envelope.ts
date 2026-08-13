/**
 * End-to-end sealed credential envelope.
 *
 * The vCenter credential is sealed in the ADMIN'S BROWSER against the gateway's
 * public key and can only be opened by the gateway's private key, which lives
 * with PrivSvc. The control plane relays the envelope but holds no private key,
 * so it cannot read the credential — the guarantee is cryptographic, not a
 * logging-discipline promise. Neither Front Door, nor middleware, nor an APM
 * trace, nor a crash dump ever sees plaintext. See ADR-0001 section (C).
 *
 * Hybrid construction (RSA-OAEP-SHA256 + AES-256-GCM):
 *   RSA-2048 with OAEP-SHA256 can only wrap ~190 bytes, which a long password
 *   plus username plus future fields can exceed. So a random AES-256 key
 *   encrypts the payload and RSA wraps only that key.
 *
 * The certificate fingerprint the envelope was sealed to is carried in the
 * clear AND bound as AES-GCM additional authenticated data. That gives two
 * things: the agent can tell a STALE envelope (sealed to a cert that has since
 * rotated) from a corrupt one and report it precisely, and an attacker cannot
 * rewrite the fingerprint without breaking authentication.
 */

import crypto from "node:crypto";

export const ENVELOPE_VERSION = 1;
export const ENVELOPE_ALG = "RSA-OAEP-256+A256GCM";

export interface SealedEnvelope {
  v: number;
  alg: string;
  /** SHA-256 (hex, lowercase, no separators) of the DER cert this was sealed to. */
  certFingerprint: string;
  /** RSA-OAEP-wrapped AES-256 key, base64url. */
  ek: string;
  /** 12-byte GCM IV, base64url. */
  iv: string;
  /** Ciphertext, base64url. */
  ct: string;
  /** 16-byte GCM auth tag, base64url. */
  tag: string;
}

export interface VCenterCredential {
  username: string;
  password: string;
}

export class EnvelopeError extends Error {
  constructor(
    message: string,
    readonly code:
      | "unsupported_version"
      | "stale_envelope"
      | "decrypt_failed"
      | "malformed"
  ) {
    super(message);
    this.name = "EnvelopeError";
  }
}

const b64u = (b: Buffer) => b.toString("base64url");
const unb64u = (s: string) => Buffer.from(s, "base64url");

/** SHA-256 of a certificate's DER bytes, hex lowercase. */
export function certFingerprintFromPem(certPem: string): string {
  const der = pemToDer(certPem, "CERTIFICATE");
  return crypto.createHash("sha256").update(der).digest("hex");
}

function pemToDer(pem: string, label: string): Buffer {
  const m = pem.match(new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`));
  if (!m) throw new EnvelopeError(`PEM block ${label} not found`, "malformed");
  return Buffer.from(m[1].replace(/\s+/g, ""), "base64");
}

/**
 * Seal a credential against the gateway's certificate.
 *
 * In production this happens in the browser via Web Crypto; this Node
 * implementation is the reference used by tests and by any CLI fallback. Both
 * must produce the same wire format.
 */
export function sealCredential(cred: VCenterCredential, certPem: string): SealedEnvelope {
  const certFingerprint = certFingerprintFromPem(certPem);
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  // Bind the fingerprint so it cannot be swapped without failing auth.
  cipher.setAAD(Buffer.from(certFingerprint, "utf8"));
  const ct = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(cred), "utf8")),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  const ek = crypto.publicEncrypt(
    {
      key: new crypto.X509Certificate(certPem).publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    key
  );
  key.fill(0);

  return {
    v: ENVELOPE_VERSION,
    alg: ENVELOPE_ALG,
    certFingerprint,
    ek: b64u(ek),
    iv: b64u(iv),
    ct: b64u(ct),
    tag: b64u(tag),
  };
}

/**
 * Open an envelope with the gateway's private key.
 *
 * `expectedFingerprint` is the fingerprint of the certificate the gateway
 * currently holds. When it differs from the envelope's, the credential was
 * sealed against a cert that has since rotated: that is `stale_envelope` and
 * the admin must re-enter it — deliberately distinguished from a decrypt
 * failure so the UI can say something useful instead of "invalid credential".
 */
export function openEnvelope(
  env: SealedEnvelope,
  privateKeyPem: string,
  expectedFingerprint?: string
): VCenterCredential {
  if (!env || typeof env !== "object") throw new EnvelopeError("envelope missing", "malformed");
  if (env.v !== ENVELOPE_VERSION) {
    throw new EnvelopeError(`unsupported envelope version ${env.v}`, "unsupported_version");
  }
  if (env.alg !== ENVELOPE_ALG) {
    throw new EnvelopeError(`unsupported envelope algorithm ${env.alg}`, "unsupported_version");
  }
  for (const f of ["ek", "iv", "ct", "tag", "certFingerprint"] as const) {
    if (typeof env[f] !== "string" || !env[f]) {
      throw new EnvelopeError(`envelope field ${f} missing`, "malformed");
    }
  }
  if (expectedFingerprint) {
    const want = expectedFingerprint.replace(/[:\s]/g, "").toLowerCase();
    const got = env.certFingerprint.replace(/[:\s]/g, "").toLowerCase();
    if (want !== got) {
      throw new EnvelopeError(
        "credential was sealed to a different gateway certificate (it has since rotated)",
        "stale_envelope"
      );
    }
  }

  let key: Buffer;
  try {
    key = crypto.privateDecrypt(
      {
        key: crypto.createPrivateKey(privateKeyPem),
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      unb64u(env.ek)
    );
  } catch {
    // Never echo the underlying crypto error — it can leak oracle detail.
    throw new EnvelopeError("could not unwrap the envelope key", "decrypt_failed");
  }

  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, unb64u(env.iv));
    decipher.setAAD(Buffer.from(env.certFingerprint, "utf8"));
    decipher.setAuthTag(unb64u(env.tag));
    const plain = Buffer.concat([decipher.update(unb64u(env.ct)), decipher.final()]);
    const parsed = JSON.parse(plain.toString("utf8"));
    plain.fill(0);
    if (typeof parsed?.username !== "string" || typeof parsed?.password !== "string") {
      throw new EnvelopeError("envelope payload is not a credential", "malformed");
    }
    return { username: parsed.username, password: parsed.password };
  } catch (e) {
    if (e instanceof EnvelopeError) throw e;
    throw new EnvelopeError("envelope failed authentication", "decrypt_failed");
  } finally {
    key.fill(0);
  }
}
