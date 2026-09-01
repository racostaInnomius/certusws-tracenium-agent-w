// privsvc/macos/src/credential-store.ts
//
// Custody of the vCenter service-account credential for the Infrastructure
// Gateway (ADR-0001). PrivSvc owns this because it is the only component that
// holds the enrollment private key — the credential is sealed in the admin's
// BROWSER against this device's certificate, relayed by a control plane that
// has no key for it, and can therefore be opened here and nowhere else.
//
// STORAGE CHOICE — why a file and not the System keychain
// The documented preference was the System keychain, and this daemon does
// already drive it for certificates. But the `security` CLI takes the secret as
// a COMMAND-LINE ARGUMENT, which puts the vCenter password in the process table
// for anything running `ps` — a worse exposure than the one we are trying to
// avoid. There is no argv-free path through that CLI, and linking against
// Security.framework is out of scope for this daemon. So the credential is
// stored AES-256-GCM encrypted under a per-install master key, both files
// root-owned and 0600 — the same boundary that already protects the enrollment
// private key sitting next to it.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { certPaths } from "./paths";
import { readGatewayKey, readGatewayPrivateKeyPem } from "./gateway-key";
import { success, fail, type PrivSvcRequest, type PrivSvcResponse } from "./protocol";

const ENVELOPE_VERSION = 1;
const ENVELOPE_ALG = "RSA-OAEP-256+A256GCM";

/** Credentials live beside the certs, in the same root-only directory. */
function storeDir(): string {
  return path.dirname(certPaths().clientKey);
}
function masterKeyPath(): string {
  return path.join(storeDir(), "credential-master.key");
}
function credentialPath(ref: string): string {
  // Refs are namespaced ("vcenter/default"). Flatten so a hostile ref cannot
  // escape the directory — this value ultimately comes off the wire.
  const safe = ref.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 120) || "default";
  return path.join(storeDir(), `credential-${safe}.bin`);
}

function writeSecret(file: string, data: Buffer): void {
  // Create with 0600 from the outset — never a window where it is world-readable.
  const fd = fs.openSync(file, "w", 0o600);
  try {
    fs.writeSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.chmodSync(file, 0o600);
}

function loadOrCreateMasterKey(): Buffer {
  const file = masterKeyPath();
  if (fs.existsSync(file)) {
    const key = fs.readFileSync(file);
    if (key.length === 32) return key;
    // A truncated or corrupt key would silently produce undecryptable data.
    // Refuse rather than quietly re-key and orphan every stored credential.
    throw Object.assign(new Error("credential master key is corrupt"), {
      code: "store_unavailable",
    });
  }
  const key = crypto.randomBytes(32);
  writeSecret(file, key);
  return key;
}

/** SHA-256 of the installed client certificate DER, hex — the seal target. */
function currentCertFingerprint(): string {
  const pem = fs.readFileSync(certPaths().clientCert, "utf8");
  const m = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
  if (!m) throw Object.assign(new Error("no client certificate installed"), { code: "malformed" });
  const der = Buffer.from(m[1].replace(/\s+/g, ""), "base64");
  return crypto.createHash("sha256").update(der).digest("hex");
}

interface SealedEnvelope {
  v: number;
  alg: string;
  certFingerprint: string;
  ek: string;
  iv: string;
  ct: string;
  tag: string;
}

/**
 * Open a sealed envelope with the enrollment private key.
 *
 * Mirrors the browser's sealCredential and the agent's reference openEnvelope
 * byte for byte: RSA-OAEP-SHA256 unwraps the AES key, AES-256-GCM decrypts the
 * payload, and the certificate fingerprint is bound as additional authenticated
 * data so it cannot be rewritten.
 */
function openEnvelope(env: SealedEnvelope): { username: string; password: string } {
  if (!env || typeof env !== "object") {
    throw Object.assign(new Error("envelope missing"), { code: "malformed" });
  }
  if (Number(env.v) !== ENVELOPE_VERSION || env.alg !== ENVELOPE_ALG) {
    throw Object.assign(new Error(`unsupported envelope ${env.v}/${env.alg}`), {
      code: "unsupported_version",
    });
  }
  for (const f of ["ek", "iv", "ct", "tag", "certFingerprint"] as const) {
    if (typeof env[f] !== "string" || !env[f]) {
      throw Object.assign(new Error(`envelope field ${f} missing`), { code: "malformed" });
    }
  }

  // La huella del sobre elige la clave, en lugar de darla por supuesta.
  //
  // ADR-0013 mete una segunda: la del gateway, que es la correcta y la
  // única que existe para esto. La de enrolamiento se sigue aceptando
  // durante el despliegue —un backend ya actualizado sirve el
  // certificado de enrolamiento mientras el agente no haya publicado el
  // suyo, y al revés— y ese solapamiento es justo lo que evita que un
  // gateway que hoy funciona deje de hacerlo a mitad de la actualización.
  //
  // Si no casa con ninguna, se selló contra un certificado que este
  // equipo ya no tiene: `stale_envelope` le dice al admin que vuelva a
  // introducirla, en vez de un fallo de descifrado que no dice nada.
  const wanted = env.certFingerprint.replace(/[:\s]/g, "").toLowerCase();
  const gateway = readGatewayKey();

  let privateKeyPem: string | null = null;
  if (gateway && gateway.fingerprintSha256 === wanted) {
    privateKeyPem = readGatewayPrivateKeyPem();
  } else if (currentCertFingerprint().toLowerCase() === wanted) {
    privateKeyPem = fs.readFileSync(certPaths().clientKey, "utf8");
  }

  if (!privateKeyPem) {
    throw Object.assign(
      new Error("credential was sealed to a different device certificate"),
      { code: "stale_envelope" }
    );
  }

  const unb64u = (s: string) => Buffer.from(s, "base64url");
  let aesKey: Buffer;
  try {
    aesKey = crypto.privateDecrypt(
      {
        key: crypto.createPrivateKey(privateKeyPem),
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      unb64u(env.ek)
    );
  } catch {
    // Never echo the underlying crypto error — it can leak oracle detail.
    throw Object.assign(new Error("could not unwrap the envelope key"), {
      code: "decrypt_failed",
    });
  }

  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, unb64u(env.iv));
    decipher.setAAD(Buffer.from(env.certFingerprint, "utf8"));
    decipher.setAuthTag(unb64u(env.tag));
    const plain = Buffer.concat([decipher.update(unb64u(env.ct)), decipher.final()]);
    const parsed = JSON.parse(plain.toString("utf8"));
    plain.fill(0);
    if (typeof parsed?.username !== "string" || typeof parsed?.password !== "string") {
      throw Object.assign(new Error("envelope payload is not a credential"), { code: "malformed" });
    }
    return { username: parsed.username, password: parsed.password };
  } catch (e: any) {
    if (e?.code) throw e;
    throw Object.assign(new Error("envelope failed authentication"), { code: "decrypt_failed" });
  } finally {
    aesKey.fill(0);
  }
}

function sealAtRest(plaintext: Buffer): Buffer {
  const key = loadOrCreateMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  key.fill(0);
  // iv | tag | ciphertext — fixed-width prefix keeps parsing trivial.
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

function openAtRest(blob: Buffer): Buffer {
  if (blob.length < 28) {
    throw Object.assign(new Error("stored credential is truncated"), { code: "store_unavailable" });
  }
  const key = loadOrCreateMasterKey();
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, blob.subarray(0, 12));
    decipher.setAuthTag(blob.subarray(12, 28));
    return Buffer.concat([decipher.update(blob.subarray(28)), decipher.final()]);
  } finally {
    key.fill(0);
  }
}

// ── IPC handlers ────────────────────────────────────────────────────────────

export function handleCredentialProvision(req: PrivSvcRequest): PrivSvcResponse {
  const params: any = req.params ?? {};
  const ref = String(params.ref || "vcenter/default");
  try {
    const cred = openEnvelope(params.envelope);
    const plain = Buffer.from(JSON.stringify(cred), "utf8");
    try {
      writeSecret(credentialPath(ref), sealAtRest(plain));
    } finally {
      plain.fill(0);
    }
    return success(req.id, { ok: true, certFingerprint: currentCertFingerprint() });
  } catch (e: any) {
    // Never surface the credential, and never surface raw crypto detail.
    return fail(req.id, e?.code || "decrypt_failed", e?.message || "could not store the credential");
  }
}

export function handleCredentialRetrieve(req: PrivSvcRequest): PrivSvcResponse {
  const params: any = req.params ?? {};
  const ref = String(params.ref || "vcenter/default");
  const file = credentialPath(ref);
  if (!fs.existsSync(file)) {
    return fail(req.id, "not_found", "no credential stored under that reference");
  }
  try {
    const plain = openAtRest(fs.readFileSync(file));
    const parsed = JSON.parse(plain.toString("utf8"));
    plain.fill(0);
    return success(req.id, { username: parsed.username, password: parsed.password });
  } catch (e: any) {
    return fail(req.id, e?.code || "store_unavailable", "stored credential could not be read");
  }
}

export function handleCredentialRemove(req: PrivSvcRequest): PrivSvcResponse {
  const params: any = req.params ?? {};
  const ref = String(params.ref || "vcenter/default");
  try {
    // Idempotent by contract: already-gone is the desired end state, not an
    // error to retry forever.
    fs.rmSync(credentialPath(ref), { force: true });
    return success(req.id, { ok: true });
  } catch (e: any) {
    return fail(req.id, "store_unavailable", e?.message || "could not remove the credential");
  }
}
