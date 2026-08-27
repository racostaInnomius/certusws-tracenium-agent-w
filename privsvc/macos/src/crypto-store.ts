import crypto from "crypto";
import fs from "fs";
import https from "https";
import os from "os";
import { execFile } from "child_process";
import { promisify } from "util";
import { certPaths, ensurePrivSvcDirs, CERT_DIR } from "./paths";
import {
  evaluateAnchorPins,
  loadAnchorPins,
  saveAnchorPins,
  describeAnchorVerdict,
  type AnchorPinMode,
  type AnchorPinVerdict
} from "./anchor-pin";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";

const execFileAsync = promisify(execFile);
const OPENSSL_BIN = process.env.OPENSSL_BIN || "/usr/bin/openssl";
const MACOS_CSR_KEY_BITS = "2048";

function normalizePem(value: any): string {
  return String(value || "").trim() + "\n";
}

function splitPemCertificates(pemBundle: string): string[] {
  const matches = String(pemBundle || "").match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
  return matches ? matches.map((pem) => normalizePem(pem)) : [];
}

function certFingerprintPem(pem: string): string {
  const x509 = new crypto.X509Certificate(pem);
  return String(x509.fingerprint256 || "").replace(/:/g, "").toLowerCase();
}

function readBundledRootCaPem(): string | null {
  const paths = certPaths();
  try {
    if (!fs.existsSync(paths.bundledRootCa)) return null;
    const pem = fs.readFileSync(paths.bundledRootCa, "utf8");
    return pem.includes("BEGIN CERTIFICATE") ? normalizePem(pem) : null;
  } catch {
    return null;
  }
}

function buildFullCaBundlePem(caBundlePem: string): { fullBundlePem: string; issuingCaThumbprint?: string } {
  const certs = splitPemCertificates(caBundlePem);
  const bundledRootCaPem = readBundledRootCaPem();

  if (bundledRootCaPem) {
    certs.push(bundledRootCaPem);
  }

  const deduped: string[] = [];
  const seen = new Set<string>();

  for (const certPem of certs) {
    try {
      const fingerprint = certFingerprintPem(certPem);
      if (seen.has(fingerprint)) continue;
      seen.add(fingerprint);
      deduped.push(certPem);
    } catch {
      continue;
    }
  }

  const issuingCaThumbprint = deduped.length > 0 ? certFingerprintPem(deduped[0]) : undefined;

  return {
    fullBundlePem: deduped.join(""),
    issuingCaThumbprint
  };
}


/**
 * Modo del pin de anclas. `observe` por defecto — ver anchor-pin.ts para
 * por qué NO bloquea de salida (hay una rotacion de CA en curso, y un pin
 * estricto en mitad de una rotacion legitima deja equipos incomunicados).
 */
function anchorPinMode(): AnchorPinMode {
  return process.env.TRACENIUM_ANCHOR_PIN === "enforce" ? "enforce" : "observe";
}

/** Huellas de los certificados AUTOFIRMADOS del bundle: las que se instalan como raiz. */
function rootFingerprintsOf(bundlePem: string): string[] {
  const out: string[] = [];
  for (const pem of splitPemCertificates(bundlePem)) {
    try {
      const cert = new crypto.X509Certificate(pem);
      if (cert.subject === cert.issuer) out.push(certFingerprintPem(pem));
    } catch {
      continue;
    }
  }
  return out;
}

/**
 * Evalua el bundle contra los pines, lo registra RUIDOSAMENTE y persiste
 * la linea base. Devuelve el veredicto para que el llamante pueda
 * incluirlo en la respuesta IPC — un veredicto que solo va al log se
 * pierde, y esta ruta ya tiene un historial de tragarse errores.
 */
function applyAnchorPin(bundlePem: string): AnchorPinVerdict {
  const mode = anchorPinMode();
  const verdict = evaluateAnchorPins(loadAnchorPins(CERT_DIR), rootFingerprintsOf(bundlePem), mode);
  const message = describeAnchorVerdict(verdict);

  if (verdict.unpinned.length > 0) {
    logger.warn(message);
  } else {
    logger.info(message);
  }

  // Se fija lo que efectivamente se va a confiar. En `enforce` lo
  // rechazado no entra, para no legitimar en el fichero lo que se acaba
  // de negar.
  const accepted = verdict.incoming.filter((fp) => !verdict.rejected.includes(fp));
  try {
    saveAnchorPins(CERT_DIR, [...verdict.pinned, ...accepted]);
  } catch (err) {
    logger.warn(`anchor-pin: no se pudo persistir la linea base: ${String(err)}`);
  }

  return verdict;
}

async function installCaCertificatesToSystemKeychain(
  bundlePem: string,
  rejectedFingerprints: string[] = []
): Promise<void> {
  const certs = splitPemCertificates(bundlePem).filter((pem) => {
    if (rejectedFingerprints.length === 0) return true;
    try {
      return !rejectedFingerprints.includes(certFingerprintPem(pem));
    } catch {
      return true;
    }
  });
  if (certs.length === 0) return;

  const tempDir = fs.mkdtempSync("/tmp/tracenium-ca-");

  try {
    const certFiles = certs.map((certPem, index) => {
      const file = `${tempDir}/ca-${index}.crt`;
      fs.writeFileSync(file, certPem, { encoding: "utf8", mode: 0o644 });
      return {
        file,
        cert: new crypto.X509Certificate(certPem)
      };
    });

    for (const entry of certFiles) {
      if (entry.cert.subject === entry.cert.issuer) {
        await execFileAsync("/usr/bin/security", [
          "add-trusted-cert",
          "-d",
          "-r",
          "trustRoot",
          "-k",
          "/Library/Keychains/System.keychain",
          entry.file
        ]).catch(() => undefined);
      } else {
        await execFileAsync("/usr/bin/security", [
          "add-certificates",
          "-k",
          "/Library/Keychains/System.keychain",
          entry.file
        ]).catch(() => undefined);
      }
    }
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
}

// ---------------------------------------------------------------------------
// System Keychain — client identity (cert + private key)
// ---------------------------------------------------------------------------
//
// Architectural constraint: @grpc/grpc-js takes raw PEM buffers via
// credentials.createSsl(); there is no hook to source key material from
// the macOS Keychain at handshake time. A "proper" Keychain-native mTLS
// stack would need a SecureTransport sidecar (C++/Rust) piping bytes into
// Node, which is out of scope for this release.
//
// What we CAN do — and what P1-5 delivers — is dual-storage:
//
//   1. Client cert + private key are ALSO installed into System.keychain
//      as an identity, tagged with our daemon's binary path in the ACL.
//   2. The PEM files on disk remain the runtime source (gRPC-js reads
//      them into buffers at connect time).
//   3. The Keychain copy gives us:
//        - An audit trail (security-cli and Console.app record access).
//        - Tamper detection: if the files are deleted or corrupted, we
//          can re-export from Keychain as a recovery mechanism (future).
//        - Defense-in-depth: a backup snapshot that skips our PrivSvc
//          dir (but captures /Library/Keychains) still loses the key,
//          and vice versa — both copies have to be reached for theft.
//        - Forces an attacker who replaces our binary on disk to either
//          forge its codesigning identity or lose the Keychain-side key.
//
// On rotation, the old identity is removed so Keychain doesn't accumulate
// dead entries that could be misused by certificate-pinning tools.

const KEYCHAIN_PATH = "/Library/Keychains/System.keychain";

// Path to the node binary that runs PrivSvc. The Keychain ACL is tied to
// this executable so a malicious tampered binary at a different path
// cannot read the key partition.
const PRIVSVC_NODE_BIN = "/Library/Application Support/Tracenium/Runtime/node";

function keychainLabelForDevice(deviceId: string): string {
  return `Tracenium Agent mTLS (${deviceId})`;
}

/**
 * Install a client identity (cert + private key) into the System
 * Keychain. Best-effort: any failure is logged and swallowed — the file-
 * based PEMs remain authoritative for runtime gRPC.
 *
 * Mechanics:
 *   1. Pack cert + key into a PKCS#12 blob via `openssl pkcs12 -export`.
 *      The blob is protected by a random passphrase that never leaves
 *      this function — `security import` consumes it via argv and the
 *      temp .p12 is unlinked in finally. Argv is visible in `ps` to
 *      root, but we're already running as root and the window is
 *      milliseconds, so the risk is acceptable vs. adding a named-pipe
 *      dance.
 *   2. `security import` with `-T <node bin>` binds the access ACL to
 *      our daemon's node binary. Other binaries attempting to read the
 *      key will be prompted for user approval (which never comes on a
 *      headless system) — effectively blocked.
 *   3. `security set-key-partition-list` allows the "apple:" partition
 *      id to access non-interactively so our own daemon doesn't prompt.
 *      The `-S "apple:,teamid:<our-team>,unsigned:"` list is permissive
 *      enough for local execution but still gated by the -T ACL above.
 */
async function installClientIdentityToSystemKeychain(
  clientCertPem: string,
  clientKeyPem: string,
  deviceId: string
): Promise<{ installed: boolean; label: string } | null> {
  const label = keychainLabelForDevice(deviceId);

  let tempDir: string | null = null;
  try {
    tempDir = fs.mkdtempSync("/private/tmp/tracenium-id-");
    // Lock the temp dir down — even though we're root, this reduces the
    // chance that some rogue ad-hoc process enumerates /tmp and sees the
    // .p12 during the brief window before we unlink it.
    fs.chmodSync(tempDir, 0o700);

    const certPath = `${tempDir}/client.crt`;
    const keyPath = `${tempDir}/client.key`;
    const p12Path = `${tempDir}/identity.p12`;

    fs.writeFileSync(certPath, clientCertPem, { encoding: "utf8", mode: 0o600 });
    fs.writeFileSync(keyPath, clientKeyPem, { encoding: "utf8", mode: 0o600 });

    // Random passphrase ~= 22 chars base64. Used only to traverse the
    // openssl → security boundary; never persisted.
    const passphrase = crypto.randomBytes(16).toString("base64").replace(/[=+/]/g, "");

    await execFileAsync(OPENSSL_BIN, [
      "pkcs12",
      "-export",
      "-in", certPath,
      "-inkey", keyPath,
      "-name", label,
      "-out", p12Path,
      "-passout", `pass:${passphrase}`
    ]);
    fs.chmodSync(p12Path, 0o600);

    // Remove any previous entry with the same label so import doesn't
    // duplicate. delete-identity is idempotent — failure is fine.
    await execFileAsync("/usr/bin/security", [
      "delete-identity",
      "-c", label,
      KEYCHAIN_PATH
    ]).catch(() => undefined);

    await execFileAsync("/usr/bin/security", [
      "import", p12Path,
      "-k", KEYCHAIN_PATH,
      "-P", passphrase,
      "-t", "priv",
      "-f", "pkcs12",
      "-T", PRIVSVC_NODE_BIN,
      "-T", "/usr/bin/security"
    ]);

    // Allow non-interactive access by our partition id. Without this,
    // any attempt to read the key would trigger a UI prompt (which on a
    // headless daemon means hangs / timeouts).
    await execFileAsync("/usr/bin/security", [
      "set-key-partition-list",
      "-S", "apple-tool:,apple:,unsigned:",
      "-k", "",                        // system keychain has no password
      "-s",                            // sign operations
      "-l", label,                     // match by label
      KEYCHAIN_PATH
    ]).catch((err) => {
      // set-key-partition-list returns non-zero on some macOS versions
      // when the key is already in the requested partition. Log and
      // carry on — the import itself succeeded.
      logger.warn("keychain_set_partition_list_failed", {
        error: err?.message || String(err)
      });
    });

    logger.info("keychain_client_identity_installed", { label, deviceId });
    return { installed: true, label };
  } catch (err: any) {
    logger.warn("keychain_client_identity_install_failed", {
      deviceId,
      error: err?.message || String(err)
    });
    return null;
  } finally {
    if (tempDir) {
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
    }
  }
}

/**
 * Remove a previously-installed client identity from the System
 * Keychain. Called after a successful rotation so we don't pile up
 * stale identities across renewals (every 30 days = 12+ per year).
 *
 * Best-effort: no-op if the label isn't present.
 */
async function removeClientIdentityFromSystemKeychain(deviceId: string, labelOverride?: string): Promise<void> {
  const label = labelOverride || keychainLabelForDevice(deviceId);
  try {
    await execFileAsync("/usr/bin/security", [
      "delete-identity",
      "-c", label,
      KEYCHAIN_PATH
    ]);
    logger.info("keychain_client_identity_removed", { label });
  } catch (err: any) {
    // delete-identity returns non-zero when nothing matches; that's fine.
    logger.debug("keychain_client_identity_remove_noop", {
      label,
      error: err?.message || String(err)
    });
  }
}

function assertDeviceId(value: any): string {
  const deviceId = String(value || "").trim();
  if (!deviceId) throw new Error("deviceId_required");
  return deviceId;
}

async function isRsaPrivateKey(keyPath: string): Promise<boolean> {
  if (!fs.existsSync(keyPath)) return false;

  try {
    const { stdout } = await execFileAsync(OPENSSL_BIN, [
      "pkey",
      "-in",
      keyPath,
      "-text",
      "-noout"
    ]);

    return /Private-Key:\s*\(2048 bit/.test(stdout);
  } catch {
    return false;
  }
}

async function ensureEnrollmentPrivateKey(keyPath: string, reuseExistingKey: boolean): Promise<void> {
  const canReuse = reuseExistingKey && await isRsaPrivateKey(keyPath);

  if (canReuse) {
    return;
  }

  try {
    fs.rmSync(keyPath, { force: true });
  } catch {}

  await execFileAsync(OPENSSL_BIN, [
    "genpkey",
    "-algorithm",
    "RSA",
    "-pkeyopt",
    `rsa_keygen_bits:${MACOS_CSR_KEY_BITS}`,
    "-out",
    keyPath
  ]);
  fs.chmodSync(keyPath, 0o600);
}

export async function handleGenerateCsr(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const paths = certPaths();
  const csrConfigPath = `${paths.clientCsr}.cnf`;

  try {
    ensurePrivSvcDirs();
    const params = req.params || {};
    const tenantId = String(params.tenantId || req.meta?.tenantId || "bootstrap");
    const deviceId = assertDeviceId(params.deviceId || req.meta?.deviceId);
    const reuseExistingKey = params.reuseExistingKey !== false;
    const dnsName = os.hostname();

    // Cross-platform contract: agent-core passes `keyAlgorithm` to tell
    // each PrivSvc which algorithm to produce. macOS has only ever
    // generated RSA-2048 (via `openssl genpkey -algorithm RSA`), so for
    // now the only accepted value is `RSA_2048`. Any other value is a
    // contract mismatch and must fail loudly rather than silently
    // producing the wrong algorithm — exactly the class of bug that
    // broke Windows enrollment.
    const keyAlgorithm = String(params.keyAlgorithm || "RSA_2048").toUpperCase();
    if (keyAlgorithm !== "RSA_2048") {
      return fail(
        req.id,
        "bad_request",
        `unsupported keyAlgorithm on macOS: ${keyAlgorithm} (only RSA_2048)`
      );
    }

    await ensureEnrollmentPrivateKey(paths.clientKey, reuseExistingKey);

    const csrConfig = [
      "[req]",
      "prompt = no",
      "distinguished_name = dn",
      "req_extensions = req_ext",
      "[dn]",
      `CN = ${dnsName}`,
      "[req_ext]",
      "keyUsage = critical,digitalSignature",
      "extendedKeyUsage = clientAuth",
      "subjectAltName = @alt_names",
      "[alt_names]",
      `DNS.1 = ${dnsName}`,
      `URI.1 = tracenium://tenant/${tenantId}/device/${deviceId}`
    ].join("\n");
    fs.writeFileSync(csrConfigPath, `${csrConfig}\n`, { encoding: "utf8", mode: 0o600 });

    await execFileAsync(OPENSSL_BIN, [
      "req",
      "-new",
      "-sha256",
      "-key",
      paths.clientKey,
      "-config",
      csrConfigPath,
      "-out",
      paths.clientCsr
    ]);

    const csrPem = fs.readFileSync(paths.clientCsr, "utf8");
    return success(req.id, {
      csrPem,
      deviceId,
      dnsName,
      keyAlgorithm: "RSA_2048",
      keyStore: "file",
      keyPath: paths.clientKey
    });
  } catch (err: any) {
    return fail(req.id, "csr_generate_failed", err?.message || String(err));
  } finally {
    try {
      fs.rmSync(csrConfigPath, { force: true });
    } catch {}
  }
}

export async function handleInstallCert(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    ensurePrivSvcDirs();
    const paths = certPaths();
    const params = req.params || {};
    const clientCertPem = normalizePem(params.clientCertPem);
    const caBundlePem = normalizePem(params.caBundlePem);

    if (!clientCertPem.includes("BEGIN CERTIFICATE")) {
      return fail(req.id, "invalid_client_cert", "clientCertPem is required");
    }

    if (!caBundlePem.includes("BEGIN CERTIFICATE")) {
      return fail(req.id, "invalid_ca_bundle", "caBundlePem is required");
    }

    if (!fs.existsSync(paths.clientKey)) {
      return fail(req.id, "missing_private_key", "CSR private key was not found");
    }

    const { fullBundlePem, issuingCaThumbprint } = buildFullCaBundlePem(caBundlePem);

    fs.writeFileSync(paths.clientCert, clientCertPem, { encoding: "utf8", mode: 0o600 });
    fs.writeFileSync(paths.caBundle, fullBundlePem, { encoding: "utf8", mode: 0o644 });

    // El pin se evalua ANTES de instalar, y el fallo deja de ser mudo:
    // el `.catch(() => undefined)` que habia aqui se tragaba tanto un
    // error de instalacion como un ancla inesperada.
    const anchorVerdict = applyAnchorPin(fullBundlePem);
    await installCaCertificatesToSystemKeychain(fullBundlePem, anchorVerdict.rejected).catch(
      (err) => logger.warn(`install CA anchors failed: ${String(err)}`)
    );

    // Also install the client identity (cert + private key) into the
    // System Keychain as a secondary store. Runtime still reads from
    // the PEM files above — this is defense-in-depth (see the big
    // comment at the top of the Keychain helper block for rationale).
    const clientKeyPem = fs.readFileSync(paths.clientKey, "utf8");
    const deviceId = assertDeviceId(params.deviceId || req.meta?.deviceId);
    const keychainResult = await installClientIdentityToSystemKeychain(
      clientCertPem,
      clientKeyPem,
      deviceId
    );

    const clientCertThumbprint = certFingerprintPem(clientCertPem);

    return success(req.id, {
      clientCertThumbprint,
      issuingCaThumbprint,
      clientCertPath: paths.clientCert,
      caBundlePath: paths.caBundle,
      // `keyStore` reflects the authoritative runtime source (still
      // "file" for gRPC-js) plus whether the Keychain mirror landed.
      // Ops can query this to verify the dual-storage invariant.
      keyStore: keychainResult?.installed ? "file+keychain" : "file",
      keychainLabel: keychainResult?.label ?? null
    });
  } catch (err: any) {
    return fail(req.id, "cert_install_failed", err?.message || String(err));
  }
}

function postJsonMtls(url: string, payload: any, identity: { clientCert: Buffer; clientKey: Buffer; caBundle: Buffer }): Promise<any> {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify(payload), "utf8");
    const target = new URL(url);
    const trustAgentCa = process.env.CERT_RENEWAL_TRUST_AGENT_CA === "1";

    const request = https.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || 443,
      path: `${target.pathname}${target.search}`,
      method: "POST",
      cert: identity.clientCert,
      key: identity.clientKey,
      ...(trustAgentCa ? { ca: identity.caBundle } : {}),
      headers: {
        "Content-Type": "application/json",
        "Content-Length": String(body.length)
      },
      timeout: 30000
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", chunk => chunks.push(Buffer.from(chunk)));
      response.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        if ((response.statusCode || 500) < 200 || (response.statusCode || 500) >= 300) {
          reject(new Error(`HTTP ${response.statusCode}: ${text}`));
          return;
        }

        try {
          resolve(JSON.parse(text));
        } catch (err) {
          reject(err);
        }
      });
    });

    request.on("timeout", () => {
      request.destroy(new Error("renew request timeout"));
    });
    request.on("error", reject);
    request.write(body);
    request.end();
  });
}

function backupFile(file: string): string | null {
  if (!fs.existsSync(file)) return null;
  const backup = `${file}.bak`;
  fs.copyFileSync(file, backup);
  return backup;
}

function restoreBackup(backup: string | null, file: string) {
  if (!backup || !fs.existsSync(backup)) return;
  fs.copyFileSync(backup, file);
}

export async function handleRenewCert(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  ensurePrivSvcDirs();
  const paths = certPaths();

  // Defined outside the try so the `finally` cleanup can see them even
  // if we throw before they're first written.
  const pendingKey = `${paths.clientKey}.pending`;
  const pendingCsr = `${paths.clientCsr}.pending`;
  const pendingConf = `${paths.clientCsr}.cnf`;
  const pendingCert = `${paths.clientCert}.pending`;
  const pendingCa = `${paths.caBundle}.pending`;

  try {
    const params = req.params || {};
    const serverBaseUrl = String(params.serverBaseUrl || "").replace(/\/+$/, "");
    const tenantId = String(params.tenantId || req.meta?.tenantId || "");
    const deviceId = assertDeviceId(params.deviceId || req.meta?.deviceId);

    if (!serverBaseUrl) {
      return fail(req.id, "bad_request", "serverBaseUrl required");
    }

    if (!tenantId) {
      return fail(req.id, "bad_request", "tenantId required");
    }

    const conf = [
      "[req]",
      "prompt = no",
      "distinguished_name = dn",
      "req_extensions = req_ext",
      "[dn]",
      `CN = tracenium-agent-${deviceId}`,
      "O = Tracenium",
      `OU = ${tenantId}`,
      "[req_ext]",
      "keyUsage = critical,digitalSignature",
      "extendedKeyUsage = clientAuth",
      `subjectAltName = URI:tracenium://tenant/${tenantId}/device/${deviceId}`
    ].join("\n");

    fs.writeFileSync(pendingConf, conf + "\n", { encoding: "utf8", mode: 0o600 });

    await execFileAsync(OPENSSL_BIN, [
      "genpkey",
      "-algorithm",
      "RSA",
      "-pkeyopt",
      `rsa_keygen_bits:${MACOS_CSR_KEY_BITS}`,
      "-out",
      pendingKey
    ]);
    fs.chmodSync(pendingKey, 0o600);

    await execFileAsync(OPENSSL_BIN, [
      "req",
      "-new",
      "-sha256",
      "-key",
      pendingKey,
      "-out",
      pendingCsr,
      "-config",
      pendingConf
    ]);

    const csrPem = fs.readFileSync(pendingCsr, "utf8");
    const identity = loadInstalledIdentity();
    const response = await postJsonMtls(
      `${serverBaseUrl}/api/v1/security/certificates/renew`,
      { csrPem },
      identity
    );

    const clientCertPem = normalizePem(response.clientCertPem);
    const caBundlePem = normalizePem(response.caBundlePem);

    if (!clientCertPem.includes("BEGIN CERTIFICATE") || !caBundlePem.includes("BEGIN CERTIFICATE")) {
      return fail(req.id, "renew_response_invalid", "renewal response missing certificate material");
    }

    const { fullBundlePem, issuingCaThumbprint } = buildFullCaBundlePem(caBundlePem);

    fs.writeFileSync(pendingCert, clientCertPem, { encoding: "utf8", mode: 0o600 });
    fs.writeFileSync(pendingCa, fullBundlePem, { encoding: "utf8", mode: 0o644 });

    const keyBackup = backupFile(paths.clientKey);
    const certBackup = backupFile(paths.clientCert);
    const caBackup = backupFile(paths.caBundle);

    try {
      fs.renameSync(pendingKey, paths.clientKey);
      fs.renameSync(pendingCert, paths.clientCert);
      fs.renameSync(pendingCa, paths.caBundle);
    } catch (err) {
      restoreBackup(keyBackup, paths.clientKey);
      restoreBackup(certBackup, paths.clientCert);
      restoreBackup(caBackup, paths.caBundle);
      throw err;
    }

    const clientCertThumbprint = certFingerprintPem(clientCertPem);
    const x509 = new crypto.X509Certificate(clientCertPem);

    // El pin se evalua ANTES de instalar, y el fallo deja de ser mudo:
    // el `.catch(() => undefined)` que habia aqui se tragaba tanto un
    // error de instalacion como un ancla inesperada.
    const anchorVerdict = applyAnchorPin(fullBundlePem);
    await installCaCertificatesToSystemKeychain(fullBundlePem, anchorVerdict.rejected).catch(
      (err) => logger.warn(`install CA anchors failed: ${String(err)}`)
    );

    // Re-install the rotated identity into System Keychain. The install
    // helper deletes any prior entry with the same label first, so we
    // don't need a separate removeClientIdentity call here — renewal
    // uses the same per-device label (only the cert changes).
    const renewedKeyPem = fs.readFileSync(paths.clientKey, "utf8");
    const keychainResult = await installClientIdentityToSystemKeychain(
      clientCertPem,
      renewedKeyPem,
      deviceId
    );

    return success(req.id, {
      deviceId,
      clientCertPem,
      caBundlePem: fullBundlePem,
      clientCertThumbprint,
      issuingCaThumbprint,
      notAfter: x509.validTo,
      status: response.status || "pending",
      keyStore: keychainResult?.installed ? "file+keychain" : "file",
      keychainLabel: keychainResult?.label ?? null
    });
  } catch (err: any) {
    return fail(req.id, "cert_renew_failed", err?.message || String(err));
  } finally {
    // Best-effort cleanup of every pending artifact. On the happy path the
    // `.pending` cert/key/ca files have already been renamed into place
    // and don't exist anymore, so unlinkSync errors are expected — we
    // swallow them. On a failure path (openssl crashed, renewal API 5xx,
    // rename collision, etc.) any of these could still be sitting in
    // CERT_DIR leaking disk and, worse, leaving a key PEM readable by
    // anyone who can read the dir. finally wins over mid-function
    // cleanup precisely because we cover every exit path.
    for (const file of [pendingCsr, pendingConf, pendingKey, pendingCert, pendingCa]) {
      try { fs.unlinkSync(file); } catch {}
    }
  }
}

export function loadInstalledIdentity() {
  const paths = certPaths();
  const clientCert = fs.readFileSync(paths.clientCert);
  const clientKey = fs.readFileSync(paths.clientKey);
  const caBundlePem = fs.readFileSync(paths.caBundle, "utf8");
  const { fullBundlePem } = buildFullCaBundlePem(caBundlePem);
  const caBundle = Buffer.from(fullBundlePem, "utf8");

  return {
    clientCert,
    clientKey,
    caBundle
  };
}
