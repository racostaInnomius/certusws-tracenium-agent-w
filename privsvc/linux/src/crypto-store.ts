// privsvc/linux/src/crypto-store.ts
//
// Linux equivalent of macOS crypto-store.ts. Same IPC contract
// (handleGenerateCsr / handleInstallCert / handleRenewCert /
// loadInstalledIdentity) so the agent's enrollment + rotation code
// doesn't need to know which OS it's running on.
//
// What's missing vs macOS, intentionally:
//   * No Keychain mirror. macOS stores client cert + private key
//     into System.keychain as a defense-in-depth secondary copy
//     (audit trail, tamper detection, force codesign-bound ACL).
//     Linux has no equivalent system-wide keystore that satisfies
//     all three properties without pulling in heavy dependencies
//     (libsecret needs a logged-in session; pkcs11 needs a HSM /
//     softhsm install). The single source of truth is the PEM
//     files in /etc/tracenium/certs/, locked down by filesystem
//     permissions (clientKey 0600 root:root, dir 0750 root:tracenium).
//     If a customer ever needs HSM-backed keys we revisit then.
//   * No system trust-store install. macOS pushes the CA into
//     System.keychain so other tools (curl, browsers) trust it;
//     on Linux the equivalent (`update-ca-trust extract` for RHEL,
//     `update-ca-certificates` for Debian) is intentionally NOT
//     called. The CA bundle is private to Tracenium's gRPC client
//     and doesn't need to leak into other apps. If a customer
//     wants the CA in their system trust store they'll add it
//     manually via their distro's mechanism.
import crypto from "crypto";
import fs from "fs";
import https from "https";
import os from "os";
import { execFile } from "child_process";
import { promisify } from "util";
import { certPaths, ensurePrivSvcDirs } from "./paths";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";
// ADR-0015 — compartido con macOS a propósito: es aritmética sobre bytes
// que el backend tiene que aceptar, y dos copias que divergen dejan una
// plataforma sin poder enrolar. Ver privsvc/shared/der.ts.
import { buildCsr, ClassicAlgorithm } from "../../shared/pkcs10";
import { loadOrCreateAltKey } from "../../shared/alt-key";

const execFileAsync = promisify(execFile);

// openssl is universally available on every Linux distro we target
// (ssh-server / coreutils dependencies pull it in transitively).
// /usr/bin/openssl is the canonical FHS path; we honour OPENSSL_BIN
// override for unusual installs (Alpine in /usr/sbin, custom builds).
const OPENSSL_BIN = process.env.OPENSSL_BIN || "/usr/bin/openssl";
const LINUX_CSR_KEY_BITS = "2048";

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

// Build the full CA bundle that gRPC will use for server verification.
// Combines the issuing CA chain from the backend with the bundled root
// CA we ship in /var/lib/tracenium/assets/ — same logic as macOS so a
// renewal that updates the issuing CA without redeploying the agent
// continues to chain to a known root.
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
    issuingCaThumbprint,
  };
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
      "-noout",
    ]);
    return /Private-Key:\s*\(2048 bit/.test(stdout);
  } catch {
    return false;
  }
}

/**
 * ¿La clave de este fichero es del algoritmo que se ha pedido?
 *
 * ⚠️ Reutilizar sin comprobar el ALGORITMO era el fallo latente del
 * contrato viejo: `reuseExistingKey` sólo miraba que hubiera una RSA de
 * 2048. Con dos algoritmos en juego, un equipo que ya tuviera RSA la
 * reutilizaría para siempre y nunca llegaría a P-384 — la migración se
 * quedaría en el papel sin que nada fallara.
 */
async function keyMatchesAlgorithm(keyPath: string, alg: ClassicAlgorithm): Promise<boolean> {
  if (alg === "RSA_2048") return isRsaPrivateKey(keyPath);
  try {
    const { stdout } = await execFileAsync(OPENSSL_BIN, ["pkey", "-in", keyPath, "-noout", "-text"]);
    return /secp384r1|NIST CURVE: P-384/.test(stdout);
  } catch {
    return false;
  }
}

async function ensureEnrollmentPrivateKey(
  keyPath: string,
  reuseExistingKey: boolean,
  alg: ClassicAlgorithm
): Promise<void> {
  const canReuse = reuseExistingKey && await keyMatchesAlgorithm(keyPath, alg);
  if (canReuse) return;

  try {
    fs.rmSync(keyPath, { force: true });
  } catch {}

  const args = alg === "RSA_2048"
    ? ["genpkey", "-algorithm", "RSA", "-pkeyopt", `rsa_keygen_bits:${LINUX_CSR_KEY_BITS}`, "-out", keyPath]
    : null;

  if (!args) {
    // ⚠️ LA CLAVE P-384 LA GENERA NODE, NO `openssl`. Medido el
    // 2026-09-05 y es la razón entera de esta rama:
    //
    // El `openssl` de macOS es /usr/bin/openssl = LibreSSL 3.3.6, y su
    // `genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384` produce
    // una clave con PARÁMETROS EXPLÍCITOS de curva en vez del OID de la
    // curva con nombre. La SPKI resultante pesa 464 bytes en vez de 120,
    // y una clave con parámetros explícitos la rechazan o la maltratan
    // muchos verificadores — un formato legal que casi nadie quiere.
    //
    // LibreSSL sí admite `-pkeyopt ec_param_enc:named_curve`, así que se
    // podría arreglar con una bandera más. No se hace: una bandera que
    // hay que acordarse de poner en dos ficheros, cuyo olvido no da
    // error y sólo se nota mirando el DER, es una trampa. Node produce
    // siempre la curva con nombre y ya es quien firma el CSR.
    //
    // La rama RSA se deja EXACTAMENTE como estaba: es el 100% de la
    // flota de hoy y este cambio no tiene por qué tocarla.
    const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
    fs.writeFileSync(
      keyPath,
      privateKey.export({ format: "pem", type: "pkcs8" }) as string,
      { encoding: "utf8", mode: 0o600 }
    );
    fs.chmodSync(keyPath, 0o600);
    return;
  }

  await execFileAsync(OPENSSL_BIN, args);
  fs.chmodSync(keyPath, 0o600);
}

export async function handleGenerateCsr(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const paths = certPaths();

  try {
    ensurePrivSvcDirs();
    const params = req.params || {};
    const tenantId = String(params.tenantId || req.meta?.tenantId || "bootstrap");
    const deviceId = assertDeviceId(params.deviceId || req.meta?.deviceId);
    const reuseExistingKey = params.reuseExistingKey !== false;
    const dnsName = os.hostname();

    // Cross-platform contract: agent-core passes `keyAlgorithm` to tell
    // each PrivSvc which algorithm to produce. Cualquier valor fuera de
    // la lista falla RUIDOSAMENTE en vez de producir otro algoritmo en
    // silencio — la clase de fallo que rompió el enrolamiento de Windows.
    //
    // ADR-0015 punto 7: se añade EC_P384 y, en otro eje, `altKeyAlgorithm`
    // para la mitad post-cuántica.
    const keyAlgorithm = String(params.keyAlgorithm || "RSA_2048").toUpperCase();
    if (keyAlgorithm !== "RSA_2048" && keyAlgorithm !== "EC_P384") {
      return fail(
        req.id,
        "bad_request",
        `unsupported keyAlgorithm on linux: ${keyAlgorithm} (RSA_2048 | EC_P384)`
      );
    }

    // ⚠️ Ausente significa CLÁSICO, no error: un agente nuevo contra el
    // backend de hoy sigue enrolando exactamente igual.
    const altKeyAlgorithm = String(params.altKeyAlgorithm || "").toUpperCase();
    if (altKeyAlgorithm && altKeyAlgorithm !== "ML_DSA_65") {
      return fail(
        req.id,
        "bad_request",
        `unsupported altKeyAlgorithm on linux: ${altKeyAlgorithm} (ML_DSA_65)`
      );
    }

    await ensureEnrollmentPrivateKey(paths.clientKey, reuseExistingKey, keyAlgorithm);

    // ADR-0015 punto 8 — el CSR lo construimos nosotros.
    //
    // ⚠️ AQUÍ VIVÍA UN `openssl req -new -config`. `openssl req` NO PUEDE
    // hacer un CSR híbrido: la prueba de posesión alternativa se firma
    // sobre el propio CertificationRequestInfo y va DENTRO de él, que es
    // un problema de huevo y gallina sin solución en línea de comandos.
    // Se cambia también en Linux, donde el openssl sí conoce ML-DSA,
    // porque tener dos caminos distintos por plataforma es cómo se
    // producen los CSR que valen en una y no en la otra.
    const altKey = altKeyAlgorithm ? loadOrCreateAltKey(paths.clientKey, { reuse: reuseExistingKey }) : null;

    const built = buildCsr({
      classicKey: crypto.createPrivateKey(fs.readFileSync(paths.clientKey)),
      classicAlgorithm: keyAlgorithm as ClassicAlgorithm,
      commonName: dnsName,
      tenantId,
      deviceId,
      dnsName,
      altPrivateKeyPkcs8: altKey?.pkcs8Der ?? null,
      altPublicKeySpki: altKey?.spkiDer ?? null
    });

    fs.writeFileSync(paths.clientCsr, built.pem, { encoding: "utf8", mode: 0o600 });

    const csrPem = fs.readFileSync(paths.clientCsr, "utf8");
    return success(req.id, {
      csrPem,
      deviceId,
      dnsName,
      keyAlgorithm,
      // ⚠️ Se responde lo que se HIZO, no lo que se pidió.
      altKeyAlgorithm: built.hybrid ? "ML_DSA_65" : null,
      altKeyPath: altKey?.path ?? null,
      keyStore: "file",
      keyPath: paths.clientKey,
    });
  } catch (err: any) {
    return fail(req.id, "csr_generate_failed", err?.message || String(err));
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

    // Cert: 0600 — only privsvc (root) reads this. The agent never
    // touches cert files directly; gRPC connection goes through
    // priv.call("grpc.connect") which materialises Buffers in memory.
    fs.writeFileSync(paths.clientCert, clientCertPem, { encoding: "utf8", mode: 0o600 });
    // CA bundle: 0644 — public info, world-readable is fine. Matches
    // macOS shape so cross-platform tooling (debugging scripts that
    // dump the bundle) doesn't need root on either host.
    fs.writeFileSync(paths.caBundle, fullBundlePem, { encoding: "utf8", mode: 0o644 });

    const clientCertThumbprint = certFingerprintPem(clientCertPem);

    return success(req.id, {
      clientCertThumbprint,
      issuingCaThumbprint,
      clientCertPath: paths.clientCert,
      caBundlePath: paths.caBundle,
      keyStore: "file", // Linux is file-only — see top-of-file comment for why
      keychainLabel: null,
    });
  } catch (err: any) {
    return fail(req.id, "cert_install_failed", err?.message || String(err));
  }
}

// POST a JSON body to the backend renewal endpoint over mTLS. Used by
// the renewal flow only; identical to macOS's helper so behaviour is
// consistent across platforms.
function postJsonMtls(
  url: string,
  payload: any,
  identity: { clientCert: Buffer; clientKey: Buffer; caBundle: Buffer }
): Promise<any> {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify(payload), "utf8");
    const target = new URL(url);
    const trustAgentCa = process.env.CERT_RENEWAL_TRUST_AGENT_CA === "1";

    const request = https.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || 443,
      path: target.pathname + (target.search || ""),
      method: "POST",
      cert: identity.clientCert,
      key: identity.clientKey,
      ca: trustAgentCa ? identity.caBundle : undefined,
      headers: {
        "content-type": "application/json",
        "content-length": String(body.length),
      },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`renewal HTTP ${res.statusCode}: ${text.slice(0, 256)}`));
          return;
        }
        try {
          resolve(JSON.parse(text));
        } catch (err: any) {
          reject(new Error(`renewal response parse failed: ${err?.message || String(err)}`));
        }
      });
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

  // Pending paths declared up front so the finally{} cleanup can see
  // them even if we throw before writing them. Matches macOS shape so
  // the cleanup invariant ("any .pending file is leaked unless we
  // unlink it") is preserved.
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

    if (!serverBaseUrl) return fail(req.id, "bad_request", "serverBaseUrl required");
    if (!tenantId) return fail(req.id, "bad_request", "tenantId required");

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
      `subjectAltName = URI:tracenium://tenant/${tenantId}/device/${deviceId}`,
    ].join("\n");

    fs.writeFileSync(pendingConf, conf + "\n", { encoding: "utf8", mode: 0o600 });

    await execFileAsync(OPENSSL_BIN, [
      "genpkey",
      "-algorithm",
      "RSA",
      "-pkeyopt",
      `rsa_keygen_bits:${LINUX_CSR_KEY_BITS}`,
      "-out",
      pendingKey,
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
      pendingConf,
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
      // Atomic rename trio. If any of these fail mid-flight we restore
      // backups so the next gRPC connect attempt uses the previous
      // (still-valid until expiry) identity rather than a half-rolled
      // state.
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

    logger.info("cert_renewed", {
      deviceId,
      clientCertThumbprint,
      issuingCaThumbprint,
      notAfter: x509.validTo,
    });

    return success(req.id, {
      deviceId,
      clientCertPem,
      caBundlePem: fullBundlePem,
      clientCertThumbprint,
      issuingCaThumbprint,
      notAfter: x509.validTo,
      status: response.status || "pending",
      keyStore: "file",
      keychainLabel: null,
    });
  } catch (err: any) {
    return fail(req.id, "cert_renew_failed", err?.message || String(err));
  } finally {
    // Best-effort cleanup of every pending artifact. On the happy path
    // the .pending cert/key/ca files have already been renamed into
    // place and don't exist anymore, so unlinkSync errors are expected
    // — we swallow them. On a failure path (openssl crashed, renewal
    // API 5xx, rename collision) any of these could still be sitting
    // in CERT_DIR leaking disk and, worse, leaving a key PEM readable
    // by anyone who can read the dir. finally{} wins over mid-function
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
    caBundle,
  };
}
