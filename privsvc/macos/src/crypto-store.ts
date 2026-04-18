import crypto from "crypto";
import fs from "fs";
import https from "https";
import os from "os";
import { execFile } from "child_process";
import { promisify } from "util";
import { certPaths, ensurePrivSvcDirs } from "./paths";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";

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

async function installCaCertificatesToSystemKeychain(bundlePem: string): Promise<void> {
  const certs = splitPemCertificates(bundlePem);
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

    await installCaCertificatesToSystemKeychain(fullBundlePem).catch(() => undefined);

    const clientCertThumbprint = certFingerprintPem(clientCertPem);

    return success(req.id, {
      clientCertThumbprint,
      issuingCaThumbprint,
      clientCertPath: paths.clientCert,
      caBundlePath: paths.caBundle,
      keyStore: "file"
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
  try {
    ensurePrivSvcDirs();
    const paths = certPaths();
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

    const pendingKey = `${paths.clientKey}.pending`;
    const pendingCsr = `${paths.clientCsr}.pending`;
    const pendingConf = `${paths.clientCsr}.cnf`;
    const pendingCert = `${paths.clientCert}.pending`;
    const pendingCa = `${paths.caBundle}.pending`;

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

    await installCaCertificatesToSystemKeychain(fullBundlePem).catch(() => undefined);

    for (const file of [pendingCsr, pendingConf]) {
      try { fs.unlinkSync(file); } catch {}
    }

    return success(req.id, {
      deviceId,
      clientCertPem,
      caBundlePem: fullBundlePem,
      clientCertThumbprint,
      issuingCaThumbprint,
      notAfter: x509.validTo,
      status: response.status || "pending",
      keyStore: "file"
    });
  } catch (err: any) {
    return fail(req.id, "cert_renew_failed", err?.message || String(err));
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
