import crypto from "crypto";
import fs from "fs";
import https from "https";
import { execFile } from "child_process";
import { promisify } from "util";
import { certPaths, ensurePrivSvcDirs } from "./paths";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";

const execFileAsync = promisify(execFile);
const OPENSSL_BIN = process.env.OPENSSL_BIN || "/usr/bin/openssl";

function normalizePem(value: any): string {
  return String(value || "").trim() + "\n";
}

function certFingerprintPem(pem: string): string {
  const x509 = new crypto.X509Certificate(pem);
  return String(x509.fingerprint256 || "").replace(/:/g, "").toLowerCase();
}

function assertDeviceId(value: any): string {
  const deviceId = String(value || "").trim();
  if (!deviceId) throw new Error("deviceId_required");
  return deviceId;
}

export async function handleGenerateCsr(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    ensurePrivSvcDirs();
    const paths = certPaths();
    const params = req.params || {};
    const tenantId = String(params.tenantId || req.meta?.tenantId || "bootstrap");
    const deviceId = assertDeviceId(params.deviceId || req.meta?.deviceId);
    const reuseExistingKey = params.reuseExistingKey !== false;

    if (!reuseExistingKey || !fs.existsSync(paths.clientKey)) {
      await execFileAsync(OPENSSL_BIN, [
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        paths.clientKey
      ]);
      fs.chmodSync(paths.clientKey, 0o600);
    }

    const subject = `/CN=tracenium-agent-${deviceId}/O=Tracenium/OU=${tenantId}`;
    await execFileAsync(OPENSSL_BIN, [
      "req",
      "-new",
      "-sha256",
      "-key",
      paths.clientKey,
      "-subj",
      subject,
      "-out",
      paths.clientCsr
    ]);

    const csrPem = fs.readFileSync(paths.clientCsr, "utf8");
    return success(req.id, {
      csrPem,
      deviceId,
      keyAlgorithm: "ECDSA_P256",
      keyStore: "file",
      keyPath: paths.clientKey
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

    fs.writeFileSync(paths.clientCert, clientCertPem, { encoding: "utf8", mode: 0o600 });
    fs.writeFileSync(paths.caBundle, caBundlePem, { encoding: "utf8", mode: 0o644 });

    const clientCertThumbprint = certFingerprintPem(clientCertPem);
    const issuingCaThumbprint = certFingerprintPem(caBundlePem);

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

    const request = https.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || 443,
      path: `${target.pathname}${target.search}`,
      method: "POST",
      cert: identity.clientCert,
      key: identity.clientKey,
      ca: identity.caBundle,
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
      "ecparam",
      "-name",
      "prime256v1",
      "-genkey",
      "-noout",
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

    fs.writeFileSync(pendingCert, clientCertPem, { encoding: "utf8", mode: 0o600 });
    fs.writeFileSync(pendingCa, caBundlePem, { encoding: "utf8", mode: 0o644 });

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
    const issuingCaThumbprint = certFingerprintPem(caBundlePem);
    const x509 = new crypto.X509Certificate(clientCertPem);

    for (const file of [pendingCsr, pendingConf]) {
      try { fs.unlinkSync(file); } catch {}
    }

    return success(req.id, {
      deviceId,
      clientCertPem,
      caBundlePem,
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
  const caBundle = fs.readFileSync(paths.caBundle);

  return {
    clientCert,
    clientKey,
    caBundle
  };
}
