import crypto from "crypto";
import fs from "fs";
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
