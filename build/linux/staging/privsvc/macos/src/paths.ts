import fs from "fs";
import path from "path";

const configuredSocketPath = process.env.TRACENIUM_PRIVSVC_SOCKET_PATH;

export const RUN_DIR = configuredSocketPath
  ? path.dirname(configuredSocketPath)
  : "/var/run/tracenium";
export const SOCKET_PATH = configuredSocketPath || path.join(RUN_DIR, "privsvc.sock");
export const DATA_DIR = process.env.TRACENIUM_PRIVSVC_DATA_DIR || "/Library/Application Support/Tracenium/PrivSvc";
export const CERT_DIR = path.join(DATA_DIR, "certs");
export const ASSETS_DIR = path.join(DATA_DIR, "assets");
export const LOG_DIR = process.env.TRACENIUM_PRIVSVC_LOG_DIR || "/Library/Logs/Tracenium";

export function ensurePrivSvcDirs() {
  for (const dir of [RUN_DIR, DATA_DIR, CERT_DIR, ASSETS_DIR, LOG_DIR]) {
    fs.mkdirSync(dir, { recursive: true });
  }

  try {
    fs.chmodSync(RUN_DIR, 0o755);
    fs.chmodSync(DATA_DIR, 0o700);
    fs.chmodSync(CERT_DIR, 0o700);
    fs.chmodSync(ASSETS_DIR, 0o755);
    fs.chmodSync(LOG_DIR, 0o755);
  } catch {}
}

export function certPaths() {
  return {
    clientKey: path.join(CERT_DIR, "client.key.pem"),
    clientCsr: path.join(CERT_DIR, "client.csr.pem"),
    clientCert: path.join(CERT_DIR, "client.crt.pem"),
    caBundle: path.join(CERT_DIR, "ca-bundle.crt.pem"),
    bundledRootCa: path.join(ASSETS_DIR, "root-ca.crt")
  };
}
