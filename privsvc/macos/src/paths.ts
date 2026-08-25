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
    // DATA_DIR a 755, NO 700. Lo secreto vive en certs/, que se queda en 700
    // justo debajo, así que el contenido sigue sellado — lo único que 755
    // concede es ATRAVESAR el directorio.
    //
    // Con 700 el helper de captura (PrivSvc/macos/tracenium-screencap) era
    // inalcanzable: el privsvc lo lanza con `sudo -u <usuario>` para que corra
    // en la sesión gráfica, y ese proceso ya no es root, así que no podía ni
    // entrar en el directorio. El síntoma era
    //   sudo: unable to execute .../tracenium-screencap: Permission denied
    // que parece falta de bit de ejecución y no lo es.
    //
    // ⚠️ El postinstall del pkg ya ponía 755 aquí, pero esta línea lo revertía
    // en CADA arranque del privsvc — segundos después de instalar. Un arreglo
    // solo en el instalador no sobrevive; los dos sitios tienen que coincidir.
    fs.chmodSync(DATA_DIR, 0o755);
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
