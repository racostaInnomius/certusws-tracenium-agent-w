// privsvc/linux/src/gateway-key.ts
//
// ADR-0013 — la clave con la que se abre la credencial de vCenter.
//
// ── Por qué existe ─────────────────────────────────────────────────
//
// ADR-0001 decidió abrir el sobre sellado con la clave privada de
// ENROLAMIENTO. En Windows eso no funciona ni ha funcionado nunca: la
// clave se crea solo-firma y CNG rechaza descifrar con ella.
//
// Aquí SÍ funciona hoy, pero no porque sea correcto: descifrar con
// `certPaths().clientKey` contradice la misma extensión KeyUsage crítica
// (`digitalSignature`) del mismo certificado. Linux es simplemente la
// plataforma que no lo comprueba. Un mecanismo que depende de que nadie
// mire es un mecanismo que se rompe el día que alguien mira.
//
// ── Por qué nace con el rol y no con el enrolamiento ───────────────
//
// Una clave capaz de descifrar es precisamente lo que puede abrir datos
// sellados. Provisionarla en el enrolamiento se la daría a toda la flota
// para servir como mucho a un equipo por tenant — y a los tenants sin
// vCenter, a ninguno, nunca. Nace con `policy.gateway.vcenter` y muere
// con él.
//
// ── openssl y no node:crypto ───────────────────────────────────────
//
// Node no sabe emitir certificados X.509, solo claves. El resto del
// daemon ya se apoya en openssl para esto, y `-addext` está verificado
// en LibreSSL 3.3.6 y OpenSSL 3.6.3 — los dos extremos del rango que se
// encuentra en campo. La ruta con `-config` es una trampa documentada en
// `cdp-keys.ts`; no se repite aquí.

import fs from "fs";
import path from "path";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";
import { CERT_DIR, ensurePrivSvcDirs } from "./paths";
import { success, fail, type PrivSvcRequest, type PrivSvcResponse } from "./protocol";

const execFileAsync = promisify(execFile);
const OPENSSL_BIN = process.env.OPENSSL_BIN || "/usr/bin/openssl";

const KEY_BITS = 2048;
const VALID_DAYS = 1825; // 5 años, igual que la rama Windows.

export function gatewayKeyPaths() {
  return {
    key: path.join(CERT_DIR, "gateway-enc.key.pem"),
    cert: path.join(CERT_DIR, "gateway-enc.crt.pem"),
  };
}

export type GatewayKeyMaterial = {
  certPem: string;
  fingerprintSha256: string;
  notAfter: string | null;
};

/**
 * Huella SHA-256 del DER, en minúsculas y sin separadores.
 *
 * Es la forma exacta que el sobre usa como AAD del GCM y con la que se
 * elige la clave. Divergir aquí rompería la autenticación sin decir por
 * qué, así que existe una sola función y la usan todos.
 */
export function fingerprintOf(certPem: string): string {
  const der = pemToDer(certPem);
  return crypto.createHash("sha256").update(der).digest("hex").toLowerCase();
}

function pemToDer(pem: string): Buffer {
  const body = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  return Buffer.from(body, "base64");
}

/** El material actual, o null si este equipo no es gateway. */
export function readGatewayKey(): GatewayKeyMaterial | null {
  const paths = gatewayKeyPaths();
  // Las dos mitades o ninguna: una clave sin certificado no se puede
  // publicar, y un certificado sin clave no abre nada.
  if (!fs.existsSync(paths.cert) || !fs.existsSync(paths.key)) return null;
  try {
    const certPem = fs.readFileSync(paths.cert, "utf8");
    if (!certPem.includes("BEGIN CERTIFICATE")) return null;
    return {
      certPem,
      fingerprintSha256: fingerprintOf(certPem),
      notAfter: notAfterOf(certPem),
    };
  } catch {
    return null;
  }
}

/** La clave privada en PEM, para desellar. Null si no hay. */
export function readGatewayPrivateKeyPem(): string | null {
  const paths = gatewayKeyPaths();
  try {
    return fs.existsSync(paths.key) ? fs.readFileSync(paths.key, "utf8") : null;
  } catch {
    return null;
  }
}

function notAfterOf(certPem: string): string | null {
  try {
    return new crypto.X509Certificate(certPem).validTo;
  } catch {
    return null;
  }
}

/**
 * Alta idempotente.
 *
 * La sincronización de políticas llama a esto cada vez que ve el bloque
 * de gateway, no solo la primera. Si generase material nuevo en cada
 * llamada invalidaría la credencial ya sellada en cada sincronización,
 * así que devolver lo que ya hay es el comportamiento, no un atajo.
 */
export async function ensureGatewayKey(deviceId: string): Promise<GatewayKeyMaterial> {
  if (!deviceId || !deviceId.trim()) throw new Error("deviceId_required");

  const existing = readGatewayKey();
  if (existing) return existing;

  ensurePrivSvcDirs();
  const paths = gatewayKeyPaths();

  // Un intento anterior a medias deja una mitad suelta. Se retira antes
  // de crear: quedarse con la clave vieja y el certificado nuevo es
  // exactamente el estado que no abre nada y parece sano.
  destroyGatewayKey();

  try {
    await execFileAsync(OPENSSL_BIN, [
      "genpkey",
      "-algorithm", "RSA",
      "-pkeyopt", `rsa_keygen_bits:${KEY_BITS}`,
      "-out", paths.key,
    ]);
    // 0600 cuanto antes: en un daemon de sistema el modo del fichero ES
    // la frontera de seguridad.
    fs.chmodSync(paths.key, 0o600);

    await execFileAsync(OPENSSL_BIN, [
      "req", "-new", "-x509",
      "-key", paths.key,
      "-out", paths.cert,
      "-days", String(VALID_DAYS),
      "-sha256",
      "-subj", opensslSubject(deviceId),
      // Declara lo único que este material existe para hacer. Nadie
      // construye una cadena con este certificado —el navegador solo le
      // saca la clave pública— pero un certificado que miente sobre su
      // propósito es una línea que alguien se cree más adelante.
      "-addext", "keyUsage=critical,keyEncipherment",
      "-addext", "basicConstraints=critical,CA:FALSE",
    ]);
    fs.chmodSync(paths.cert, 0o644);

    const material = readGatewayKey();
    if (!material) throw new Error("gateway key material unreadable after creation");
    return material;
  } catch (err) {
    // La destrucción va en el MISMO camino que la creación. Un manejador
    // aparte es lo que alguien se olvida de llamar, y lo que se olvida
    // aquí es una clave de descifrado huérfana.
    destroyGatewayKey();
    throw err;
  }
}

/** Baja idempotente: que ya no esté es el estado deseado. */
export function destroyGatewayKey(): { removed: boolean } {
  const paths = gatewayKeyPaths();
  let removed = false;
  for (const file of [paths.key, paths.cert]) {
    try {
      if (fs.existsSync(file)) {
        fs.rmSync(file, { force: true });
        removed = true;
      }
    } catch {
      /* otro proceso se adelantó, o el fichero desapareció */
    }
  }
  return { removed };
}

/**
 * `CN=...,OU=<deviceId>` en el formato con barras que espera openssl.
 *
 * ⚠️ El deviceId llega del llamante y termina dentro de un DN. Una barra
 * sin escapar abriría un componente nuevo del sujeto; se rechaza en
 * lugar de reinterpretarse, porque un sujeto silenciosamente distinto
 * del pedido es peor que un error.
 */
export function opensslSubject(deviceId: string): string {
  const clean = deviceId.trim();
  if (!clean || /[/\\\n\r]/.test(clean)) throw new Error("deviceId_invalid");
  return `/CN=Tracenium Gateway Credential Key/OU=${clean}`;
}

// ── Handlers IPC ────────────────────────────────────────────────────

export async function handleGatewayKeyEnsure(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const deviceId = String(req.params?.deviceId || req.meta?.deviceId || "").trim();
  if (!deviceId) return fail(req.id, "bad_request", "deviceId required");
  try {
    const material = await ensureGatewayKey(deviceId);
    return success(req.id, material);
  } catch (e: any) {
    return fail(req.id, "gateway_key_error", e?.message || "could not provision the gateway key");
  }
}

export async function handleGatewayKeyDestroy(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    return success(req.id, { ok: true, ...destroyGatewayKey() });
  } catch (e: any) {
    return fail(req.id, "gateway_key_error", e?.message || "could not remove the gateway key");
  }
}
