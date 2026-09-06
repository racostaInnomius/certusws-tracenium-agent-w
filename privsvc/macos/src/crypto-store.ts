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
  saveAnchorState,
  describeAnchorVerdict,
  type AnchorPinMode,
  type AnchorPinVerdict
} from "./anchor-pin";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";
// ADR-0015 — compartido con Linux a propósito: es aritmética sobre bytes
// que el backend tiene que aceptar, y dos copias que divergen dejan una
// plataforma sin poder enrolar. Ver privsvc/shared/der.ts.
import { buildCsr, ClassicAlgorithm } from "../../shared/pkcs10";
import { loadOrCreateAltKey } from "../../shared/alt-key";

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
 * Evalua el bundle contra los pines, lo registra RUIDOSAMENTE, persiste
 * la linea base y GUARDA el veredicto para que pueda salir del equipo.
 *
 * ⚠️ Correccion 2026-09-03: este comentario decia que el veredicto se
 * devolvia «para que el llamante pueda incluirlo en la respuesta IPC».
 * Ningun llamante lo hacia — los dos lo usaban solo para filtrar
 * `rejected`. La intencion estaba escrita y el cableado no existia, que
 * es como el modo `observe` acabo observando hacia un log local que
 * nadie lee. Ahora se persiste aqui, y `cdp.anchor.state` lo sirve.
 */
function applyAnchorPin(bundlePem: string, source: "enroll" | "renew"): AnchorPinVerdict {
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

  // ADR-0011 fase 0, paso 1. Persistir el veredicto es lo que permite
  // que el ciclo de facts lo suba: el log local no lo lee nadie desde el
  // control plane, y sin dato no se puede decidir el paso a `enforce`.
  //
  // Se guarda DESPUES de los pines y aparte: un fallo aqui no debe
  // impedir que la linea base quede fijada, que es la defensa. La
  // telemetria es lo accesorio de los dos.
  try {
    saveAnchorState(CERT_DIR, verdict, mode, source);
  } catch (err) {
    logger.warn(`anchor-pin: no se pudo persistir el veredicto: ${String(err)}`);
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
      // El fallo se REGISTRA. Estos dos `.catch(() => undefined)` eran
      // el hallazgo menor del gate 1 de ADR-0011: plantar un ancla —o
      // no plantarla— fallaba en silencio en las dos rutas. El aviso de
      // fuera ya no se traga el error, pero sin esto seguiría sin poder
      // decir CUÁL de los certificados del bundle falló.
      const esRaiz = entry.cert.subject === entry.cert.issuer;
      const args = esRaiz
        ? ["add-trusted-cert", "-d", "-r", "trustRoot", "-k", KEYCHAIN_PATH, entry.file]
        : ["add-certificates", "-k", KEYCHAIN_PATH, entry.file];

      await execFileAsync("/usr/bin/security", args).catch((err) => {
        logger.warn(
          `${esRaiz ? "add-trusted-cert" : "add-certificates"} fallo para ` +
            `${entry.cert.subject}: ${String(err?.stderr || err?.message || err).trim().split("\n")[0]}`
        );
      });
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
// ⚠️ ADR-0011 decisión 9.b pedía llevar ESTA clave a un almacén no
// extraíble, y no se puede mientras el transporte sea grpc-js. Se
// enumeraron los consumidores en macOS, y son cinco:
//
//   grpc-bridge.ts:1046  grpc.credentials.createSsl(ca, key, cert)
//   crypto-store.ts:562  https.request({ key })  — la renovación
//   credential-store.ts  crypto.createPrivateKey(...)
//   dp.ts:194            mTLS contra el distribution point
//   sdp.ts:587           curl --key <RUTA>  ← ni siquiera admite bytes
//
// Los cinco necesitan el material; el último necesita además un FICHERO.
// Una clave que no sale del llavero no puede alimentar a ninguno.
//
// Eso reencuadra la deuda que el ADR daba por «de macOS»: no lo es, es
// del transporte. Windows se libra porque su puente es C# y SChannel
// firma con un handle de CNG sin ver la clave nunca; macOS y Linux van
// por grpc-js, que solo entiende buffers, así que la identidad del
// agente es un fichero en LAS DOS.
//
// El almacén no extraíble sí existe ya, en `keystore.ts`, y es donde
// nacerán las claves de la fase 2 (`cdp.csr.generate`) — nuevas, sin
// este lastre.
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

/**
 * ¿La clave de este fichero es del algoritmo que se ha pedido?
 *
 * ⚠️ Reutilizar sin comprobar el ALGORITMO fue el fallo latente del
 * contrato viejo: `reuseExistingKey` sólo miraba que hubiera una RSA de
 * 2048. Con dos algoritmos en juego, un equipo que ya tuviera RSA
 * seguiría reutilizándola para siempre y nunca llegaría a P-384 — la
 * migración se quedaría en el papel sin que nada fallara.
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

  if (canReuse) {
    return;
  }

  try {
    fs.rmSync(keyPath, { force: true });
  } catch {}

  const args = alg === "RSA_2048"
    ? ["genpkey", "-algorithm", "RSA", "-pkeyopt", `rsa_keygen_bits:${MACOS_CSR_KEY_BITS}`, "-out", keyPath]
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
    // silencio — exactamente la clase de fallo que rompió el
    // enrolamiento de Windows.
    //
    // ADR-0015 punto 7: la lista deja de ser sólo RSA_2048. Se añade
    // EC_P384 (el suelo clásico de CNSA 2.0, lo que prepara
    // rotate-phase0.sh) y, aparte, `altKeyAlgorithm` para la mitad
    // post-cuántica. Son dos ejes distintos a propósito: la clásica
    // decide qué firma el PKCS#10 y la alternativa si además hay una
    // segunda prueba de posesión.
    const keyAlgorithm = String(params.keyAlgorithm || "RSA_2048").toUpperCase();
    if (keyAlgorithm !== "RSA_2048" && keyAlgorithm !== "EC_P384") {
      return fail(
        req.id,
        "bad_request",
        `unsupported keyAlgorithm on macOS: ${keyAlgorithm} (RSA_2048 | EC_P384)`
      );
    }

    // ⚠️ Ausente significa CLÁSICO, no error. Es lo que permite desplegar
    // este agente antes de que exista una Issuing híbrida: un agente
    // nuevo contra el backend de hoy sigue enrolando exactamente igual.
    const altKeyAlgorithm = String(params.altKeyAlgorithm || "").toUpperCase();
    if (altKeyAlgorithm && altKeyAlgorithm !== "ML_DSA_65") {
      return fail(
        req.id,
        "bad_request",
        `unsupported altKeyAlgorithm on macOS: ${altKeyAlgorithm} (ML_DSA_65)`
      );
    }

    await ensureEnrollmentPrivateKey(paths.clientKey, reuseExistingKey, keyAlgorithm);

    // ADR-0015 punto 8 — el CSR lo construimos nosotros.
    //
    // ⚠️ AQUÍ VIVÍA UN `openssl req -new -config`. No se sustituye por
    // gusto: `openssl req` NO PUEDE hacer un CSR híbrido. La
    // subjectAltPublicKeyInfo lleva una SPKI de ML-DSA que el openssl de
    // macOS ni siquiera sabe construir —es LibreSSL— y la prueba de
    // posesión alternativa tiene que firmarse sobre el propio
    // CertificationRequestInfo y meterse DENTRO de él, que es un problema
    // de huevo y gallina sin solución en línea de comandos.
    //
    // El camino es ÚNICO para clásico e híbrido a propósito: dos caminos
    // dejarían el clásico —el 100% de la flota hoy— peor probado que el
    // que casi nadie usa todavía.
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
      // ⚠️ Se responde lo que se HIZO, no lo que se pidió. Un agent-core
      // que pidiera híbrido y recibiera clásico sin enterarse creería
      // tener una mitad post-cuántica que nadie le dio.
      altKeyAlgorithm: built.hybrid ? "ML_DSA_65" : null,
      altKeyPath: altKey?.path ?? null,
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

    const { fullBundlePem, issuingCaThumbprint } = buildFullCaBundlePem(caBundlePem);

    fs.writeFileSync(paths.clientCert, clientCertPem, { encoding: "utf8", mode: 0o600 });
    fs.writeFileSync(paths.caBundle, fullBundlePem, { encoding: "utf8", mode: 0o644 });

    // El pin se evalua ANTES de instalar, y el fallo deja de ser mudo:
    // el `.catch(() => undefined)` que habia aqui se tragaba tanto un
    // error de instalacion como un ancla inesperada.
    const anchorVerdict = applyAnchorPin(fullBundlePem, "enroll");
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
    const anchorVerdict = applyAnchorPin(fullBundlePem, "renew");
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
