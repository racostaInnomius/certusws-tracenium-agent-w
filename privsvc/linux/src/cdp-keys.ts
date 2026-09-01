// privsvc/linux/src/cdp-keys.ts
//
// ADR-0011 FASE 2 — `cdp.csr.generate` parametrizado, con almacen de
// clave SEPARADO y ciclo de vida completo (decision 9).
//
// Gemelo de `privsvc/macos/src/cdp-keys.ts` y de `CdpKeys.cs`. Se
// mantienen paralelos a proposito: tres implementaciones de la misma
// regla que divergen son peores que una sola, porque nadie sabe cual
// manda. El CONTRATO —validacion del keyId, prefijo reservado, registro,
// destruccion en el mismo camino de codigo— es identico; lo unico que
// cambia es donde vive la clave.
//
// ── Por que aqui SI es un fichero, y no es deuda ────────────────────
//
// La decision 9.b fija el objetivo por plataforma, y para Linux dice
// literalmente «TPM2 via PKCS#11, o fichero `0600` en directorio
// restringido». Es decir: esto cumple el objetivo declarado, no lo
// aplaza. macOS necesitaba llavero porque su punto de partida era un
// fichero SIN esa decision escrita; aqui esta escrita.
//
// ⚠️ La separacion respecto a la clave de enrolamiento es ESTRUCTURAL:
// el llamante entrega un `keyId` opaco y este modulo DERIVA la ruta. Un
// llamante que pida `../client` no llega a ninguna parte, porque la ruta
// que se usa nunca es la que mando.

import fs from "fs";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import { CERT_DIR, certPaths } from "./paths";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";

const execFileAsync = promisify(execFile);
const OPENSSL_BIN = process.env.OPENSSL_BIN || "/usr/bin/openssl";
const OPENSSL_TIMEOUT_MS = 30_000;

/** Prefijo reservado. Ninguna clave de enrolamiento lo lleva. */
export const CDP_KEY_PREFIX = "tracenium-cdp-";

/**
 * `keyId` aceptable. Identico al de macOS y al de Windows a proposito.
 *
 * Deliberadamente estrecho: sin `/`, sin `\`, sin `..`, sin espacios, y
 * con tope de longitud. Minusculas porque en Windows los nombres de
 * clave CNG no distinguen la caja de forma fiable, y dos `keyId` que
 * solo difieran en mayusculas serian dos claves aqui y una alli — una
 * divergencia silenciosa entre sistemas operativos.
 */
const KEY_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export function isValidKeyId(keyId: unknown): keyId is string {
  if (typeof keyId !== "string") return false;
  if (!KEY_ID_RE.test(keyId)) return false;
  if (keyId.includes("..")) return false;
  return true;
}

/** Directorio propio, separado del de enrolamiento. */
export function cdpKeyDir(): string {
  return path.join(CERT_DIR, "cdp-keys");
}

/**
 * Ruta derivada. El llamante NUNCA la elige.
 *
 * Se resuelve y se comprueba que sigue dentro del directorio: la
 * derivacion ya lo garantiza con el regex de arriba, pero esta es la
 * clase de invariante que conviene que falle ruidosamente el dia que
 * alguien lo relaje. Mismo patron que el guard de escritura de la
 * fase 1.
 */
export function cdpKeyPath(keyId: string): string {
  if (!isValidKeyId(keyId)) throw new Error("invalid_key_id");
  const dir = cdpKeyDir();
  const p = path.resolve(path.join(dir, `${keyId}.key.pem`));
  if (!p.startsWith(dir + path.sep)) throw new Error("invalid_key_id");
  // Y que jamas sea la identidad mTLS del agente. Reutilizar esa ruta es
  // exactamente la caida de flota que describe la correccion de ADR-0004.
  if (p === path.resolve(certPaths().clientKey)) {
    throw new Error("refuses_to_touch_enrollment_key");
  }
  return p;
}

function ensureKeyDir(): void {
  // ⚠️ Solo el directorio propio, NO `ensurePrivSvcDirs()`. Esa crea el
  // arbol entero del PrivSvc —incluido el del socket en /run— y un
  // generador de CSR no tiene por que crear eso: en cuanto una de esas
  // rutas no es escribible, la emision falla por un motivo que no tiene
  // nada que ver con ella. Se midio exactamente asi.
  const dir = cdpKeyDir();
  fs.mkdirSync(dir, { recursive: true });
  // 0700: el «directorio restringido» que pide la decision 9.b. El
  // CERT_DIR de Linux esta a 0750 y aqui se aprieta un escalon mas,
  // porque lo que hay dentro son claves sin certificado — utilidad cero
  // y responsabilidad no-cero.
  try {
    fs.chmodSync(dir, 0o700);
  } catch {}
}

// ── Registro: desde cuando y por que ────────────────────────────────
//
// ⚠️ NO es la fuente de verdad de que hay: eso lo dice el directorio.
// El registro solo enriquece. Al reves, un registro desincronizado
// inventariaria claves que no existen.

export type KeyLedgerEntry = {
  keyId: string;
  subject: string;
  createdAt: string;
  requestId?: string | null;
  certInstalledAt?: string | null;
};

function ledgerPath(): string {
  return path.join(cdpKeyDir(), "ledger.json");
}

export function readLedger(): Record<string, KeyLedgerEntry> {
  try {
    const parsed = JSON.parse(fs.readFileSync(ledgerPath(), "utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function writeLedger(data: Record<string, KeyLedgerEntry>): void {
  try {
    ensureKeyDir();
    const tmp = `${ledgerPath()}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { encoding: "utf8", mode: 0o600 });
    fs.renameSync(tmp, ledgerPath());
  } catch (err) {
    logger.warn(`cdp-keys: no se pudo persistir el registro: ${String(err)}`);
  }
}

export function recordKey(entry: KeyLedgerEntry): void {
  const l = readLedger();
  l[entry.keyId] = entry;
  writeLedger(l);
}

export function forgetKey(keyId: string): void {
  const l = readLedger();
  delete l[keyId];
  writeLedger(l);
}

export function markCertInstalled(keyId: string, whenIso?: string): void {
  const l = readLedger();
  if (!l[keyId]) return;
  l[keyId].certInstalledAt = whenIso || new Date().toISOString();
  writeLedger(l);
}

// ── CSR ─────────────────────────────────────────────────────────────

const EKUS: Record<string, string> = {
  clientAuth: "clientAuth",
  serverAuth: "serverAuth"
};

/** Los atributos de sujeto admitidos. Los mismos que el helper de macOS. */
const SUBJECT_ATTRS = new Set(["CN", "O", "OU"]);

/**
 * Traduce "CN=a,O=b" al formato con barras que espera openssl, RECHAZANDO
 * lo que no reconoce.
 *
 * ⚠️ El rechazo es el punto entero de esta funcion. Medido en LibreSSL
 * 3.3.6 y OpenSSL 3.6.3: un sujeto con un atributo desconocido NO falla,
 * los dos AVISAN y lo DESCARTAN —«Subject Attribute ZZ has no known NID,
 * skipped»— y emiten el CSR sin el. Es decir, el llamante pide un sujeto
 * y la CA firma otro, sin que nadie se entere.
 *
 * El helper de macOS ya rechazaba lo que no fuera CN/O/OU, asi que sin
 * esto las dos plataformas emitirian cosas distintas ante la misma
 * peticion — exactamente la divergencia que el ADR dice que no puede
 * haber.
 */
export function toOpensslSubject(subject: string): string {
  const partes = subject.startsWith("/")
    ? subject.slice(1).split("/")
    : subject.split(",");

  const salida: string[] = [];
  for (const parte of partes) {
    const trozo = parte.trim();
    if (!trozo) continue;
    const i = trozo.indexOf("=");
    if (i <= 0) throw new Error(`componente de subject invalido: ${trozo}`);
    const clave = trozo.slice(0, i).trim().toUpperCase();
    const valor = trozo.slice(i + 1).trim();
    if (!SUBJECT_ATTRS.has(clave)) {
      throw new Error(`atributo de subject no soportado: ${clave} (solo CN, O, OU)`);
    }
    if (!valor) throw new Error(`atributo de subject sin valor: ${clave}`);
    salida.push(`${clave}=${valor}`);
  }
  if (salida.length === 0) throw new Error("subject vacio");
  return "/" + salida.join("/");
}

/**
 * Extensiones del CSR, como argumentos `-addext`.
 *
 * ⚠️ Sin fichero de configuracion, y no por gusto. Con `-config` hay que
 * declarar `distinguished_name` apuntando a una seccion `[dn]`, y como
 * el sujeto entra por `-subj` esa seccion queda vacia — momento en el
 * que openssl aborta con «no objects specified in config file», que no
 * menciona el sujeto por ningun lado. Quitar `distinguished_name` no
 * arregla nada: LibreSSL entonces pide «unable to find
 * 'distinguished_name' in config». Las dos medidas.
 *
 * La salida es rellenar `[dn]` con un sujeto de relleno que `-subj`
 * pisa, o no usar config. Se elige lo segundo: un sujeto escrito en un
 * fichero que NO es el que sale es exactamente la clase de linea que
 * alguien lee mas adelante y se cree.
 *
 * `-addext` verificado en LibreSSL 3.3.6 y OpenSSL 3.6.3, que son los
 * dos extremos del rango que se va a encontrar en campo.
 */
export function buildCsrExtArgs(dnsNames: string[], uris: string[], eku: string): string[] {
  const args = [
    "-addext", "keyUsage=critical,digitalSignature",
    "-addext", `extendedKeyUsage=${eku}`
  ];
  const alt = [
    ...dnsNames.map((d) => `DNS:${d}`),
    ...uris.map((u) => `URI:${u}`)
  ];
  // Sin SAN no se emite la extension: una `subjectAltName=` vacia hace
  // fallar a openssl.
  if (alt.length > 0) args.push("-addext", `subjectAltName=${alt.join(",")}`);
  return args;
}

// ── Handlers IPC ────────────────────────────────────────────────────

/**
 * `cdp.csr.generate`.
 *
 * ⚠️ Decision 9.c: la destruccion va en el MISMO camino de codigo que la
 * creacion. Si algo falla despues de generar la clave, se borra aqui
 * antes de responder — un manejador aparte es lo que alguien se olvida
 * de cablear.
 */
export async function handleCdpCsrGenerate(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const p: any = req.params || {};
  const keyId = String(p.keyId || "");

  if (!isValidKeyId(keyId)) {
    return fail(req.id, "bad_request", "keyId invalido (min: [a-z0-9][a-z0-9._-]{0,63})");
  }

  const subject = String(p.subject || "").trim();
  if (!subject) return fail(req.id, "bad_request", "subject requerido");
  // Se acepta el mismo formato con comas que macOS y se traduce al de
  // barras que espera openssl, para que el llamante no tenga que saber
  // en que sistema operativo aterriza. La traduccion RECHAZA lo que no
  // reconoce; ver la nota de toOpensslSubject.
  let subj: string;
  try {
    subj = toOpensslSubject(subject);
  } catch (err: any) {
    return fail(req.id, "bad_request", String(err?.message || err));
  }

  const ekuIn = String(p.eku || "clientAuth");
  const eku = EKUS[ekuIn];
  if (!eku) return fail(req.id, "bad_request", `eku no soportado: ${ekuIn} (clientAuth|serverAuth)`);

  const keyAlgorithm = String(p.keyAlgorithm || "RSA_2048").toUpperCase();
  if (keyAlgorithm !== "RSA_2048") {
    return fail(req.id, "bad_request", `keyAlgorithm no soportado: ${keyAlgorithm}`);
  }

  // Se recorta ANTES de filtrar. Un nombre que solo tiene espacios es
  // "truthy" y llegaria hasta openssl como `DNS: `, que aborta el
  // comando entero con «Error loading command line extensions» — un
  // fallo a mitad de camino por una entrada que se podia rechazar aqui.
  const dns = Array.isArray(p.dnsNames)
    ? p.dnsNames.map((d: any) => String(d).trim()).filter(Boolean)
    : [];
  const uris = Array.isArray(p.uris)
    ? p.uris.map((u: any) => String(u).trim()).filter(Boolean)
    : [];

  let keyPath: string;
  try {
    ensureKeyDir();
    keyPath = cdpKeyPath(keyId);
  } catch (err: any) {
    return fail(req.id, "bad_request", String(err?.message || err));
  }

  // Registro ANTES de crear (ver la nota del gemelo de macOS): asi es
  // un superconjunto y ninguna clave puede quedar sin entrada.
  recordKey({
    keyId,
    subject,
    createdAt: new Date().toISOString(),
    requestId: p.requestId ? String(p.requestId) : null,
    certInstalledAt: null
  });

  const csrPath = `${keyPath}.csr`;
  let claveCreada = false;

  try {
    await execFileAsync(
      OPENSSL_BIN,
      ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", keyPath],
      { timeout: OPENSSL_TIMEOUT_MS }
    );
    fs.chmodSync(keyPath, 0o600);
    claveCreada = true;

    await execFileAsync(
      OPENSSL_BIN,
      [
        "req", "-new", "-sha256",
        "-key", keyPath,
        "-subj", subj,
        ...buildCsrExtArgs(dns, uris, eku),
        "-out", csrPath
      ],
      { timeout: OPENSSL_TIMEOUT_MS }
    );

    const csrPem = fs.readFileSync(csrPath, "utf8");

    return success(req.id, {
      keyId,
      csrPem,
      keyAlgorithm: "RSA_2048",
      // Se DECLARA lo que es, sin adornarlo. En Linux la clave es un
      // fichero 0600 en directorio 0700 — es lo que la decision 9.b
      // acepta aqui, y llamarlo de otra forma seria mentir en el
      // inventario.
      keyStore: "file-restricted"
    });
  } catch (err: any) {
    if (claveCreada) {
      try {
        fs.rmSync(keyPath, { force: true });
      } catch {}
    }
    forgetKey(keyId);
    return fail(req.id, "csr_failed", String(err?.stderr || err?.message || err).trim().split("\n")[0]);
  } finally {
    // El CSR es publico, pero no hay motivo para dejarlo: ya viaja en la
    // respuesta.
    try {
      fs.rmSync(csrPath, { force: true });
    } catch {}
  }
}

/**
 * `cdp.key.destroy` — la ejecuta el AGENTE, no el control plane
 * (decision 9.c): el control plane puede ser el adversario, puede estar
 * caido, y no tiene acceso al almacen.
 *
 * ⚠️ Se hace `unlink`, no `shred`. Sobre un ext4 con journal, overlayfs
 * o un SSD con wear levelling, sobrescribir el fichero no garantiza nada
 * y solo daria una sensacion de seguridad que no se corresponde con lo
 * que ocurre. Lo que de verdad reduce el riesgo es que la clave casi no
 * exista (9.a) — y eso es una decision de secuencia, no de borrado.
 */
export async function handleCdpKeyDestroy(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const keyId = String((req.params as any)?.keyId || "");
  if (!isValidKeyId(keyId)) return fail(req.id, "bad_request", "keyId invalido");

  let keyPath: string;
  try {
    keyPath = cdpKeyPath(keyId);
  } catch (err: any) {
    return fail(req.id, "bad_request", String(err?.message || err));
  }

  const existia = fs.existsSync(keyPath);
  try {
    fs.rmSync(keyPath, { force: true });
  } catch (err: any) {
    return fail(req.id, "key_delete_failed", String(err?.message || err));
  }
  // Se VERIFICA. «No lanzo» no es lo mismo que «ya no esta», y la
  // destruccion es una fase obligatoria del ciclo, no una limpieza
  // optimista.
  if (fs.existsSync(keyPath)) {
    return fail(req.id, "key_delete_incomplete", "la clave sigue en disco tras el borrado");
  }

  forgetKey(keyId);
  return success(req.id, { keyId, destroyed: existia ? 1 : 0 });
}

/**
 * `cdp.key.list` — decision 9.d.
 *
 * El respaldo no puede ser solo un cron: un respaldo que nadie mira se
 * pudre, y entonces el diseño PARECE completo mientras el residuo se
 * acumula en silencio (`purge_after` en este mismo repositorio). Esto es
 * lo que hace que una huerfana aparezca en el panel.
 */
export async function handleCdpKeyList(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const dir = cdpKeyDir();
  let ficheros: string[] = [];
  try {
    ficheros = fs.readdirSync(dir).filter((f) => f.endsWith(".key.pem"));
  } catch {
    return success(req.id, { keys: [], count: 0 });
  }

  const ledger = readLedger();
  const ahora = Date.now();

  const keys = ficheros.map((f) => {
    const keyId = f.slice(0, -".key.pem".length);
    const meta = ledger[keyId];
    // Sin registro se usa el mtime del fichero. Una clave sin entrada es
    // justamente la mas sospechosa —quedo de un fallo a medias— y
    // dejarla sin edad la escondería del panel.
    let createdAt = meta?.createdAt || null;
    if (!createdAt) {
      try {
        createdAt = fs.statSync(path.join(dir, f)).mtime.toISOString();
      } catch {}
    }
    return {
      keyId,
      subject: meta?.subject ?? null,
      createdAt,
      requestId: meta?.requestId ?? null,
      certInstalledAt: meta?.certInstalledAt ?? null,
      orphan: !meta?.certInstalledAt,
      ageDays: createdAt ? Math.floor((ahora - Date.parse(createdAt)) / 86_400_000) : null
    };
  });

  return success(req.id, { keys, count: keys.length });
}
