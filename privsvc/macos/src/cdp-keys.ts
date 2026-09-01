// privsvc/macos/src/cdp-keys.ts
//
// ADR-0011 FASE 2 — `cdp.csr.generate` parametrizado, con almacen de
// clave SEPARADO y ciclo de vida completo (decision 9).
//
// ── Por que un metodo nuevo y no reutilizar el de enrolamiento ──────
//
// Lo pide la correccion medida de ADR-0004 (2026-08-13), que desmonta la
// premisa de que generalizar el CSR fuera «cableado»:
//
//   · `crypto.csr.generate` escribe a rutas FIJAS. Invocarlo para un
//     certificado arbitrario SOBRESCRIBIRIA la clave de enrolamiento del
//     agente — o sea, una caida de flota.
//   · Sujeto y extensiones son fijos (CN=hostname, clientAuth, SAN con
//     el URI `tracenium://`). Un certificado de servidor necesita
//     serverAuth y otro SAN.
//   · Solo acepta RSA_2048.
//
// ⚠️ Y hay un agujero de hoy que esto viene a cerrar: en Windows,
// `crypto.csr.generate` YA acepta un `keyName` del llamante SIN validar
// (`CryptoCsr.cs:39`), y el de enrolamiento es `tracenium-{deviceId}`.
// Una peticion con ese nombre y `reuseExistingKey:false` borra y
// recrea la identidad mTLS del agente. Ese es exactamente el escenario
// de caida de flota, alcanzable hoy desde el control plane.
//
// ── La separacion es ESTRUCTURAL, no por convenio ───────────────────
//
// El llamante NO nombra el sitio de almacenamiento: entrega un `keyId`
// opaco y este modulo DERIVA la etiqueta. Un llamante que pida
// `../client` o `tracenium-<deviceId>` no llega a ninguna parte, porque
// el nombre que se usa nunca es el que mando.
//
// Y encima se comprueba el resultado contra la ubicacion de
// enrolamiento antes de tocar nada. Es redundante a proposito: la
// derivacion ya lo impide, pero esta es la clase de invariante que
// conviene que falle ruidosamente si alguien cambia el prefijo.

import fs from "fs";
import path from "path";
import { CERT_DIR, certPaths } from "./paths";
import { createKey, deleteKey, generateCsr, listKeys, SYSTEM_KEYCHAIN } from "./keystore";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";

/**
 * El prefijo reservado. Ninguna clave de enrolamiento lo lleva ni puede
 * llevarlo: el enrolamiento usa fichero (`client.key.pem`), no llavero.
 */
export const CDP_KEY_PREFIX = "tracenium-cdp-";

/**
 * `keyId` aceptable.
 *
 * Deliberadamente estrecho. Todo lo que no sea esto es NO, que es el
 * lado correcto por el que fallar cuando lo que se nombra acabara
 * concatenado a una ruta o a una etiqueta de llavero: sin `/`, sin `\`,
 * sin `..`, sin espacios, y con tope de longitud.
 *
 * Minusculas a proposito. Las etiquetas de llavero y los nombres de
 * clave CNG en Windows no distinguen mayusculas de forma fiable, y dos
 * `keyId` que solo difieran en la caja serian dos claves en una
 * plataforma y una en otra — una divergencia silenciosa entre sistemas
 * operativos es justo lo que este modulo no puede permitirse.
 */
const KEY_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export function isValidKeyId(keyId: unknown): keyId is string {
  if (typeof keyId !== "string") return false;
  if (!KEY_ID_RE.test(keyId)) return false;
  // `..` no puede formarse con el regex de arriba (que si admite `.`),
  // pero se comprueba igual: el dia que alguien relaje el regex, esto
  // sigue en pie.
  if (keyId.includes("..")) return false;
  return true;
}

/** Etiqueta derivada. El llamante NUNCA la elige. */
export function cdpKeyLabel(keyId: string): string {
  if (!isValidKeyId(keyId)) throw new Error("invalid_key_id");
  return `${CDP_KEY_PREFIX}${keyId}`;
}

/**
 * Ultima linea: que lo derivado no sea la identidad del agente.
 *
 * En macOS no puede serlo —una vive en el llavero y la otra en un
 * fichero—, y precisamente por eso conviene: si algun dia el
 * enrolamiento se mudara al llavero (ver la nota de crypto-store.ts
 * sobre por que hoy no puede), esta comprobacion es lo que evitaria que
 * la mudanza abriera la puerta en silencio.
 */
export function assertNotEnrollmentKey(label: string): void {
  const enrol = path.basename(certPaths().clientKey);
  if (!label.startsWith(CDP_KEY_PREFIX) || label.includes(enrol)) {
    throw new Error("refuses_to_touch_enrollment_key");
  }
}

// ── Registro: que claves hay, desde cuando y por que ────────────────
//
// El llavero sabe QUE claves existen pero no CUANDO se crearon: se
// comprobo que atributos devuelve un llavero de fichero y no hay
// `cdat`. Y sobre todo no sabe POR QUE existe cada una, que es el dato
// que convierte una huerfana en accionable.
//
// ⚠️ El registro NO es la fuente de verdad de que hay. La lista sale
// SIEMPRE del almacen real y el registro solo la enriquece. Al reves,
// un registro desincronizado inventaria claves que no existen — y este
// repositorio ya tiene el caso contrario escrito en la decision 9.d:
// `purge_after` se escribe y no lo barre nadie.

export type KeyLedgerEntry = {
  keyId: string;
  subject: string;
  createdAt: string;
  /** La solicitud de ADR-0009 que autorizo la emision. */
  requestId?: string | null;
  /** Cuando se instalo el certificado. Sin esto, la clave es huerfana. */
  certInstalledAt?: string | null;
};

function ledgerPath(): string {
  return path.join(CERT_DIR, "cdp-keys.json");
}

export function readLedger(): Record<string, KeyLedgerEntry> {
  try {
    const raw = fs.readFileSync(ledgerPath(), "utf8");
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    // Un registro ilegible no puede costar la operacion: la verdad esta
    // en el llavero, esto es metadato.
    return {};
  }
}

function writeLedger(data: Record<string, KeyLedgerEntry>): void {
  try {
    // Solo el directorio propio: `ensurePrivSvcDirs()` crea el arbol
    // entero del PrivSvc y un registro de claves no tiene por que
    // depender de que el del socket sea escribible.
    fs.mkdirSync(CERT_DIR, { recursive: true });
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

/** Marca que el certificado llego: la clave deja de ser huerfana. */
export function markCertInstalled(keyId: string, whenIso?: string): void {
  const l = readLedger();
  if (!l[keyId]) return;
  l[keyId].certInstalledAt = whenIso || new Date().toISOString();
  writeLedger(l);
}

// ── Handlers IPC ────────────────────────────────────────────────────

const EKUS = new Set(["clientAuth", "serverAuth"]);

/**
 * `cdp.csr.generate` — genera la clave y devuelve el CSR.
 *
 * ⚠️ Decision 9.c: la destruccion va en el MISMO camino de codigo que la
 * creacion. Si algo falla despues de crear la clave, se destruye aqui,
 * antes de responder. Un manejador aparte es exactamente lo que alguien
 * se olvida de cablear — y una clave sin certificado tiene utilidad cero
 * y responsabilidad no-cero.
 */
export async function handleCdpCsrGenerate(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const p: any = req.params || {};
  const keyId = String(p.keyId || "");

  if (!isValidKeyId(keyId)) {
    return fail(req.id, "bad_request", "keyId invalido (min: [a-z0-9][a-z0-9._-]{0,63})");
  }

  const subject = String(p.subject || "").trim();
  if (!subject) return fail(req.id, "bad_request", "subject requerido");

  const eku = String(p.eku || "clientAuth");
  if (!EKUS.has(eku)) {
    return fail(req.id, "bad_request", `eku no soportado: ${eku} (clientAuth|serverAuth)`);
  }

  const keyAlgorithm = String(p.keyAlgorithm || "RSA_2048").toUpperCase();
  if (keyAlgorithm !== "RSA_2048") {
    // Se falla RUIDOSAMENTE, como ya hace el de enrolamiento. Ahi la
    // razon esta escrita: un desajuste de algoritmo silencioso rompio el
    // enrolamiento de Windows una vez.
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

  let label: string;
  try {
    label = cdpKeyLabel(keyId);
    assertNotEnrollmentKey(label);
  } catch (err: any) {
    return fail(req.id, "bad_request", String(err?.message || err));
  }

  // ⚠️ El registro se escribe ANTES de crear la clave, y el orden
  // importa. Al reves, un fallo al persistir el registro dejaria una
  // clave sin entrada: aqui y en Linux la lista aun la veria (se
  // enumera el almacen real), pero en Windows CNG no se puede enumerar
  // por prefijo sin bajar a P/Invoke, asi que esa clave quedaria
  // invisible en el inventario — justo el residuo silencioso que la
  // decision 9.d existe para impedir.
  //
  // Asi el registro es un SUPERCONJUNTO: una entrada sin clave es una
  // intencion que no llego a nada, y la lista la descarta porque la
  // verdad de que hay la sigue diciendo el almacen.
  recordKey({
    keyId,
    subject,
    createdAt: new Date().toISOString(),
    requestId: p.requestId ? String(p.requestId) : null,
    certInstalledAt: null
  });

  const creada = await createKey(label, { keychain: SYSTEM_KEYCHAIN });
  if (!creada.ok) {
    forgetKey(keyId);
    return fail(req.id, creada.code || "key_create_failed", creada.message || "no se pudo crear la clave");
  }

  // A partir de aqui existe material de clave privada. Todo camino de
  // salida que no sea el exitoso tiene que destruirlo.
  try {
    const csr = await generateCsr(label, subject, {
      dnsNames: dns,
      uris,
      eku: eku as "clientAuth" | "serverAuth",
      keychain: SYSTEM_KEYCHAIN
    });

    if (!csr.ok || !csr.csrPem) {
      await deleteKey(label, SYSTEM_KEYCHAIN);
      forgetKey(keyId);
      return fail(req.id, csr.code || "csr_failed", csr.message || "no se pudo firmar el CSR");
    }

    return success(req.id, {
      keyId,
      csrPem: csr.csrPem,
      keyAlgorithm: "RSA_2048",
      // El almacen se DECLARA. Es lo que permite a un operador —y a un
      // pliego— comprobar que la clave no es extraible sin creerse la
      // documentacion.
      keyStore: "keychain-nonextractable"
    });
  } catch (err: any) {
    await deleteKey(label, SYSTEM_KEYCHAIN);
    forgetKey(keyId);
    return fail(req.id, "csr_failed", String(err?.message || err));
  }
}

/**
 * `cdp.key.destroy` — destruccion explicita.
 *
 * La ejecuta el AGENTE, no el control plane (decision 9.c). Tres
 * razones y cada una basta: el control plane puede ser el adversario
 * —es la tesis del ADR—, puede estar caido, y no tiene acceso al
 * almacen de claves.
 */
export async function handleCdpKeyDestroy(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const keyId = String((req.params as any)?.keyId || "");
  if (!isValidKeyId(keyId)) return fail(req.id, "bad_request", "keyId invalido");

  let label: string;
  try {
    label = cdpKeyLabel(keyId);
    assertNotEnrollmentKey(label);
  } catch (err: any) {
    return fail(req.id, "bad_request", String(err?.message || err));
  }

  const out = await deleteKey(label, SYSTEM_KEYCHAIN);
  // El registro se limpia aunque el borrado falle a medias: dejarlo
  // seria afirmar en el inventario una clave que ya no esta. La verdad
  // la sigue teniendo el llavero.
  forgetKey(keyId);

  if (!out.ok) return fail(req.id, out.code || "key_delete_failed", out.message || "no se pudo destruir");
  return success(req.id, { keyId, destroyed: out.deleted ?? 0 });
}

/**
 * `cdp.key.list` — las claves que hay, con su edad y si son huerfanas.
 *
 * Decision 9.d: el respaldo no puede ser solo un cron, porque un
 * respaldo que nadie mira se pudre y entonces el diseño PARECE completo
 * mientras el residuo se acumula en silencio. Esto es lo que hace que
 * una huerfana aparezca en el mismo panel que todo lo demas.
 */
export async function handleCdpKeyList(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const out = await listKeys(CDP_KEY_PREFIX, SYSTEM_KEYCHAIN);
  if (!out.ok) return fail(req.id, out.code || "key_list_failed", out.message || "no se pudo listar");

  const ledger = readLedger();
  const ahora = Date.now();

  const keys = (out.keys || []).map((k: any) => {
    const keyId = String(k.label || "").slice(CDP_KEY_PREFIX.length);
    const meta = ledger[keyId];
    const createdAt = meta?.createdAt || null;
    return {
      keyId,
      subject: meta?.subject ?? null,
      createdAt,
      requestId: meta?.requestId ?? null,
      certInstalledAt: meta?.certInstalledAt ?? null,
      // Sin certificado instalado, la clave es huerfana: utilidad cero,
      // responsabilidad no-cero.
      orphan: !meta?.certInstalledAt,
      ageDays: createdAt
        ? Math.floor((ahora - Date.parse(createdAt)) / 86_400_000)
        : null
    };
  });

  return success(req.id, { keys, count: keys.length });
}
