// src/plugins/cdp/verify-serving.ts
//
// ADR-0033 F1, decision D4 — «la verificacion es una sonda, no la
// palabra del agente».
//
// Tras instalar un certificado y recargar el servicio, alguien tiene que
// preguntarle al PUERTO que esta sirviendo. Hasta hoy la verificacion
// era un rescan completo de CDP que no comparaba nada: se encolaba, el
// inventario se actualizaba, y nadie decia si el servicio presenta el
// certificado nuevo o sigue con el viejo porque nadie lo recargo. Ese es
// el hueco que cierra este job, y es la misma leccion de `runUpdateTask`
// reportando exitos que no lo eran.
//
// ── Tres cosas que este fichero hace a proposito ─────────────────────
//
// 1. NO usa el ciclo de recoleccion de CDP (12 h) ni la foto de facts
//    con su enfriamiento. Una verificacion que llega cuando el
//    enfriamiento lo permita no verifica nada: el momento en que hay que
//    mirar es el de DESPUES de instalar. La respuesta viaja sola por el
//    outbox, como la de la consulta en vivo (ADR-0029).
//
// 2. NO escribe un segundo cliente TLS. Reutiliza la sonda del colector
//    de listeners —preambulo StartTLS incluido, y la segunda conexion
//    que dictamina el KEM hibrido—, porque dos clientes que hablan TLS
//    en el mismo repositorio divergen y entonces el inventario y la
//    verificacion dicen cosas distintas del mismo puerto.
//
// 3. Distingue «no contesta» de «contesta con otro certificado». Es LA
//    distincion del ADR: `matches: null` no es un desajuste, es un
//    desconocido. Fundirlas dejaria un servicio caido marcado como
//    «sirve otro certificado» (y a alguien persiguiendo un fantasma), o
//    peor, un desajuste real escondido detras de un «no se pudo
//    conectar».
//
// ── Lo que NO hace ───────────────────────────────────────────────────
//
// No descubre puertos: sondea SOLO los objetivos que trae el job. No
// escribe un byte de protocolo de aplicacion: el socket muere en cuanto
// el handshake da un certificado. Y no decide nada sobre la renovacion
// —el veredicto `installed_not_serving` lo pone el control plane
// comparando contra el certificado que acaba de firmar—; aqui solo se
// reporta lo que el puerto presento.

import crypto from "crypto";
import { STARTTLS_PORTS, type StartTlsProtocol } from "./starttls";
import {
  probeTlsWithKemDetailed,
  type KemProbeOutcome
} from "./providers/tls-listeners";
import { FACTS_SCHEMA_VERSION } from "../../update/update-source-report";

/** Nombre del job. El backend lo declara igual en su lista de tipos. */
export const CDP_VERIFY_SERVING_JOB_TYPE = "cdp_verify_serving";
/** Namespace de facts: viaja SOLO en su evento, como live_query y dex. */
export const CDP_VERIFY_SERVING_FACTS_NAMESPACE = "cdp_verify_serving";

/**
 * Tope de objetivos.
 *
 * Un certificado se sirve en uno o dos sitios (el 443 y quiza un 8443);
 * ocho cubre de sobra un equipo con varios bindings. Mas que eso no es
 * una verificacion, es un escaneo — y un escaneo lo pide otra cosa, con
 * otro permiso.
 */
export const MAX_TARGETS = 8;

/** Tope por objetivo. Cubre el preambulo StartTLS + las dos conexiones del KEM. */
export const TARGET_BUDGET_MS = 9_000;

/**
 * Tope total de reloj de pared.
 *
 * ⚠️ Menor que el ACK_TIMEOUT_MS del job runner (60 s) a proposito: un
 * job que agota el tope del llamante se reporta como perdido y no
 * contesta nada, que es el peor desenlace posible para una verificacion.
 * Mejor ocho objetivos con los dos ultimos en «presupuesto agotado» que
 * el silencio.
 */
export const TOTAL_BUDGET_MS = 30_000;

/** Cuantos objetivos a la vez. Mismo criterio que el rol Probe. */
const CONCURRENCY = 4;

const STARTTLS_PROTOCOLS: StartTlsProtocol[] = ["smtp", "imap", "pop3", "ldap", "postgres", "mysql"];

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const LOOPBACK = /^(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|::1)$/i;

export type VerifyTarget = {
  host: string;
  port: number;
  /** El SNI que se manda. Cadena vacia = sin SNI (una IP que no es loopback). */
  sni: string;
  startTls?: StartTlsProtocol;
};

export type VerifyTargetResult = {
  host: string;
  port: number;
  sni: string;
  startTls?: string;
  /** ¿Completo el handshake y dio un certificado? */
  answered: boolean;
  /** Huella SHA-256 del DER de la hoja SERVIDA, hex en minusculas sin `:`. */
  fingerprint256?: string;
  protocol?: string;
  cipher?: string;
  kexGroup?: string;
  kemHybrid?: boolean | null;
  chainDepth?: number;
  /** ¿El almacen de confianza de ESTE equipo acepta la cadena servida? */
  chainAuthorized?: boolean;
  chainError?: string;
  /**
   * `true`/`false` solo cuando el job trajo `expectFingerprint256` Y el
   * puerto contesto. `null` = no se pudo saber, que NO es un desajuste.
   */
  matches: boolean | null;
  /** Razon estable cuando no contesto. Nunca vacia si `answered` es false. */
  error?: string;
  elapsedMs: number;
};

export type VerifyServingReport = {
  jobId: string;
  expectFingerprint256: string | null;
  targets: VerifyTargetResult[];
  summary: {
    probed: number;
    answered: number;
    matched: number;
    mismatched: number;
    unknown: number;
  };
};

export type VerifyServingDeps = {
  /** Sonda inyectable. Por defecto, la misma del colector de listeners. */
  probe?: (t: VerifyTarget) => Promise<KemProbeOutcome>;
  enqueue: (payload: unknown) => number;
  /** Topes, para poder ejercitar el agotamiento sin esperar 30 s. */
  targetBudgetMs?: number;
  totalBudgetMs?: number;
  now?: () => number;
  logger?: { info?: (...a: any[]) => void; warn?: (...a: any[]) => void };
};

export type JobAck = { status: 0 | 1 | 2; message: string };

type Parsed =
  | { ok: true; targets: VerifyTarget[]; expect: string | null }
  | { ok: false; error: string };

/** Normaliza una huella: hex en minusculas, sin `:` ni espacios. */
export function normalizeFingerprint(raw: unknown): string | null {
  const s = String(raw ?? "").trim().toLowerCase().replace(/[\s:]/g, "");
  return /^[0-9a-f]{64}$/.test(s) ? s : null;
}

/**
 * Valida el payload ENTERO o lo rechaza ENTERO.
 *
 * Nada de sondear los objetivos buenos y callarse los malos: un objetivo
 * mal formado es un fallo del control plane, y una verificacion a medias
 * que se reporta como completa es justo el falso verde que este job
 * viene a impedir.
 */
export function parseVerifyServingPayload(payload: unknown): Parsed {
  const p: any = payload || {};
  const bruto = p.targets;
  if (!Array.isArray(bruto) || bruto.length === 0) {
    return { ok: false, error: "targets vacio o ausente" };
  }
  if (bruto.length > MAX_TARGETS) {
    // Se rechaza en vez de recortar: recortar sondearia menos de lo que
    // el control plane cree haber pedido y reportaria exito.
    return { ok: false, error: `demasiados targets: ${bruto.length} (max ${MAX_TARGETS})` };
  }

  const expectRaw = p.expectFingerprint256;
  let expect: string | null = null;
  if (expectRaw !== undefined && expectRaw !== null && String(expectRaw).trim() !== "") {
    expect = normalizeFingerprint(expectRaw);
    if (!expect) return { ok: false, error: "expectFingerprint256 no es un SHA-256 hex de 64 caracteres" };
  }

  const targets: VerifyTarget[] = [];
  for (const t of bruto) {
    const bruto_host = t?.host === undefined || t?.host === null || String(t.host).trim() === ""
      ? "127.0.0.1"
      : String(t.host).trim();
    const host = bruto_host.toLowerCase();
    if (host.length > 253 || !/^[a-z0-9._:\-[\]]+$/.test(host)) {
      return { ok: false, error: `host invalido: ${String(t?.host).slice(0, 40)}` };
    }
    const port = Number(t?.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return { ok: false, error: `puerto invalido: ${String(t?.port).slice(0, 20)}` };
    }

    let startTls: StartTlsProtocol | undefined;
    if (t?.startTls !== undefined && t?.startTls !== null && String(t.startTls).trim() !== "") {
      const s = String(t.startTls).trim().toLowerCase() as StartTlsProtocol;
      if (!STARTTLS_PROTOCOLS.includes(s)) {
        return { ok: false, error: `startTls no soportado: ${String(t.startTls).slice(0, 20)} (${STARTTLS_PROTOCOLS.join("|")})` };
      }
      startTls = s;
    } else if (STARTTLS_PORTS[port]) {
      // Se declara lo que la sonda va a hacer igualmente por el puerto,
      // para que el resultado diga que hubo preambulo.
      startTls = STARTTLS_PORTS[port];
    }

    // El SNI que pidieron; si no, el nombre. Una IP no lleva SNI —no es
    // un nombre—, salvo loopback, donde "localhost" es lo que manda hoy
    // el colector de listeners y lo que muchos vhost por defecto
    // esperan.
    const sniRaw = t?.sni === undefined || t?.sni === null ? "" : String(t.sni).trim();
    const sni = sniRaw !== ""
      ? sniRaw
      : IPV4.test(host) || host.includes(":")
        ? (LOOPBACK.test(host) ? "localhost" : "")
        : host;

    targets.push({ host, port, sni, ...(startTls ? { startTls } : {}) });
  }

  return { ok: true, targets, expect };
}

/** Sonda por defecto: la del colector de listeners, con su StartTLS y su KEM. */
function defaultProbe(t: VerifyTarget): Promise<KemProbeOutcome> {
  return probeTlsWithKemDetailed(t.host, t.port, t.sni, t.startTls ? { startTls: t.startTls } : {});
}

function withDeadline(p: Promise<KemProbeOutcome>, ms: number): Promise<KemProbeOutcome> {
  let timer: NodeJS.Timeout;
  return Promise.race([
    p,
    new Promise<KemProbeOutcome>((resolve) => {
      timer = setTimeout(() => resolve({ ok: false, code: "target_budget_exhausted" }), ms);
    })
  ]).finally(() => clearTimeout(timer));
}

async function mapLimited<T, R>(items: T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const i = cursor++;
      if (i >= items.length) return;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

/**
 * Sondea los objetivos y devuelve lo que cada puerto presento.
 *
 * Separado del job para poder ejercitarlo sin outbox ni ACK.
 */
export async function probeTargets(
  targets: VerifyTarget[],
  expect: string | null,
  deps: Pick<VerifyServingDeps, "probe" | "targetBudgetMs" | "totalBudgetMs" | "now">
): Promise<VerifyTargetResult[]> {
  const probe = deps.probe ?? defaultProbe;
  const now = deps.now ?? (() => Date.now());
  const inicio = now();
  const total = deps.totalBudgetMs ?? TOTAL_BUDGET_MS;
  const porObjetivo = deps.targetBudgetMs ?? TARGET_BUDGET_MS;

  return mapLimited(targets, CONCURRENCY, async (t) => {
    const t0 = now();
    const base = {
      host: t.host,
      port: t.port,
      sni: t.sni,
      ...(t.startTls ? { startTls: t.startTls } : {})
    };

    // El presupuesto total se mira ANTES de abrir el socket: un objetivo
    // que ni se intento se dice, no se reporta como caido.
    if (t0 - inicio >= total) {
      return { ...base, answered: false, matches: null, error: "total_budget_exhausted", elapsedMs: 0 };
    }

    let out: KemProbeOutcome;
    try {
      out = await withDeadline(probe(t), Math.min(porObjetivo, Math.max(1, total - (t0 - inicio))));
    } catch (err: any) {
      // La sonda promete no rechazar; si algun dia rompe esa promesa,
      // esto lo convierte en un motivo y no en un job caido.
      out = { ok: false, code: `probe_threw:${String(err?.message || err).slice(0, 60)}` };
    }
    const elapsedMs = now() - t0;

    if (!out.ok) {
      // ⚠️ `matches: null`, JAMAS false. Un puerto que no contesta no ha
      // dicho que sirva otro certificado.
      return { ...base, answered: false, matches: null, error: out.code || "unknown", elapsedMs };
    }

    const fingerprint256 = crypto.createHash("sha256").update(out.probe.der).digest("hex");
    return {
      ...base,
      // Si el preambulo lo decidio la sonda (por puerto) y aqui no se
      // habia declarado, que salga igual: el resultado describe lo que
      // se hizo.
      ...(out.probe.startTls ? { startTls: out.probe.startTls } : {}),
      answered: true,
      fingerprint256,
      ...(out.probe.protocol ? { protocol: out.probe.protocol } : {}),
      ...(out.probe.cipher ? { cipher: out.probe.cipher } : {}),
      ...(out.probe.kexGroup ? { kexGroup: out.probe.kexGroup } : {}),
      ...(out.probe.kemHybrid !== undefined ? { kemHybrid: out.probe.kemHybrid } : {}),
      chainDepth: out.probe.chainDepth,
      chainAuthorized: out.probe.chainAuthorized,
      ...(out.probe.chainError ? { chainError: out.probe.chainError } : {}),
      // Sin expectativa no hay nada que comparar: `null` es «no se
      // pregunto», que es distinto de «no se pudo saber» solo para quien
      // mira el job, y el job ya sabe si mando la huella.
      matches: expect ? fingerprint256 === expect : null,
      elapsedMs
    };
  });
}

/** Sólo caracteres seguros en un campo de ACK (`;` y `=` lo romperían). */
function safe(v: unknown): string {
  return String(v ?? "unknown").replace(/[^A-Za-z0-9_.:\- ]/g, "_").slice(0, 120) || "unknown";
}

export async function runVerifyServingJob(
  deps: VerifyServingDeps,
  input: { jobId: string; payload: unknown }
): Promise<JobAck> {
  const parsed = parseVerifyServingPayload(input.payload);
  if (!parsed.ok) {
    return { status: 2, message: `cdp_verify_serving_failed;reason=bad_payload:${safe(parsed.error)}` };
  }

  const targets = await probeTargets(parsed.targets, parsed.expect, deps);

  const summary = {
    probed: targets.length,
    answered: targets.filter((t) => t.answered).length,
    matched: targets.filter((t) => t.matches === true).length,
    mismatched: targets.filter((t) => t.matches === false).length,
    unknown: targets.filter((t) => t.matches === null).length
  };

  const report: VerifyServingReport = {
    jobId: input.jobId,
    expectFingerprint256: parsed.expect,
    targets,
    summary
  };

  // La respuesta viaja SOLA en su namespace, por el outbox: persistencia,
  // reintento y ACK por evento sin tocar el proto. Y sobre todo, sin
  // pasar por la foto de facts, cuyo enfriamiento de CDP DESCARTA una
  // segunda recogida seguida — que es justo lo que es una verificacion
  // hecha a los pocos segundos de instalar.
  deps.enqueue({
    schemaVersion: FACTS_SCHEMA_VERSION,
    namespaces: { [CDP_VERIFY_SERVING_FACTS_NAMESPACE]: report }
  });

  deps.logger?.info?.("[cdp] verificacion por sonda", { jobId: input.jobId, ...summary });

  return {
    status: 0,
    message:
      `cdp_verify_serving_done;probed=${summary.probed};answered=${summary.answered}` +
      `;matched=${summary.matched};mismatched=${summary.mismatched};unknown=${summary.unknown}`
  };
}
