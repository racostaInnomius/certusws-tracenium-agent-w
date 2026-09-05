// src/domain/cdp-types.ts
//
// CDP (Crypto Discovery Plugin) wire schema 1.0.
//
// The agent reports FACTS about X.509 certificates found in the OS
// stores — metadata only, never key material. All judgment (expiry
// status, weak-crypto flags, nonstandard-root detection) lives
// server-side so thresholds can change without a fleet rollout.
// See certusws-tracenium/docs/CDP_CRYPTO_DISCOVERY_DESIGN.md.

export type CdpCollector = {
  plugin: "cdp";
  version: string;
};

/** `network` (fase 2): un objetivo remoto sondeado por el rol Probe. No
 *  esta EN el equipo; el equipo solo es quien lo miro. */
export type CdpStoreScope = "machine" | "user" | "system-roots" | "network";

export type CdpStoreInfo = {
  /** Stable store identifier, e.g. "lm/my", "keychain/system", "fs/etc-ssl-certs". */
  id: string;
  name: string;
  scope: CdpStoreScope;
};

export type CdpCertItem = {
  /** Stable per-device key: sha256(fingerprint256 + ":" + storeId). */
  id: string;
  fingerprint256: string;
  fingerprintSha1?: string;
  serial?: string;

  subjectDN?: string;
  subjectCN?: string;
  issuerDN?: string;
  issuerCN?: string;

  /** ISO-8601 UTC. */
  notBefore?: string;
  notAfter?: string;

  keyAlgorithm?: string;
  keySizeBits?: number;
  curve?: string;
  signatureAlgorithm?: string;
  /** Raw algorithm OIDs straight from the DER. Reported so the control
   *  plane can name and classify algorithms this agent predates —
   *  post-quantum in particular. See ADR-0004. */
  publicKeyOid?: string;
  signatureOid?: string;
  /**
   * La mitad alternativa de un certificado híbrido "catalyst" (ITU-T
   * X.509 2019): clave y firma post-cuánticas en tres extensiones no
   * críticas, junto a las clásicas de siempre.
   *
   * Ausentes en un certificado normal. Se mandan como OID crudo, igual
   * que los otros dos: la clasificación es server-side.
   *
   * ⚠️ Su presencia dice que el certificado DECLARA una mitad
   * post-cuántica, NO que esa mitad se verifique. Ver extractHybridOids.
   */
  altSignatureOid?: string;
  altPublicKeyOid?: string;
  hasAltSignature?: boolean;
  /** sha256 of the DER SubjectPublicKeyInfo (same value as openssl's
   *  pin-sha256, in hex). Identifies the KEY, not the certificate —
   *  the control plane uses it to spot copied private keys. */
  publicKeyHash?: string;
  /** CRL distribution point URLs from the certificate (ADR-0004 c). */
  crlUrls?: string[];
  /** OCSP responder URLs from Authority Information Access. */
  ocspUrls?: string[];
  /** Only for `source: "listener"` — what the live handshake revealed
   *  about the chain the service serves (ADR-0004 b). */
  tls?: {
    port: number;
    /** Certificates the server actually sent. 1 usually means it
     *  omitted the intermediates. */
    chainDepth: number;
    /** Does the device's own trust store accept the chain? */
    chainAuthorized: boolean;
    /** OpenSSL verify code when it does not. */
    chainError?: string;
    /** Advisory only: a proxy legitimately serves other names. */
    coversDeviceHostname?: boolean;
    /** Which process serves this certificate (ADR-0004 a). The join key
     *  the control plane uses to attribute a certificate to an owning
     *  application in the software inventory. */
    process?: { pid: number; name?: string; path?: string };
    /**
     * Fase 2 (analisis de madurez 2026-09) — lo que el handshake NEGOCIO,
     * no solo lo que el servidor presento. Es la mitad KEM de PQC, la
     * urgente: el trafico grabado hoy se descifra manana si el
     * intercambio de claves es clasico, y eso vive AQUI, no en el
     * certificado.
     */
    /** TLSv1.2 / TLSv1.3. */
    protocol?: string;
    /** Suite negociada, nombre IANA cuando Node lo da. */
    cipher?: string;
    /** Grupo de intercambio de claves negociado por defecto, cuando Node
     *  lo nombra: X25519, prime256v1… Medido en Node 22.21: SI se expone
     *  en TLS 1.3 para ECDH clasico, pero para el grupo hibrido
     *  X25519MLKEM768 getEphemeralKeyInfo() devuelve `{}`. Ausente + TLS
     *  1.3 no significa nada por si solo; `kemHybrid` es el veredicto. */
    kexGroup?: string;
    /**
     * ¿Acepta el servidor un intercambio hibrido post-cuantico?
     *   true  — negocio X25519MLKEM768 (por defecto o forzado).
     *   false — con el cliente restringido al grupo hibrido el handshake
     *           fallo: el servidor no lo soporta.
     *   null  — no se pudo determinar (el OpenSSL de este agente no
     *           conoce el grupo, o el servidor no volvio a contestar).
     * Nunca se infiere: ausencia de dato ≠ «no».
     */
    kemHybrid?: boolean | null;
    kemProbeError?: string;
    /** Solo para `source: "probe"`: el host tal como lo escribio el
     *  operador en la policy. */
    target?: string;
  };

  isCA?: boolean;
  selfSigned?: boolean;
  /** Metadata only — the key itself is NEVER read or transmitted. */
  hasPrivateKey?: boolean;

  keyUsage?: string[];
  extendedKeyUsage?: string[];
  san?: string[];

  store: CdpStoreInfo;
  /** Where the certificate was found:
   *   "store"      — OS certificate store
   *   "java-store" — JKS/PKCS12 keystore (JVM cacerts or app keystore)
   *   "listener"   — captured from a live local TLS handshake, i.e. what
   *                  the service actually serves (may differ from any
   *                  store). */
  source: "store" | "java-store" | "listener" | "file" | "nss" | "probe" | "adcs";
};

/**
 * Un almacen que EXISTIA y no se pudo leer en este escaneo (keystore
 * bloqueado, keychain de otro usuario, base NSS abierta, PrivSvc sin el
 * metodo de usuario...). Sus certificados faltan de `items` sin haber
 * desaparecido: ni el agente ni el control plane pueden afirmar su baja.
 * `prefix: true` = el id nombra una familia de almacenes (`user/`).
 */
export type CdpUnreadableStore = {
  id: string;
  name: string;
  reason: string;
  prefix?: boolean;
};

/**
 * Escaneo parcial: lo que se vio es cierto; lo que NO se vio no se
 * puede dar por retirado. `unreadableStores` acota la duda a almacenes
 * concretos; `unscoped` son fallos de un colector entero cuyos almacenes
 * no se pueden nombrar (entonces no se afirma NINGUNA baja).
 */
export type CdpPartialScan = {
  unreadableStores: CdpUnreadableStore[];
  unscoped: string[];
};

export type CdpDelta = {
  added: CdpCertItem[];
  removed: Array<{ id: string }>;
  updated: CdpCertItem[];
};

export type CdpCollectorError = {
  message: string;
  phase?: string;
};

export type CdpNamespace = {
  schemaVersion: "1.0";
  collector: CdpCollector;
  collectedAt: string;

  /** Internal-only scheduler flag; stripped semantics match SCP/PMP. */
  hasChanges: boolean;

  /** True when the item cap was hit and low-priority certs were dropped. */
  truncated: boolean;

  stores: CdpStoreInfo[];

  certificates: {
    count: number;
    /** Full baseline — first send or forced resync only. */
    items?: CdpCertItem[];
    /** Incremental changes vs the local SQLite baseline. */
    delta?: CdpDelta;
  };

  collectorError?: CdpCollectorError;

  /**
   * Estado del pin de anclas de confianza (ADR-0011 fase 0, paso 1).
   *
   * Ausente = el PrivSvc de este equipo no conoce `cdp.anchor.state`
   * todavía, que es lo que verá toda la flota hasta que la versión con
   * el método llegue. Distinto de `applicable: false`, que es una
   * plataforma donde no hay anclas que fijar (Linux, gate 1).
   */
  anchorPin?: CdpAnchorPinReport;
  /** Presente cuando algun almacen existia y no se pudo leer. Ver
   *  CdpPartialScan: sin esto, una base NSS bloqueada un dia se leia
   *  como «todos sus certificados fueron retirados». */
  partial?: CdpPartialScan;

  /**
   * Conector AD CS (fase 4). Solo lo manda una Certification Authority
   * con `cdp.adcs.enabled`. Lo emitido NO esta en este equipo: el control
   * plane lo proyecta a activos con origen `adcs`, no a la lista de
   * certificados del equipo.
   */
  adcs?: CdpAdcsReport;
};


export type CdpAnchorPinReport = {
  applicable: boolean;
  platform: string;
  /** Motivo, cuando `applicable` es false. */
  reason?: string;
  mode: "observe" | "enforce" | null;
  pinnedCount: number;
  pinned: string[];
  /**
   * Último veredicto, o null si este equipo no ha enrolado ni renovado
   * desde que existe el mecanismo. `null` es «no ha evaluado», NO «no
   * vio nada» — la diferencia es la que separa un inventario de una
   * falsa tranquilidad.
   */
  last: {
    at: string;
    mode: "observe" | "enforce";
    source: "enroll" | "renew";
    incoming: string[];
    unpinned: string[];
    rejected: string[];
    firstRun: boolean;
    unpinnedSeenTotal: number;
  } | null;
};


export type CdpAdcsReport = {
  isCa: boolean;
  caName: string | null;
  sinceRequestId: number;
  lastRequestId: number;
  /** Emisiones nuevas desde el cursor, con su plantilla y solicitante. */
  issued: Array<CdpCertItem & { requestId: number; disposition: number | null; requester?: string; template?: string }>;
  truncated: boolean;
  parseFailures: number;
  /** Que columnas reconocio el parser: si falta una, se ve aqui. */
  columnsFound: { requestId: boolean; disposition: boolean; requester: boolean; template: boolean; rawCertificate: boolean } | null;
};
