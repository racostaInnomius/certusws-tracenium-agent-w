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

/**
 * Dónde vive la clave privada de un certificado (ola 1.3b), sabido SIN
 * exportarla: por el proveedor criptográfico en Windows, por ser un
 * fichero en Linux/ficheros. `unknown` = el proveedor no se pudo leer.
 */
export type CdpKeyStorage = "software" | "tpm" | "smartcard" | "unknown";

/**
 * Veredicto de cadena de un certificado de ALMACÉN (ola 1.3a), calculado
 * contra lo inventariado en el mismo escaneo. Los listeners y las sondas
 * no lo llevan: su cadena la juzga el handshake (`tls.chainAuthorized`).
 * Ausente en un autofirmado (no tiene emisor que buscar).
 */
export type CdpChainVerdict = {
  /** ¿Está el emisor (mismo DN, y AKI/SKI si los hay) en el inventario? */
  issuerFound: boolean;
  /** ¿Verifica la firma contra ese emisor? Ausente si no se pudo comprobar
   *  (emisor ausente, o algoritmo que el OpenSSL del agente no conoce). */
  signatureValid?: boolean;
  /** ¿Termina la cadena en una raíz del almacén de confianza del SO?
   *  false = termina en un autofirmado que NO es raíz de confianza;
   *  ausente = no se pudo construir hasta arriba. */
  trusted?: boolean;
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
  /** AIA caIssuers (solo http): dónde descargar el certificado emisor,
   *  que el control plane necesita para preguntar por OCSP (ola 1.7). */
  caIssuerUrls?: string[];
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
    /** El puerto exigio un preambulo StartTLS (smtp, imap, pop3, ldap,
     *  postgres, mysql) antes del handshake. Ausente = TLS implicito. */
    startTls?: string;
    /** Ola 1.2 — el nombre que se mando como SNI y que produjo ESTE
     *  certificado. Ausente = no se mando ninguno (lo que sirve la
     *  direccion por defecto). El barrido hace los dos intentos. */
    sni?: string;
    /** Ola 1.2 — la entrada de `cdp.probeRanges` que descubrio este
     *  endpoint, tal como la escribio el operador. Ausente en un
     *  objetivo explicito de `probeTargets` o en un listener local. */
    sweep?: string;
  };

  isCA?: boolean;
  selfSigned?: boolean;
  /** Metadata only — the key itself is NEVER read or transmitted. */
  hasPrivateKey?: boolean;
  /** Solo con `hasPrivateKey`. ¿Permite el proveedor exportar la clave?
   *  Leído de la política de exportación, nunca intentando exportar. */
  keyExportable?: boolean;
  keyStorage?: CdpKeyStorage;
  /** Ola 1.3a — ver CdpChainVerdict. */
  chain?: CdpChainVerdict;

  keyUsage?: string[];
  extendedKeyUsage?: string[];
  san?: string[];

  store: CdpStoreInfo;
  /** Where the certificate was found:
   *   "store"      — OS certificate store
   *   "java-store" — JKS/JCEKS/PKCS12 keystore (JVM cacerts, app keystore,
   *                  or one the file discovery found by its magic bytes)
   *   "file"       — PEM/DER/PKCS#12 file on disk (file discovery)
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

  /**
   * vCenter por el gateway de infraestructura (2026-09-14). Solo lo manda
   * el agente del gateway con `gateway.readCertificates`: el certificado
   * maquina de vCenter y el de cada ESXi, leidos de lo que cada uno sirve
   * en 443. No estan en este equipo: el control plane los proyecta a
   * activos con origen `vcenter`. Lista completa; viaja cuando cambia.
   */
  vcenter?: CdpVcenterReport;

  /**
   * Claves de host SSH leidas de disco (§5.2). No son X.509: el control
   * plane las proyecta a activos con origen `ssh`. Solo viaja cuando
   * cambia (digest en cdp_meta) o en un baseline completo.
   */
  sshHostKeys?: CdpSshHostKeys;

  /**
   * Ola 1.4 — claves SSH por usuario: `authorized_keys` (quien PUEDE
   * entrar), los `.pub` que cada cuenta tiene, y la presencia de las
   * privadas. Lista COMPLETA del equipo; viaja cuando cambia (digest) o
   * en un baseline, como las claves de host. `truncated` dice cuando NO
   * es completa, y entonces no se puede reconciliar por ausencia.
   */
  sshUserKeys?: CdpSshUserKeys;

  /**
   * Ola 1.5 — que libreria criptografica carga cada SERVICIO. Lista
   * completa de los procesos con puerto a la escucha; viaja cuando
   * cambia (digest) o en un baseline, como las claves SSH. El veredicto
   * de «esto bloquea la migracion» lo pone el control plane, que ya
   * tiene los umbrales escritos y citados (agility.service).
   */
  processLibraries?: CdpProcessLibraries;

  /**
   * Si la pila TLS del propio sistema negocia intercambio hibrido
   * post-cuantico, MEDIDO en un handshake de bucle local (15-sep), mas
   * el numero de revision de Windows (UBR). Sustituye la deduccion por
   * build del control plane. Viaja cuando cambia o en un baseline.
   */
  osTls?: CdpOsTlsCapability;

  /**
   * Ola 1.1 — claves privadas SUELTAS encontradas por el descubrimiento de
   * ficheros: solo PRESENCIA (ruta, tipo y tamaño si la parte pública lo
   * dice, cifrada o no, y si casa con un certificado). Nunca un byte de la
   * clave. Lista completa del equipo; viaja cuando cambia (digest) o en un
   * baseline. Las de rutas que este escaneo no pudo ver se arrastran de la
   * última lista enviada, así que el control plane puede reconciliar por
   * ausencia sin más.
   */
  looseKeys?: { keys: CdpLooseKey[] };

  /**
   * Ola 1.1 — cómo fue el descubrimiento de ficheros de este escaneo:
   * modo, raíces, cuánto se miró, si se cortó por tiempo o por número y
   * qué raíces quedaron a medias. Informativo; viaja con el namespace
   * cuando este viaja (no dispara un envío por sí solo).
   */
  fileDiscovery?: CdpFileDiscoveryStats;

  /**
   * Ola 1.2 — como fue el barrido por rangos de este escaneo. Igual que
   * `fileDiscovery`: informativo, viaja con el namespace cuando este
   * viaja y no dispara un envio por si solo. Su `truncated` es lo que
   * impide que el control plane retire por ausencia lo que el barrido no
   * llego a mirar.
   */
  probeSweep?: CdpProbeSweepStats;

  /**
   * Candidatos a objetivo de sonda: servicios TLS INTERNOS con los que
   * este equipo tiene conexiones salientes establecidas. Nunca se sondean
   * por si solos; el operador los promueve desde la policy.
   */
  probeCandidates?: CdpProbeCandidate[];
};

export type CdpLooseKey = {
  path: string;
  /** pkcs8 | pkcs8-encrypted | pkcs1 | sec1 | dsa | pem-encrypted (Proc-Type
   *  heredado) | unknown (fichero de clave que no se pudo leer). */
  format: "pkcs8" | "pkcs8-encrypted" | "pkcs1" | "sec1" | "dsa" | "pem-encrypted" | "unknown";
  /** null = no se sabe (fichero ilegible). */
  encrypted: boolean | null;
  /** false = el fichero existe con nombre de clave pero no se pudo leer. */
  readable: boolean;
  keyAlgorithm?: string;
  keySizeBits?: number;
  curve?: string;
  /** sha256 de la SPKI de la parte PÚBLICA (mismo valor que el
   *  `publicKeyHash` de los certificados). Solo cuando la parte pública
   *  viene en claro en la estructura. */
  publicKeyHash?: string;
  /** Con qué certificado casa por clave pública. `unknown` = la parte
   *  pública no era derivable (cifrada, Ed25519 v1, ilegible...). */
  certMatch: "same-dir" | "inventory" | "none" | "unknown";
  matchedFingerprint256?: string;
};

/**
 * Ola 1.2 — que cubrio el barrido por rangos de ESTA ejecucion.
 *
 * No es decoracion: un barrido cortado por presupuesto NO ha visto la
 * red entera, y el control plane necesita saberlo para no retirar por
 * ausencia los endpoints que simplemente no se llegaron a mirar.
 */
export type CdpProbeSweepStats = {
  /** Entradas de `cdp.probeRanges` en la policy. */
  ranges: number;
  /** Direcciones planificadas (ya sin loopback, enlace local y multicast). */
  addresses: number;
  /** Conexiones TCP abiertas (direccion x puerto). */
  attempts: number;
  /** Cuantas aceptaron la conexion. */
  accepted: number;
  /** Cuantos certificados se obtuvieron (contando la variante por SNI). */
  answered: number;
  /** Direcciones:puerto que ya cubre `probeTargets` y no se barrieron. */
  skippedExisting: number;
  /** Segundos intentos con SNI. */
  sniAttempts: number;
  /** Veces que el SNI dio un certificado DISTINTO al de la direccion. */
  sniDistinct: number;
  elapsedMs: number;
  /** Por que se corto, o null si se completo. */
  truncated: "time" | "attempts" | "addresses" | "items" | null;
};

export type CdpFileDiscoveryStats = {
  mode: "default" | "configured";
  roots: string[];
  filesScanned: number;
  cacheHits: number;
  elapsedMs: number;
  /** Por qué se cortó el recorrido, o null si llegó al final. */
  truncated: "time" | "files" | null;
  /** Raíces que no se terminaron: lo que haya debajo no se da por retirado. */
  incompleteRoots: string[];
  /** Directorios/ficheros sin permiso bajo las raíces por defecto. */
  deniedPaths: number;
  /** Ficheros que eran copias de un bundle de raíces públicas (certifi,
   *  ca-bundle...) y no se inventariaron uno a uno. */
  trustBundlesSkipped: number;
  keystores: number;
  keys: number;
};

/** Capacidad TLS post-cuantica de la pila del SISTEMA, medida. */
export type CdpOsTlsCapability = {
  platform: "windows" | "macos" | "linux";
  /** El grupo probado: X25519MLKEM768. */
  group: string;
  /** true = negocio el grupo; false = TLS 1.3 si, el grupo no; null = no se pudo medir. */
  supported: boolean | null;
  method: "loopback_schannel" | "not_measured" | "agent_openssl_lacks_group";
  detail?: string;
  error?: string | null;
  /** Windows: CurrentBuildNumber, UBR y DisplayVersion del registro. */
  osBuild?: string;
  ubr?: number;
  displayVersion?: string;
  /**
   * ADR-0024 — lo que separa «puede migrar pero requiere el fix» de «no
   * puede»: si hay cmdlets TLS, la lista EFECTIVA de grupos en orden
   * (`Get-TlsEccCurve`) y si una GPO «ECC Curve Order» la gobierna
   * (en cuyo caso un cambio local se deshace en el siguiente gpupdate).
   * Sólo lectura: la sonda no cambia nada del sistema.
   */
  tlsCmdlets?: boolean;
  eccCurves?: string[];
  policyManaged?: boolean;
  policyCurves?: string[];
  measuredAt: string;
};

/** Un certificado leido de vCenter o de un ESXi: los campos del item de
 *  certificado sin lo que solo tiene sentido EN un equipo (id, store, source). */
export type CdpVcenterCert = Omit<CdpCertItem, "id" | "store" | "source" | "hasPrivateKey">;

export type CdpVcenterHost = {
  /** Como lo conoce vCenter: FQDN o IP con el que se anadio. */
  name: string;
  moref: string;
  connectionState: string;
  certificate?: CdpVcenterCert;
  /** Por que no se pudo leer (no alcanzable en 443, sin certificado...). */
  error?: string;
};

export type CdpVcenterReport = {
  /** Origen de vCenter, p. ej. https://vcenter.corp.example:443. */
  url: string;
  host: string;
  readAt: string;
  /** El certificado que vCenter sirve en 443 (el fijado por huella). */
  machine?: CdpVcenterCert;
  hosts: CdpVcenterHost[];
  /** false cuando algun host no se pudo leer: el control plane no retira nada por ausencia. */
  complete: boolean;
  errors?: string[];
};

export type CdpSshHostKeys = {
  host: string;
  listening: boolean;
  keys: Array<{
    keyType: string;
    algorithm: string;
    bits: number | null;
    curve: string | null;
    fingerprintSha256: string;
    path: string;
  }>;
};

/**
 * Ola 1.4 — material SSH POR USUARIO. Solo inventario.
 *
 * `authorized` = la clave CONCEDE acceso a esa cuenta (el hecho de
 * seguridad); `public` = la clave que el usuario TIENE. Se separan
 * porque mezclarlas produce un numero grande y sin significado.
 */
export type CdpSshUserKey = {
  kind: "authorized" | "public";
  /** Cuenta dueña del fichero, o `(system)`/`(administrators)`. */
  user: string;
  path: string;
  keyType: string;
  algorithm: string;
  bits: number | null;
  curve: string | null;
  /** `SHA256:<base64 sin relleno>` — el formato de `ssh-keygen -lf`. */
  fingerprintSha256: string;
  comment?: string;
  /**
   * Solo en `authorized_keys`: las restricciones tal cual las escribio
   * quien concedio el acceso (`no-pty`, `from="…"`, `command="…"`).
   * HECHOS: si una concesion sin acotar es aceptable lo decide el
   * control plane, que puede cambiar de opinion sin desplegar la flota.
   */
  options?: string[];
};

/**
 * Ola 1.4 — una clave privada de usuario: PRESENCIA, nunca material.
 *
 * ⚠️ En el modo por defecto (`public-only`) el fichero NI SIQUIERA SE
 * ABRE: solo `stat` y lo que diga el `.pub` hermano. Leer `~/.ssh/id_*`
 * dispara una detección de acceso a credenciales en CrowdStrike —
 * medido el 22-sep-2026 — y un agente de inventario marcado como robo de
 * credenciales es inaceptable. De ahí que `format` sea `unknown` y
 * `encrypted` null salvo en modo `full`.
 */
export type CdpSshUserPrivateKey = {
  user: string;
  path: string;
  /** `openssh` / formatos PEM de private-key-info; `unknown` sin leerlo. */
  format: string;
  /** null = no se sabe (lo normal: no se abre el fichero). */
  encrypted: boolean | null;
  readable: boolean;
  /** Metadatos de `stat`: no abren el fichero. */
  sizeBytes?: number;
  modifiedAt?: string;
  /** Permisos en octal (`600`, `644`): higiene que un auditor pide. */
  filePermissions?: string;
  keyType?: string;
  keyAlgorithm?: string;
  keySizeBits?: number;
  curve?: string;
  /** Huella de la mitad PUBLICA, que casa con los `authorized_keys` de
   *  otros equipos: asi se cierra «esta clave abre aquellas N cuentas». */
  fingerprintSha256?: string;
  publicHalfPath?: string;
};

export type CdpSshUserKeys = {
  /** Cuentas con material SSH (no cuentas del equipo). */
  users: number;
  keys: CdpSshUserKey[];
  privateKeys: CdpSshUserPrivateKey[];
  /** Ficheros que existen y no se pudieron leer: eso es un dato, no un cero. */
  unreadable: number;
  /** Se alcanzo un tope: la lista NO es completa y no se puede
   *  reconciliar por ausencia. */
  truncated: boolean;
  /** Con que alcance se recogio: `public-only` (defecto) no abre ningun
   *  fichero de clave privada; `full` si. El control plane lo necesita
   *  para no leer «no cifrada» donde pone «no se sabe». */
  mode: "public-only" | "full" | "off";
};

/**
 * Ola 1.5 — una libreria criptografica CARGADA por un proceso concreto.
 *
 * Hoy la agilidad se mide por PAQUETES (inventario de software) y por
 * rutas de `cacerts`. Eso responde «que versiones de OpenSSL hay» y no
 * «que servicios se quedan fuera de la migracion», que es la pregunta
 * que se acciona: nadie reinicia «openssl», se reinicia nginx.
 */
export type CdpProcessLibrary = {
  /** Informativo: la identidad estable es `imagePath` (+ `service`). */
  pid: number;
  process: string;
  imagePath?: string;
  /** Unidad de systemd o servicio de Windows, cuando lo hay. */
  service?: string;
  /** Puertos TCP a la escucha de ese proceso. */
  ports: number[];
  /** openssl | libressl | gnutls | nss | gcrypt | schannel | security-framework */
  library: string;
  /** Ruta REAL (resuelta): `libssl.so.3` casi siempre es un enlace. */
  libraryPath: string;
  version?: string;
  /**
   * De donde sale la version, porque no valen lo mismo: `soname` no
   * distingue un OpenSSL 3.0.2 de un 3.6.2 —y ese es justo el umbral de
   * ML-KEM—, mientras que `file` y `module` si.
   */
  versionSource?: "soname" | "file" | "path" | "module";
};

export type CdpProcessLibraries = {
  /** Procesos mirados (los que tienen un puerto TCP a la escucha). */
  processes: number;
  libraries: CdpProcessLibrary[];
  /** Se agoto un tope o el presupuesto: la lista NO es completa. */
  truncated: boolean;
  /** Por que no se pudo mirar (plataforma o permisos). */
  unsupported?: string;
};

export type CdpProbeCandidate = {
  host: string;
  port: number;
  connections: number;
  process?: string;
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
  issued: Array<CdpCertItem & { requestId: number; disposition: number | null; requester?: string; template?: string; templateOid?: string }>;
  truncated: boolean;
  parseFailures: number;
  /** Que columnas reconocio el parser: si falta una, se ve aqui. */
  columnsFound: { requestId: boolean; disposition: boolean; requester: boolean; template: boolean; rawCertificate: boolean; positional?: boolean } | null;
};
