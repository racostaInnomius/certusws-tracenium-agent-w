// privsvc/shared/cdp-key-algorithm.ts
//
// ADR-0033 F1 — que algoritmos admite `cdp.csr.generate`, y con que hash
// se firma cada uno. Lo comparten los PrivSvc de macOS y de Linux.
//
// ── Por que compartido y no copiado ─────────────────────────────────
//
// Porque la divergencia entre plataformas es justo lo que ADR-0011 dice
// que no puede haber: la misma peticion no puede producir certificados
// distintos segun el sistema operativo del endpoint. El gemelo de
// Windows vive aparte (`Ipc/CdpKeyAlgorithm.cs`) porque es C#, y el del
// helper de macOS (`helpers/keystore/main.swift`) porque es Swift; los
// tres ficheros tienen que aceptar y rechazar EXACTAMENTE lo mismo, y
// hay un test que compara las listas.
//
// ── Por que la tabla es cerrada ─────────────────────────────────────
//
// El campo lo manda el control plane, que es el adversario del que
// desconfia ADR-0011. «Lo que no entiendo, RSA-2048» convierte una
// peticion de ECDSA P-384 mal escrita en una clave de 2048 bits que
// nadie pidio, con un CSR que el inventario declarara como lo pedido: un
// falso verde que solo se ve auditando la CA meses despues. Se falla
// ruidosamente, como ya hace el CSR de enrolamiento — ahi la razon esta
// escrita: un desajuste silencioso de algoritmo rompio el enrolamiento
// de Windows una vez.

export type CdpKeyKind = "rsa" | "ecdsa";

export type CdpKeyAlgorithmSpec = {
  /** Nombre canonico. Es el que se DEVUELVE al control plane. */
  name: string;
  kind: CdpKeyKind;
  /** Modulo en RSA; tamaño de curva en ECDSA. */
  bits: number;
  /** Curva en el nombre que entiende `openssl genpkey -pkeyopt ec_paramgen_curve`. */
  curve?: "P-256" | "P-384";
  /** Digest de la firma del PKCS#10, como lo nombra `openssl req`. */
  digest: "sha256" | "sha384";
};

/**
 * Lo que se usa cuando el payload no trae el campo.
 *
 * ⚠️ Tiene que seguir siendo RSA_2048: un control plane que todavia no
 * manda `keyAlgorithm` —los hay desplegados— debe seguir emitiendo
 * exactamente lo que emitia antes de ADR-0033.
 */
export const CDP_DEFAULT_KEY_ALGORITHM = "RSA_2048";

const TABLA: Record<string, CdpKeyAlgorithmSpec> = {
  RSA_2048: { name: "RSA_2048", kind: "rsa", bits: 2048, digest: "sha256" },
  RSA_3072: { name: "RSA_3072", kind: "rsa", bits: 3072, digest: "sha256" },
  RSA_4096: { name: "RSA_4096", kind: "rsa", bits: 4096, digest: "sha256" },
  // El hash acompaña a la curva a proposito. Firmar P-384 con SHA-256 es
  // legal y desperdicia la curva que alguien eligio a proposito.
  ECDSA_P256: { name: "ECDSA_P256", kind: "ecdsa", bits: 256, curve: "P-256", digest: "sha256" },
  ECDSA_P384: { name: "ECDSA_P384", kind: "ecdsa", bits: 384, curve: "P-384", digest: "sha384" }
};

/** Los nombres admitidos, en orden estable (tambien para los mensajes de error). */
export const CDP_KEY_ALGORITHMS: string[] = [
  "RSA_2048",
  "RSA_3072",
  "RSA_4096",
  "ECDSA_P256",
  "ECDSA_P384"
];

/**
 * Resuelve el algoritmo pedido. `null`/vacio → el de por defecto.
 *
 * Devuelve `null` —y NO un valor de reserva— ante cualquier otra cosa.
 * Ese es el punto entero del modulo.
 */
export function resolveCdpKeyAlgorithm(raw: unknown): CdpKeyAlgorithmSpec | null {
  // ⚠️ Ausente y «algo que no es texto» NO son lo mismo. `String([])` es
  // la cadena vacia, asi que un `keyAlgorithm: []` de un control plane
  // con un bug se habria leido como «no lo mando» y habria emitido
  // RSA-2048 en silencio. Ausente es ausente; lo demas tiene que ser una
  // cadena.
  if (raw !== undefined && raw !== null && typeof raw !== "string") return null;
  let pedido = (raw ?? "").trim();
  if (pedido.length === 0) pedido = CDP_DEFAULT_KEY_ALGORITHM;
  // Se acepta la caja que venga —el resto del contrato tampoco la
  // distingue— pero NADA mas: ni guiones, ni alias, ni prefijos.
  return TABLA[pedido.toUpperCase()] ?? null;
}

/** El mensaje de rechazo, igual en las dos plataformas. */
export function cdpKeyAlgorithmError(raw: unknown): string {
  const pedido = String(raw ?? "").trim().toUpperCase();
  return `keyAlgorithm no soportado: ${pedido} (${CDP_KEY_ALGORITHMS.join("|")})`;
}
