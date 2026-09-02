// src/connectors/vcenter/gateway-key-sync.ts
//
// ADR-0013 — el ciclo de vida de la clave que abre la credencial de vCenter.
//
// La clave nace cuando este equipo pasa a ser gateway y muere cuando deja de
// serlo. No se provisiona en el enrolamiento a propósito: una clave capaz de
// descifrar es precisamente lo que puede abrir datos sellados, y darla a toda
// la flota para servir como mucho a un equipo por tenant empeora la postura de
// miles de equipos para beneficiar a uno.
//
// La señal ya existía en los dos extremos y no hubo que inventarla: el backend
// mete y retira `policy.gateway.vcenter` del override del device, y este agente
// activa el conector por la PRESENCIA de ese bloque. Aquí solo se cuelga la
// clave del mismo interruptor.
//
// ── Por qué el núcleo es una función pura ──────────────────────────
//
// Decidir QUÉ hacer y HACERLO son cosas distintas. La decisión tiene los casos
// interesantes —el rol que no cambia, el que se retira, la publicación que ya
// se hizo— y se puede probar sin un privsvc ni una red. Lo que queda debajo es
// fontanería.

/** Lo que el reconciliador puede decidir hacer. */
export type GatewayKeyAction = "ensure" | "destroy" | "none";

export interface GatewayKeyState {
  /** ¿Lleva este equipo el bloque `policy.gateway.vcenter`? */
  isGateway: boolean;
  /** Huella ya publicada al control plane, si la hubo. */
  publishedFingerprint: string | null;
}

/**
 * Qué hacer ante el estado actual.
 *
 * `ensure` incluso cuando ya se publicó: es idempotente y es la única forma de
 * notar que el material desapareció por debajo (una reinstalación, una limpieza
 * del almacén, un `/etc` restaurado de un backup). Un reconciliador que se fía
 * de su propia memoria deja de reconciliar en cuanto la realidad se mueve sin
 * avisar.
 */
export function decideGatewayKeyAction(state: GatewayKeyState): GatewayKeyAction {
  return state.isGateway ? "ensure" : state.publishedFingerprint ? "destroy" : "none";
}

/**
 * ¿Hay que publicar este material al control plane?
 *
 * Solo cuando la huella cambia. Publicar en cada sincronización de políticas
 * sería ruido constante contra un valor que casi nunca se mueve.
 */
export function shouldPublish(material: { fingerprintSha256: string }, published: string | null): boolean {
  return Boolean(material.fingerprintSha256) && material.fingerprintSha256 !== published;
}

/**
 * ADR-0013 (A) — la huella tal y como la enseña el portal: mayúsculas y pares
 * separados por dos puntos.
 *
 * ⚠️ El formato NO es cosmética. Todo el mecanismo consiste en que una persona
 * compare dos cadenas de 64 caracteres en dos pantallas distintas; si una sale
 * en minúsculas y de corrido y la otra en mayúsculas y por pares, la
 * comparación se abandona a la mitad y la casilla vuelve a ser un trámite.
 *
 * Es la misma función que `formatFingerprint` en el portal. Si una cambia, la
 * otra tiene que cambiar con ella.
 */
export function formatFingerprint(hex: string): string {
  return String(hex || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "")
    .match(/../g)
    ?.join(":") ?? "";
}

export interface GatewayKeyMaterial {
  certPem: string;
  fingerprintSha256: string;
  notAfter?: string | null;
}

export interface GatewayKeySyncDeps {
  isGateway(): boolean;
  deviceId(): string;
  /** `crypto.gwkey.ensure` — idempotente, devuelve el material vigente. */
  ensureKey(deviceId: string): Promise<GatewayKeyMaterial>;
  /** `crypto.gwkey.destroy` — idempotente. */
  destroyKey(deviceId: string): Promise<void>;
  /**
   * Publicar el certificado al control plane.
   *
   * Opcional a propósito: el transporte es un contrato entre este repo y el
   * backend, y hasta que exista al otro lado un agente que lo llamara solo
   * hablaría solo. Sin él la clave se crea y se destruye igual — lo que no
   * ocurre es que el navegador pueda sellar contra ella todavía.
   */
  publish?(material: GatewayKeyMaterial): Promise<void>;
  /**
   * ADR-0013 (A) — dejar la huella VISIBLE en el propio equipo.
   *
   * Es el otro extremo de la comparación que el portal lleva pidiendo desde
   * ADR-0001 y que hasta ahora no tenía dónde hacerse. `null` la retira al
   * perder el rol: una huella de una clave ya destruida es algo que comparar
   * que no corresponde a nada.
   */
  announce?(material: GatewayKeyMaterial | null): void;
  logger?: { info?: Function; warn?: Function; error?: Function };
}

/**
 * Un paso de reconciliación. Se llama en cada actualización de política, así
 * que tiene que ser barato y no puede lanzar: una excepción aquí saldría por
 * mitad del camino que aplica la política.
 */
export async function reconcileGatewayKey(
  deps: GatewayKeySyncDeps,
  state: { publishedFingerprint: string | null }
): Promise<{ publishedFingerprint: string | null }> {
  const action = decideGatewayKeyAction({
    isGateway: deps.isGateway(),
    publishedFingerprint: state.publishedFingerprint,
  });

  if (action === "none") return state;

  const deviceId = deps.deviceId();
  if (!deviceId) {
    deps.logger?.warn?.("[gwkey] sin deviceId — no se reconcilia");
    return state;
  }

  try {
    if (action === "destroy") {
      await deps.destroyKey(deviceId);
      deps.announce?.(null);
      deps.logger?.info?.("[gwkey] rol de gateway retirado — clave destruida");
      return { publishedFingerprint: null };
    }

    const material = await deps.ensureKey(deviceId);

    // ⚠️ ANTES de decidir si hay que publicar, y a propósito.
    //
    // Lo local no depende de lo que el control plane sepa: al reiniciar, el
    // fichero de estado se reconstruye vacío y la publicación NO se repite
    // (la huella no cambió). Anunciar después del `return` de abajo dejaría
    // sin huella visible justo a los gateways estables — los que llevan meses
    // funcionando y para los que alguien acabará queriendo comprobarla.
    deps.announce?.(material);

    if (!shouldPublish(material, state.publishedFingerprint)) return state;

    if (!deps.publish) {
      deps.logger?.info?.("[gwkey] clave lista, sin transporte para publicarla todavía", {
        fingerprint: material.fingerprintSha256,
      });
      return state;
    }

    await deps.publish(material);
    deps.logger?.info?.("[gwkey] certificado de cifrado publicado", {
      fingerprint: material.fingerprintSha256,
    });
    // Solo se recuerda DESPUÉS de que la publicación funcione. Al revés, un
    // fallo de red dejaría al agente creyendo que el control plane tiene un
    // certificado que nunca recibió, y no lo reintentaría nunca.
    return { publishedFingerprint: material.fingerprintSha256 };
  } catch (err: any) {
    // No se propaga: esto cuelga del camino que aplica políticas, y una
    // credencial de vCenter que no se puede sellar todavía no es razón para
    // tumbar la aplicación de una política que trae otras diez cosas.
    deps.logger?.warn?.("[gwkey] reconciliación fallida", { err: err?.message || String(err) });
    return state;
  }
}
