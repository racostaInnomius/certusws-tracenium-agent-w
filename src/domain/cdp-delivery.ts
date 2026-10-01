// src/domain/cdp-delivery.ts
//
// Del escaneo de CDP al ACK del backend: el paquete que mueve la línea base
// viaja pegado al namespace que devuelve el plugin, y se asocia al envío
// cuando el llamador sabe su id de outbox. Ver cdp-baseline-repo.ts
// («Entrega confirmada») para el porqué.
//
// WeakMap y no una propiedad del objeto: el namespace se serializa entero
// al payload, y el paquete (la base completa) no tiene que viajar.

import { stageCdpDelivery, type CdpDeliveryCommit } from "./cdp-baseline-repo";

const pending = new WeakMap<object, CdpDeliveryCommit>();

/** Lo llama el plugin: lo que hay que aplicar si este namespace llega. */
export function attachCdpDelivery(namespace: object, commit: CdpDeliveryCommit): void {
  pending.set(namespace, commit);
}

/** Para tests y para el llamador: el paquete pegado a un namespace, si lo hay. */
export function peekCdpDelivery(namespace: object | null | undefined): CdpDeliveryCommit | undefined {
  return namespace ? pending.get(namespace) : undefined;
}

/**
 * Lo llama quien ENCOLA el namespace, con el id que devolvió el outbox. Un
 * namespace que no se encola (sin cambios, envío descartado) no deja nada:
 * el siguiente escaneo diffea contra la misma base y lo vuelve a intentar.
 */
export function stageAttachedCdpDelivery(namespace: object | null | undefined, outboxId: number): boolean {
  const commit = peekCdpDelivery(namespace);
  if (!commit || !Number.isFinite(outboxId) || outboxId <= 0) return false;
  stageCdpDelivery(outboxId, commit);
  pending.delete(namespace as object);
  return true;
}
