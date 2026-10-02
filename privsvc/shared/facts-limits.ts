// privsvc/shared/facts-limits.ts
//
// Cuánto puede medir un envío de facts que el agente trocea por IPC.
//
// ⚠️ EL TOPE ES EL DEL CONTROL PLANE, NO UNO PROPIO.
//
// El backend acepta hasta 16 MiB de payloadJson (MAX_FACTS_PAYLOAD_BYTES en
// certusws-tracenium/modules/grpc/payload-limits.ts). Cada PrivSvc tenía su
// propio tope, más bajo y sin relación con ése: 512 KiB en Windows
// (IpcGrpcHandlers.cs) y 64 trozos —2 MiB con los trozos de 32 KiB del
// agente— en macOS y Linux. Un envío que el servidor habría aceptado moría
// en el propio equipo.
//
// Y moría mal: el rechazo volvía al agente como un fallo cualquiera, el
// agente tiraba la conexión, reconectaba y reenviaba el MISMO evento. Medido
// en TNS-OPER-SNOC04 (Server 2022) el 28-sep-2026: el compliance creció de
// 0,51 a 0,52 MiB, pasó de 512 KiB, y durante cuatro días el equipo reenvió
// los mismos 17 trozos en bucle sin que el servidor anotara nada. Los
// inventarios de certificados de los Windows del CDP caían en el mismo tope.
//
// Por eso hay un CÓDIGO propio: «demasiado grande» es definitivo para ese
// payload —reenviarlo da el mismo resultado— y el agente lo marca rechazado
// sin tocar la conexión. Cualquier otro fallo sigue siendo reintentable.
//
// El mismo valor está en src/transport/grpc-client.ts y en
// privsvc/windows/.../Ipc/FactsChunkAssembler.cs; un test compara los tres.

/** Bytes UTF-8 del payloadJson reensamblado. Igual que el backend. */
export const MAX_FACTS_PAYLOAD_BYTES = 16 * 1024 * 1024;

/**
 * Trozos por envío. Sólo protege la reserva del array antes de que llegue
 * ningún byte: con los trozos de 32 KiB del agente, 16 MiB son 512.
 */
export const MAX_FACTS_CHUNKS = 1024;

/** Código de error IPC de un envío que pasa del tope. */
export const FACTS_TOO_LARGE = "facts_too_large";
