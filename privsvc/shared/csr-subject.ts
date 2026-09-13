// privsvc/shared/csr-subject.ts
//
// Cómo se llama el equipo en su certificado. UNA sola respuesta para el
// enrolamiento y para la renovación, en macOS y en Linux.
//
// ⚠️ EXISTE PORQUE LAS DOS VÍAS DIVERGIERON, Y EN SILENCIO.
//
// El enrolamiento ponía `CN = os.hostname()` con el mismo nombre en el SAN
// DNS. La renovación, escrita aparte, ponía `CN = tracenium-agent-<uuid>` y
// ni siquiera pasaba `dnsName`, así que el SAN perdía también la entrada
// DNS. Resultado: la PRIMERA renovación de cada Mac y cada Linux renombraba
// su certificado a un identificador que no dice nada — `JPR-MacBookPro`
// pasó a `tracenium-agent-356b64ba-…` en el inventario del CDP, mientras
// `W11-JPR-LAB02` conservaba su nombre tras dos rotaciones, porque en
// Windows `CryptoCsr.cs` tiene un solo camino.
//
// Nada falló: el backend autoriza por la URI del SAN y por la huella, no
// por el CN. Por eso nadie lo vio hasta que el anillo de rotación de
// ADR-0015 iba a hacérselo a toda la flota.
//
// Se lee el hostname AL CONSTRUIR el CSR, no se guarda el del enrolamiento:
// un equipo renombrado debe llevar su nombre de hoy en el siguiente
// certificado, que es lo que haría un operador si lo reenrolase a mano.

import os from "os";

export type NombreDelEquipo = {
  /** CN del sujeto. */
  commonName: string;
  /** La misma cadena, como dNSName en el SAN. */
  dnsName: string;
};

export function nombreDelEquipo(hostname: () => string = os.hostname): NombreDelEquipo {
  const dnsName = hostname();
  return { commonName: dnsName, dnsName };
}
