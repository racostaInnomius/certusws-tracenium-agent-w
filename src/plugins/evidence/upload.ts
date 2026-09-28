// src/plugins/evidence/upload.ts
//
// ADR-0032 D3 — subir un artefacto al almacenamiento del control plane.
//
// Dos pasos, y el primero es el interesante:
//
//   1. PEDIR EL DESTINO. Lo pide PrivSvc, no este proceso, porque el
//      certificado de cliente del equipo vive allí (en Windows, la clave es del
//      almacén de la máquina y no es extraíble; ver ADR-0011/0015). El backend
//      identifica al equipo por ESE certificado y devuelve un SAS de escritura
//      acotado a la ruta de su captura.
//
//      ⚠️ Por eso el SAS no viaja en el payload del job: un job vive en
//      `device_jobs`, lo lee cualquiera con el permiso de jobs y la pantalla de
//      Jobs lo enseña. La llave se pide cuando se va a usar y dura 30 minutos.
//
//   2. SUBIR. Un PUT normal contra ese SAS. Aquí ya no hace falta certificado:
//      la llave ES la credencial, y por eso se concede sólo para crear y
//      escribir, nunca para leer.
//
// Un PrivSvc anterior a este método contesta que no lo conoce, y la captura
// termina con «no se pudo subir» y su razón — no con un silencio.

import fs from "fs";

export type PrivCall = (req: {
  v: number;
  id: string;
  method: string;
  params: Record<string, unknown>;
  meta?: Record<string, unknown>;
}) => Promise<any>;

export type UploadDeps = {
  call: PrivCall;
  /**
   * La base del control plane (`https://api…`). Va en la petición porque
   * PrivSvc no la conoce: REST y gRPC viven en hosts distintos según el
   * entorno, y fijarla en el servicio rompería pre-producción. PrivSvc la
   * valida (origen https, sin ruta) y compone ÉL la ruta.
   */
  baseUrl: string;
  meta?: { tenantId?: string; deviceId?: string };
  /** Inyectable para el test; por defecto, el `fetch` de Node. */
  put?: (url: string, body: fs.ReadStream | Buffer, headers: Record<string, string>) => Promise<{ status: number; text: string }>;
  logger?: { info?: (...a: any[]) => void; warn?: (...a: any[]) => void };
};

/** El método IPC que atiende PrivSvc. Fijo: no se compone desde el payload. */
export const UPLOAD_URL_METHOD = "evidence.upload.url";

const defaultPut = async (url: string, body: fs.ReadStream | Buffer, headers: Record<string, string>) => {
  const res = await fetch(url, {
    method: "PUT",
    // @ts-expect-error — undici acepta un stream como cuerpo; el tipo de
    // `fetch` de TS todavía no lo declara. Se sube en streaming a propósito:
    // un .evtx de 60 MB no tiene por qué caber en memoria.
    body,
    headers,
    duplex: "half",
  });
  return { status: res.status, text: await res.text().catch(() => "") };
};

/**
 * Sube un artefacto. Lanza con un motivo legible: quien llama lo escribe en el
 * manifiesto como «no se pudo subir», que es evidencia de por sí.
 */
export async function uploadArtifact(
  deps: UploadDeps,
  input: { captureId: string; name: string; filePath: string; bytes: number }
): Promise<void> {
  const resp = await deps.call({
    v: 1,
    id: `evidence_${Date.now()}`,
    method: UPLOAD_URL_METHOD,
    params: { captureId: input.captureId, name: input.name, baseUrl: deps.baseUrl },
    meta: { tenantId: deps.meta?.tenantId, deviceId: deps.meta?.deviceId },
  });

  if (!resp?.ok) {
    const reason = String(resp?.error ?? resp?.message ?? "privsvc refused");
    // Un PrivSvc viejo no conoce el método: se dice, para que no parezca un
    // problema de red ni de permisos.
    throw new Error(reason.includes("unknown method") ? "this PrivSvc does not support evidence upload yet" : reason);
  }
  const url = String(resp.result?.uploadUrl ?? "");
  if (!/^https:\/\//i.test(url)) throw new Error("control plane returned no upload url");

  const put = deps.put ?? defaultPut;
  const res = await put(url, fs.createReadStream(input.filePath), {
    "x-ms-blob-type": "BlockBlob",
    "Content-Type": "application/octet-stream",
    "Content-Length": String(input.bytes),
  });

  if (res.status < 200 || res.status >= 300) {
    // 403 suele ser el SAS caducado: se dice tal cual para que el siguiente
    // intento no se busque en el sitio equivocado.
    const hint = res.status === 403 ? " (upload url expired or not authorised)" : "";
    throw new Error(`storage answered ${res.status}${hint}`);
  }
}
