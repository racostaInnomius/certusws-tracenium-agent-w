// test/plugins/evidence-upload.test.ts
//
// ADR-0032 D3 — el contrato con PrivSvc para subir un artefacto.
//
// Lo que importa aquí es que los fallos se distingan: un PrivSvc viejo, un
// backend que dice que no, y un SAS caducado producen mensajes distintos,
// porque cada uno acaba escrito en el manifiesto y, desde ahí, en el informe
// como la razón por la que faltó un artefacto.

import { describe, it, expect, vi } from "vitest";
import { UPLOAD_URL_METHOD, uploadArtifact } from "../../src/plugins/evidence/upload";

const ART = { captureId: "11111111-2222-3333-4444-555555555555", name: "system.evtx", filePath: __filename, bytes: 10 };

const ok = (over: any = {}) => ({
  ok: true,
  result: { uploadUrl: "https://blob.core.windows.net/c/evidence/111/cap/system.evtx?sig=x", expiresAtUtc: "2026-09-28T12:00:00Z", ...over },
});

describe("uploadArtifact", () => {
  it("⭐ pide el destino a PrivSvc con la base del control plane y sube al SAS", async () => {
    const call = vi.fn(async () => ok());
    const put = vi.fn(async () => ({ status: 201, text: "" }));
    await uploadArtifact({ call, baseUrl: "https://api.tracenium.com", put }, ART);

    expect(call).toHaveBeenCalledTimes(1);
    const req = call.mock.calls[0][0] as any;
    expect(req.method).toBe(UPLOAD_URL_METHOD);
    expect(req.params).toMatchObject({ captureId: ART.captureId, name: "system.evtx", baseUrl: "https://api.tracenium.com" });

    const [url, , headers] = put.mock.calls[0] as any[];
    expect(url).toContain("sig=");
    // Azure exige declarar el tipo de blob en un PUT directo.
    expect(headers["x-ms-blob-type"]).toBe("BlockBlob");
  });

  it("⭐ un PrivSvc anterior a este método se dice con esas palabras", async () => {
    const call = vi.fn(async () => ({ ok: false, error: "unknown method" }));
    await expect(uploadArtifact({ call, baseUrl: "https://api.tracenium.com" }, ART)).rejects.toThrow(
      /does not support evidence upload yet/
    );
  });

  it("⭐ el motivo del backend viaja tal cual: acaba explicando el hueco en el informe", async () => {
    const call = vi.fn(async () => ({ ok: false, error: "upload_url_refused", message: "CAPTURE_CLOSED: That capture is already closed." }));
    await expect(uploadArtifact({ call, baseUrl: "https://api.tracenium.com" }, ART)).rejects.toThrow(/upload_url_refused/);
  });

  it("🔴 un 403 del almacenamiento dice que el destino caducó, no «falló la red»", async () => {
    const call = vi.fn(async () => ok());
    const put = vi.fn(async () => ({ status: 403, text: "AuthenticationFailed" }));
    await expect(uploadArtifact({ call, baseUrl: "https://api.tracenium.com", put }, ART)).rejects.toThrow(
      /403.*expired or not authorised/
    );
  });

  it("⚠️ sin url de subida no se inventa nada", async () => {
    const call = vi.fn(async () => ok({ uploadUrl: "" }));
    await expect(uploadArtifact({ call, baseUrl: "https://api.tracenium.com" }, ART)).rejects.toThrow(/no upload url/);
  });

  it("🔴 ni se sube a una url que no sea https", async () => {
    const call = vi.fn(async () => ok({ uploadUrl: "http://blob/evidence" }));
    const put = vi.fn();
    await expect(uploadArtifact({ call, baseUrl: "https://api.tracenium.com", put }, ART)).rejects.toThrow(/no upload url/);
    expect(put).not.toHaveBeenCalled();
  });
});
