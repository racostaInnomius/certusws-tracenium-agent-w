// test/bootstrap/cert-renewal.test.ts
//
// P0 — renovación de certificado mTLS (supervivencia: un cert vencido o un
// PEM truncado brickean el agente hasta intervención manual).
//
// Estrategia:
//   - fs REAL sobre tmpdir; certs X.509 REALES generados con openssl en
//     beforeAll (uno lejos de expirar ~90d, otro cerca ~5d).
//   - Frontera de red/privsvc mockeada: `priv.call` es un vi.fn() que
//     simula la respuesta de crypto.cert.renew.
//   - `../../src/bootstrap/config` mockeado: el módulo real lanza al
//     importar si falta GRPC_ENDPOINT y lee registry de Windows/dotenv —
//     side effects que no queremos en tests.
//   - EnrollmentStore: objeto fake { save } — sólo se usa esa superficie.
//
// NOTA DE ALCANCE (reportado en el informe del sprint):
//   El jitter del intervalo de chequeo (±1h) y la detección de thumbprint
//   mutado durante el await viven en src/core/service.ts (armCertRenewal,
//   ~líneas 255-319) DENTRO del closure de startService() — no son
//   testeables en aislamiento sin exportarlos. Aquí se testea lo que
//   cert-renewal.ts hace por sí mismo, incluyendo el hecho (sospechoso)
//   de que escribe archivos y persiste estado ANTES de que el guard del
//   caller pueda detectar la mutación.
import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll, vi } from "vitest";
import { execSync } from "child_process";
import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";

vi.mock("../../src/bootstrap/config", () => ({
  config: {
    serverBaseUrl: "https://api.test.local",
    certRenewalBaseUrl: undefined
  }
}));

import { maybeRenewClientCertificate } from "../../src/bootstrap/cert-renewal";
import type { EnrollmentState } from "../../src/bootstrap/enrollment-state";

let baseDir: string;
let certFarPem: string;   // expira en ~90 días → NO renovar (umbral 30)
let certNearPem: string;  // expira en ~5 días  → SÍ renovar
let renewedPem: string;   // "cert nuevo" devuelto por el server fake

function genCert(dir: string, name: string, days: number): string {
  const keyPath = path.join(dir, `${name}.key.pem`);
  const certPath = path.join(dir, `${name}.crt.pem`);
  execSync(
    `openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" ` +
    `-days ${days} -nodes -subj "/CN=tracenium-test-${name}" 2>/dev/null`
  );
  return fs.readFileSync(certPath, "utf8");
}

function thumbprintOf(pem: string): string {
  return new crypto.X509Certificate(pem).fingerprint256.replace(/:/g, "");
}

interface Harness {
  enrollment: EnrollmentState;
  store: { save: ReturnType<typeof vi.fn> };
  priv: { call: ReturnType<typeof vi.fn> };
  logger: { info: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> };
  clientCertPath: string;
  caBundlePath: string;
}

function makeHarness(certPem: string, overrides: Partial<EnrollmentState["mtls"]> = {}): Harness {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tracenium-certrenew-"));
  const clientCertPath = path.join(dir, "mtls-client.crt.pem");
  const caBundlePath = path.join(dir, "mtls-ca.pem");
  fs.writeFileSync(clientCertPath, certPem, { mode: 0o600 });
  fs.writeFileSync(caBundlePath, "OLD CA BUNDLE\n", { mode: 0o600 });

  const enrollment: EnrollmentState = {
    tenantId: "tenant-1",
    deviceId: "device-1",
    enrolledAtUtc: "2026-01-01T00:00:00.000Z",
    mtls: {
      clientCertPath,
      caBundlePath,
      clientCertThumbprint: thumbprintOf(certPem),
      issuingCaThumbprint: "CA-THUMB-OLD",
      ...overrides
    },
    bootstrap: { channel: "stable", capabilities: ["amp"] }
  };

  return {
    enrollment,
    store: { save: vi.fn() },
    priv: { call: vi.fn() },
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    clientCertPath,
    caBundlePath
  };
}

function okRenewResponse(extra: Record<string, unknown> = {}) {
  return {
    ok: true,
    result: {
      clientCertThumbprint: "NEW-THUMBPRINT",
      issuingCaThumbprint: "CA-THUMB-NEW",
      notAfter: "2027-01-01T00:00:00.000Z",
      clientCertPem: renewedPem,
      status: "issued",
      ...extra
    }
  };
}

beforeAll(() => {
  baseDir = fs.mkdtempSync(path.join(os.tmpdir(), "tracenium-certgen-"));
  certFarPem = genCert(baseDir, "far", 90);
  certNearPem = genCert(baseDir, "near", 5);
  renewedPem = genCert(baseDir, "renewed", 365);
});

afterAll(() => {
  try { fs.rmSync(baseDir, { recursive: true, force: true }); } catch {}
});

beforeEach(() => {
  delete process.env.CERT_RENEWAL_THRESHOLD_DAYS;
});

afterEach(() => {
  delete process.env.CERT_RENEWAL_THRESHOLD_DAYS;
  vi.restoreAllMocks();
});

describe("cert-renewal — umbral de renovación", () => {
  it("cert lejos de expirar (90d, umbral default 30d) → NO renueva ni toca la red", async () => {
    const h = makeHarness(certFarPem);

    const result = await maybeRenewClientCertificate(h as any);

    expect(result).toBe(h.enrollment);
    expect(h.priv.call).not.toHaveBeenCalled();
    expect(h.store.save).not.toHaveBeenCalled();
    expect(fs.readFileSync(h.clientCertPath, "utf8")).toBe(certFarPem);
    expect(h.logger.info).toHaveBeenCalledWith(
      "[cert-renewal] certificate renewal not needed",
      expect.objectContaining({ thresholdDays: 30 })
    );
  });

  // ── ADR-0015: el gatillo remoto se salta el umbral ────────────────
  //
  // Una rotación de CA o una migración a certificados híbridos tiene que
  // reemitir certificados perfectamente vigentes — que es EXACTAMENTE el
  // caso que el umbral existe para no tocar. Sin `force`, el mensaje
  // `RotateCert` llegaba al agente y no producía nada: `shouldRenew`
  // decía que no tocaba y la función salía por arriba. El síntoma sería
  // «pedí rotar y no pasó nada», con el job en verde.

  it("⚠️ force renueva un cert a 90 días, que sin él NO se tocaría", async () => {
    const h = makeHarness(certFarPem);
    h.priv.call.mockResolvedValue(okRenewResponse());

    const result = await maybeRenewClientCertificate({ ...(h as any), force: true });

    expect(h.priv.call).toHaveBeenCalledTimes(1);
    expect(h.priv.call.mock.calls[0][0].method).toBe("crypto.cert.renew");
    expect(result).not.toBe(h.enrollment);
    // Y lo deja escrito en el log del equipo: sin esto, una rotación de
    // flota y una renovación por calendario son indistinguibles al mirar
    // un endpoint concreto.
    expect(h.logger.info).toHaveBeenCalledWith(
      "[cert-renewal] starting certificate renewal",
      expect.objectContaining({ forced: true })
    );
  });

  it("force NO salta las demás condiciones: sin huella no renueva", async () => {
    // Salta el umbral, no la cordura. La petición al backend se hace
    // CONTRA la huella actual, así que sin ella no hay nada que pedir.
    const h = makeHarness(certFarPem);
    h.enrollment.mtls.clientCertThumbprint = "";

    const result = await maybeRenewClientCertificate({ ...(h as any), force: true });

    expect(h.priv.call).not.toHaveBeenCalled();
    expect(result).toBe(h.enrollment);
  });

  it("sin force el comportamiento de siempre no cambia", async () => {
    // El riesgo del cambio es que `force` se quedara pegado. Este caso
    // repite el de arriba pasando `force: false` explícito.
    const h = makeHarness(certFarPem);

    const result = await maybeRenewClientCertificate({ ...(h as any), force: false });

    expect(result).toBe(h.enrollment);
    expect(h.priv.call).not.toHaveBeenCalled();
  });

  it("cert cerca de expirar (5d) → renueva: llama crypto.cert.renew, escribe el cert y persiste estado", async () => {
    const h = makeHarness(certNearPem);
    h.priv.call.mockResolvedValue(okRenewResponse());

    const result = await maybeRenewClientCertificate(h as any);

    expect(h.priv.call).toHaveBeenCalledTimes(1);
    const req = h.priv.call.mock.calls[0][0];
    expect(req.method).toBe("crypto.cert.renew");
    expect(req.params).toMatchObject({
      serverBaseUrl: "https://api.test.local",
      tenantId: "tenant-1",
      deviceId: "device-1",
      clientCertThumbprint: thumbprintOf(certNearPem)
    });

    // Estado nuevo
    expect(result.mtls.clientCertThumbprint).toBe("NEW-THUMBPRINT");
    expect(result.mtls.issuingCaThumbprint).toBe("CA-THUMB-NEW");
    expect(result.mtls.clientCertNotAfter).toBe("2027-01-01T00:00:00.000Z");
    expect(result.lastRenewedAtUtc).toBeTruthy();
    expect(h.store.save).toHaveBeenCalledWith(result);

    // Archivo escrito con el PEM nuevo y permisos 0600
    expect(fs.readFileSync(h.clientCertPath, "utf8")).toBe(renewedPem);
    expect(fs.statSync(h.clientCertPath).mode & 0o777).toBe(0o600);
  });

  it("respeta CERT_RENEWAL_THRESHOLD_DAYS: umbral 120d hace renovar un cert de 90d", async () => {
    process.env.CERT_RENEWAL_THRESHOLD_DAYS = "120";
    const h = makeHarness(certFarPem);
    h.priv.call.mockResolvedValue(okRenewResponse());

    await maybeRenewClientCertificate(h as any);

    expect(h.priv.call).toHaveBeenCalledTimes(1);
  });

  it("CERT_RENEWAL_THRESHOLD_DAYS inválido (negativo o no numérico) cae al default de 30d", async () => {
    for (const bogus of ["-5", "abc", "0"]) {
      process.env.CERT_RENEWAL_THRESHOLD_DAYS = bogus;
      const h = makeHarness(certFarPem);
      await maybeRenewClientCertificate(h as any);
      expect(h.priv.call).not.toHaveBeenCalled();
    }
  });

  it("sin cert legible en disco (path inexistente) → no renueva (notAfter null)", async () => {
    const h = makeHarness(certNearPem);
    fs.unlinkSync(h.clientCertPath);

    const result = await maybeRenewClientCertificate(h as any);

    expect(result).toBe(h.enrollment);
    expect(h.priv.call).not.toHaveBeenCalled();
  });

  it("cert por vencer pero sin thumbprint en el estado → skip con warning (no llama a la red)", async () => {
    const h = makeHarness(certNearPem, { clientCertThumbprint: undefined });

    const result = await maybeRenewClientCertificate(h as any);

    expect(result).toBe(h.enrollment);
    expect(h.priv.call).not.toHaveBeenCalled();
    expect(h.logger.warn).toHaveBeenCalledWith(
      "[cert-renewal] skipping renewal: missing client cert thumbprint"
    );
  });
});

describe("cert-renewal — respuestas defectuosas del servidor", () => {
  it("respuesta ok:false → lanza y NO escribe ni persiste nada", async () => {
    const h = makeHarness(certNearPem);
    h.priv.call.mockResolvedValue({ ok: false, error: { message: "CA down" } });

    await expect(maybeRenewClientCertificate(h as any)).rejects.toThrow("CA down");
    expect(fs.readFileSync(h.clientCertPath, "utf8")).toBe(certNearPem);
    expect(h.store.save).not.toHaveBeenCalled();
  });

  it("respuesta sin clientCertThumbprint → lanza y NO escribe", async () => {
    const h = makeHarness(certNearPem);
    h.priv.call.mockResolvedValue({ ok: true, result: { clientCertPem: renewedPem } });

    await expect(maybeRenewClientCertificate(h as any)).rejects.toThrow(
      "Certificate renewal response missing clientCertThumbprint"
    );
    expect(fs.readFileSync(h.clientCertPath, "utf8")).toBe(certNearPem);
    expect(h.store.save).not.toHaveBeenCalled();
  });

  it("BUG A4: respuesta con PEM inválido (sin BEGIN CERTIFICATE) → aborta: ni escribe el archivo ni persiste el estado", async () => {
    // Comportamiento CORREGIDO: si el PEM no es válido, se aborta la renovación
    // completa (lanza) SIN escribir el archivo y SIN store.save(), dejando el
    // estado previo (disco + store) idéntico y coherente.
    const h = makeHarness(certNearPem);
    h.priv.call.mockResolvedValue(okRenewResponse({ clientCertPem: "garbage-not-a-pem" }));

    await expect(maybeRenewClientCertificate(h as any)).rejects.toThrow(
      "Certificate renewal response missing or malformed clientCertPem"
    );

    // Disco intacto: sigue el cert viejo.
    expect(fs.readFileSync(h.clientCertPath, "utf8")).toBe(certNearPem);
    // Store no tocado.
    expect(h.store.save).not.toHaveBeenCalled();
  });

  it("BUG A4: PEM con BEGIN CERTIFICATE pero cuerpo no parseable como X.509 → aborta sin escribir ni persistir", async () => {
    // El gate de string no basta: un PEM con el marcador pero basura dentro
    // debe fallar el parse X.509 y abortar antes de cualquier persistencia.
    const h = makeHarness(certNearPem);
    const fakePem =
      "-----BEGIN CERTIFICATE-----\nbm90LWEtcmVhbC1jZXJ0\n-----END CERTIFICATE-----\n";
    h.priv.call.mockResolvedValue(okRenewResponse({ clientCertPem: fakePem }));

    await expect(maybeRenewClientCertificate(h as any)).rejects.toThrow(
      /failed to parse as X\.509/
    );

    expect(fs.readFileSync(h.clientCertPath, "utf8")).toBe(certNearPem);
    expect(h.store.save).not.toHaveBeenCalled();
  });

  it("caBundlePem presente → también reescribe el CA bundle en 0600", async () => {
    const h = makeHarness(certNearPem);
    h.priv.call.mockResolvedValue(okRenewResponse({ caBundlePem: renewedPem }));

    await maybeRenewClientCertificate(h as any);

    expect(fs.readFileSync(h.caBundlePath, "utf8")).toBe(renewedPem);
    expect(fs.statSync(h.caBundlePath).mode & 0o777).toBe(0o600);
  });
});

describe("cert-renewal — atomicWriteFileSync (vía renovación)", () => {
  it("escritura correcta: contenido exacto, sin archivos .tmp- residuales", async () => {
    const h = makeHarness(certNearPem);
    h.priv.call.mockResolvedValue(okRenewResponse());

    await maybeRenewClientCertificate(h as any);

    expect(fs.readFileSync(h.clientCertPath, "utf8")).toBe(renewedPem);
    const leftovers = fs
      .readdirSync(path.dirname(h.clientCertPath))
      .filter((f) => f.includes(".tmp-"));
    expect(leftovers).toEqual([]);
  });

  it("fallo entre write y rename: el destino conserva el contenido viejo INTACTO y el tmp se limpia", async () => {
    const h = makeHarness(certNearPem);
    h.priv.call.mockResolvedValue(okRenewResponse());

    const renameSpy = vi.spyOn(fs, "renameSync").mockImplementation(() => {
      throw new Error("EIO: simulated failure between write and rename");
    });

    await expect(maybeRenewClientCertificate(h as any)).rejects.toThrow(/simulated failure/);

    renameSpy.mockRestore();

    // El PEM destino nunca queda truncado ni mezclado: o viejo o nuevo.
    expect(fs.readFileSync(h.clientCertPath, "utf8")).toBe(certNearPem);
    // Cleanup best-effort del tmp funcionó
    const leftovers = fs
      .readdirSync(path.dirname(h.clientCertPath))
      .filter((f) => f.includes(".tmp-"));
    expect(leftovers).toEqual([]);
    // Y al fallar la escritura, el estado NO se persistió (save va después)
    expect(h.store.save).not.toHaveBeenCalled();
  });

  it("crash simulado a mitad de escritura del tmp: el destino sigue siendo un PEM parseable", async () => {
    const h = makeHarness(certNearPem);
    h.priv.call.mockResolvedValue(okRenewResponse());

    // Simular proceso muerto durante writeFileSync del tmp: write lanza
    // (equivalente observable: el tmp queda a medias, el rename nunca corre).
    const writeSpy = vi.spyOn(fs, "writeFileSync").mockImplementation(() => {
      throw new Error("simulated crash mid-write");
    });

    await expect(maybeRenewClientCertificate(h as any)).rejects.toThrow(/mid-write/);
    writeSpy.mockRestore();

    const onDisk = fs.readFileSync(h.clientCertPath, "utf8");
    expect(onDisk).toBe(certNearPem);
    expect(() => new crypto.X509Certificate(onDisk)).not.toThrow();
  });
});

describe("cert-renewal — carrera con otro proceso (thumbprint mutado durante el await)", () => {
  // BUG A1 CORREGIDO:
  //
  // maybeRenewClientCertificate ahora re-verifica el thumbprint del cert EN
  // DISCO después del await de priv.call. Si otro actor (p.ej. el flujo
  // rotateCert por gRPC) reemplaza el cert en disco mientras esperamos la
  // respuesta, detectamos el cambio (readClientCertThumbprintOnDisk pre vs
  // post) y ABORTAMOS sin pisar el archivo ni persistir el store — el cert
  // más nuevo queda intacto.
  //
  // El guard en src/core/service.ts (~295-313) sigue existiendo pero sólo
  // protege la referencia en memoria; la protección del disco vive aquí.
  it("si otro proceso cambió el cert durante el await, NO lo pisa ni persiste", async () => {
    const h = makeHarness(certNearPem);
    const interloperPem = certFarPem; // "otro proceso" instaló este cert más nuevo

    h.priv.call.mockImplementation(async () => {
      // Mientras esperamos al server, el flujo rotateCert instala otro cert
      fs.writeFileSync(h.clientCertPath, interloperPem, { mode: 0o600 });
      h.enrollment.mtls.clientCertThumbprint = thumbprintOf(interloperPem);
      return okRenewResponse();
    });

    const result = await maybeRenewClientCertificate(h as any);

    // Comportamiento CORRECTO: se detecta la mutación en disco y no se pisa.
    expect(fs.readFileSync(h.clientCertPath, "utf8")).toBe(interloperPem);
    // No se persiste estado: el cert renovado (contra el thumbprint viejo)
    // se descarta de forma segura.
    expect(h.store.save).not.toHaveBeenCalled();
    // Se retorna el enrollment previo sin mutar.
    expect(result).toBe(h.enrollment);
    // Se registró el aborto por carrera.
    expect(h.logger.warn).toHaveBeenCalledWith(
      "[cert-renewal] client cert on disk changed during renewal, aborting to avoid clobbering newer cert",
      expect.objectContaining({ deviceId: "device-1" })
    );
  });
});
