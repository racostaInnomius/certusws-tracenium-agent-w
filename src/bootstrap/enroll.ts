// src/bootstrap/enroll.ts
import fs from "fs";
import crypto from "crypto";
import { EnrollmentStore } from "./enrollment-store";
import { EnrollmentState } from "./enrollment-state";
import { buildEnrollmentPayload } from "./enroll-payload";
import { config } from "./config";
import { clearEnrollmentTokenFile } from "./token-source";
import { clearBlockedMarker, waitForEnrollmentToken } from "./token-wait";
import { execSync } from "child_process";
import { getDeviceId } from "../platform/device-id";
import { writeEnrollmentMetadata } from "../platform/enrollment-meta";
import { getPrivSvcPipePath } from "../platform/privsvc-path";

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function retry<T>(fn: () => Promise<T>, attempts = 5, baseDelay = 1000): Promise<T> {
  let lastError: unknown;

  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;

      // Do not retry fatal enrollment errors
      if (err instanceof Error && err.message.startsWith("ENROLL_FATAL")) {
        throw err;
      }

      const delay = baseDelay * Math.pow(2, i);
      console.warn(`[Enroll] Attempt ${i + 1} failed. Retrying in ${delay}ms`, err);

      if (i === attempts - 1) break;

      await sleep(delay);
    }
  }

  throw lastError;
}

type EnrollResponse = {
  tenantId: string;
  deviceId: string;
  issuedAtUtc: string;
  grpcEndpoint?: string;
  mTls: {
    clientCertPem: string;
    caBundlePem: string;
  };
};

async function waitForPrivSvcPipe(timeoutMs = 20000): Promise<void> {
  const net = await import("net");

  const start = Date.now();

  while (Date.now() - start < timeoutMs) {
    try {
      await new Promise((resolve, reject) => {
        const socket = net.createConnection({ path: getPrivSvcPipePath() });

        socket.once("connect", () => {
          socket.destroy();
          resolve(true);
        });

        socket.once("error", reject);
      });

      return;
    } catch {
      await new Promise(r => setTimeout(r, 1000));
    }
  }

  throw new Error("PrivSvc pipe not ready within timeout");
}

async function generateCsrViaPrivSvc(): Promise<{ csrPem: string; deviceId: string }> {
  // IPC with PrivSvc over named pipe (already used elsewhere in agent)
  const net = await import("net");

  // tenantId is no longer derived from the token.
  // The backend resolves the tenant from the bootstrapToken during enrollment.
  // PrivSvc only needs a stable value for CSR generation context.
  const tenantId = "bootstrap";

  const deviceId = getDeviceId();

  console.log("[Enroll] CSR request tenantId:", tenantId);
  console.log("[Enroll] CSR request deviceId:", deviceId);

  // Cross-platform contract: the backend's CSR validator expects an
  // RSA public key (checks the DER OID for rsaEncryption). Historically
  // each PrivSvc picked its own algorithm — Windows defaulted to
  // ECDSA P-256 (via CNG), macOS to RSA-2048 (via openssl) — and
  // enrollment silently broke on Windows once the backend tightened
  // validation.
  //
  // Agent-core owns the contract from here forward: it's the one layer
  // that runs on every OS, so it's the right place to dictate shape.
  // Passing `keyAlgorithm` explicitly means:
  //   - Each PrivSvc (Windows .NET CNG, macOS openssl, future Linux)
  //     implements the same algorithm, regardless of its platform-
  //     native default.
  //   - If the backend ever accepts more algorithms, we negotiate here
  //     rather than hunting down three OS-specific code paths.
  const request = JSON.stringify({
    v: 1,
    id: `csr_${Date.now()}`,
    method: "crypto.csr.generate",
    params: {
      tenantId,
      deviceId,
      reuseExistingKey: true,
      keyAlgorithm: "RSA_2048"
    },
    meta: {
      tenantId,
      deviceId
    }
  });

  return new Promise((resolve, reject) => {
    const client = net.createConnection({ path: getPrivSvcPipePath() });

    let response = "";
    const timeout = setTimeout(() => {
      client.destroy();
      reject(new Error("PrivSvc CSR request timeout"));
    }, 30000);

    client.on("connect", () => {
      // send request but DO NOT close the pipe yet
      // PrivSvc will respond on the same connection
      client.write(request + "\n");
    });

    client.on("data", (data) => {
      response += data.toString();

      // process line-delimited JSON responses
      let idx;
      while ((idx = response.indexOf("\n")) !== -1) {
        const line = response.slice(0, idx).trim();
        response = response.slice(idx + 1);

        if (!line) continue;

        console.log("[Enroll] Raw CSR response:", line);
        clearTimeout(timeout);

        try {
          const parsed = JSON.parse(line);

          if (!parsed.ok) {
            reject(new Error(parsed.error?.message || "CSR generation failed"));
            client.destroy();
            return;
          }

          if (!parsed.result?.csrPem) {
            reject(new Error("PrivSvc returned response without csrPem"));
            client.destroy();
            return;
          }

          resolve({ csrPem: parsed.result.csrPem, deviceId });
          client.destroy();
          return;

        } catch (err) {
          reject(err);
          client.destroy();
          return;
        }
      }
    });

    client.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

/**
 * Manda un mensaje al PrivSvc y espera su respuesta.
 *
 * Existe porque el punto 10 necesita DOS viajes y duplicar el bloque de
 * socket entero para el segundo habría dejado dos temporizadores, dos
 * parseos y dos formas de fallar donde antes había una.
 */
async function sendToPrivSvc(mensaje: unknown, que: string): Promise<any> {
  const net = await import("net");
  const linea = JSON.stringify(mensaje) + "\n";

  return new Promise((resolve, reject) => {
    const client = net.createConnection({ path: getPrivSvcPipePath() });
    let acumulado = "";
    const timeout = setTimeout(() => {
      client.destroy();
      reject(new Error(`${que} timeout`));
    }, 30000);

    client.on("connect", () => client.write(linea));

    client.on("data", (data) => {
      acumulado += data.toString();
      const idx = acumulado.indexOf("\n");
      if (idx === -1) return;
      clearTimeout(timeout);
      const line = acumulado.slice(0, idx).trim();
      client.destroy();
      try {
        const parsed = JSON.parse(line);
        if (!parsed.ok) {
          reject(new Error(parsed.error?.message || `${que} failed`));
          return;
        }
        resolve(parsed.result || {});
      } catch (err) {
        reject(err);
      }
    });

    client.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

// Helper to install certificates via PrivSvc IPC
async function installCertViaPrivSvc(clientCertPem: string, caBundlePem: string): Promise<{ clientCertThumbprint: string; issuingCaThumbprint?: string; issuingCaThumbprints?: string[] }> {
  const net = await import("net");

  const deviceId = getDeviceId();
  const tenantId = "bootstrap";

  // ADR-0015 punto 10 — la cadena de CA viaja en SU PROPIO mensaje.
  //
  // ⚠️ El IPC es JSON delimitado por saltos de línea: un mensaje es UNA
  // línea, y en Windows el pipe tiene un tope de 64 KB por línea. Con
  // certificados catalyst la cuenta deja de sobrar —la hoja pasa de ~0,6
  // a ~6 KB, y una cadena híbrida de tres se acerca a 24 KB— así que
  // mandar cadena y hoja juntas es acercarse al tope por ahorrarse un
  // viaje. Aquí, en macOS y Linux, el socket no tiene ese tope: se hace
  // igual porque un contrato IPC que se comporta distinto según el
  // sistema se prueba en uno y falla en otro, y esa cicatriz ya la tiene
  // este producto.
  //
  // El compromiso sigue siendo UNO: `stage` sólo deja el bundle en
  // espera. Instalar la cadena sin la hoja dejaría al equipo confiando en
  // una CA nueva sin certificado con que hablarle.
  await sendToPrivSvc({
    v: 1,
    id: `cert_stage_${Date.now()}`,
    method: "crypto.cert.stage",
    params: { deviceId, caBundlePem },
    meta: { tenantId, deviceId }
  }, "PrivSvc CA bundle stage");

  const request = JSON.stringify({
    v: 1,
    id: `cert_install_${Date.now()}`,
    method: "crypto.cert.install",
    params: {
      deviceId: deviceId,
      clientCertPem: clientCertPem
      // El bundle NO va aquí: lo dejó el `stage` de arriba. El privsvc
      // sigue aceptándolo en este mensaje por si las dos mitades del
      // paquete no coinciden durante una actualización.
    },
    meta: {
      tenantId,
      deviceId
    }
  });

  return new Promise((resolve, reject) => {
    const client = net.createConnection({ path: getPrivSvcPipePath() });

    let response = "";
    const timeout = setTimeout(() => {
      client.destroy();
      reject(new Error("PrivSvc cert install timeout"));
    }, 30000);

    client.on("connect", () => {
      client.write(request + "\n");
    });

    client.on("data", (data) => {
      response += data.toString();

      let idx;
      while ((idx = response.indexOf("\n")) !== -1) {
        const line = response.slice(0, idx).trim();
        response = response.slice(idx + 1);

        if (!line) continue;

        clearTimeout(timeout);

        try {
          const parsed = JSON.parse(line);

          if (!parsed.ok) {
            reject(new Error(parsed.error?.message || "Certificate install failed"));
            client.destroy();
            return;
          }

          const result = parsed.result || {};

          client.destroy();
          resolve({
            clientCertThumbprint: String(result.clientCertThumbprint || ""),
            issuingCaThumbprint: result.issuingCaThumbprint ? String(result.issuingCaThumbprint) : undefined,
            // Un privsvc anterior no la manda; se deja undefined y el
            // consumidor cae al valor singular.
            issuingCaThumbprints: Array.isArray(result.issuingCaThumbprints)
              ? result.issuingCaThumbprints.map(String).filter(Boolean)
              : undefined
          });
          return;

        } catch (err) {
          reject(err);
          client.destroy();
          return;
        }
      }
    });

    client.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

function isLocalEnrollEnabled(): boolean {
  return process.env.TRACENIUM_LOCAL_ENROLL === "1";
}

function buildLocalEnrollmentState(store: EnrollmentStore): EnrollmentState {
  const paths = store.getPaths();

  const tenantId = process.env.TENANT_ID || "local-tenant";
  const deviceId = process.env.DEVICE_ID || crypto.randomUUID();

  // placeholders mTLS (luego serán reemplazados por enrollment real)
  if (!fs.existsSync(paths.clientCert)) fs.writeFileSync(paths.clientCert, "", "utf8");
  if (!fs.existsSync(paths.clientKey)) fs.writeFileSync(paths.clientKey, "", "utf8");
  if (!fs.existsSync(paths.caBundle)) fs.writeFileSync(paths.caBundle, "", "utf8");

  const state: EnrollmentState = {
    tenantId,
    deviceId,
    enrolledAtUtc: new Date().toISOString(),
    mtls: {
      clientCertPath: paths.clientCert,
      caBundlePath: paths.caBundle,
    },
    bootstrap: {
      channel: "stable",
      capabilities: ["amp"],
    }
  };

  return state;
}

export async function ensureEnrolled(): Promise<EnrollmentState> {
  const store = new EnrollmentStore();
  const existing = store.load();

  console.log("[Enroll] Existing enrollment state:", existing);

  if (existing && (!existing.tenantId || !existing.deviceId)) {
    console.warn("[Enroll] Corrupted enrollment state detected. Clearing store.");
    store.clear();
  }

  if (
    existing?.tenantId &&
    existing?.deviceId &&
    (existing as any)?.mtls?.clientCertThumbprint &&
    fs.existsSync(store.getPaths().clientCert) &&
    fs.existsSync(store.getPaths().caBundle)
  ) {
    console.log("[Enroll] Agent already enrolled:", existing.deviceId);
    return existing;
  }

  if (existing) {
    console.warn("[Enroll] Enrollment state missing certificate thumbprints. Re-enrolling.");
    store.clear();
  }

  // ⚠️ Antes esto era `throw`, y el gestor de servicios reciclaba el proceso:
  // 3722 arranques en cinco días sin avanzar un milímetro. Ahora espera —el
  // token puede aparecer sin que nadie reinicie nada— y explica por qué, una
  // sola vez y en la máquina. Ver token-wait.ts.
  const enrollmentToken = await waitForEnrollmentToken();

  if (!enrollmentToken) {
    throw new Error("Missing enrollment token. Agent is not enrolled.");
  }

  console.log("[Enroll] Enrollment token detected.");

  // modo local explícito (mientras backend no está listo)
  if (isLocalEnrollEnabled()) {
    const state = buildLocalEnrollmentState(store);
    store.save(state);
    return state;
  }

  console.log("[Enroll] Waiting for PrivSvc pipe...");
  await waitForPrivSvcPipe();
  console.log("[Enroll] PrivSvc pipe ready.");

  console.log("[Enroll] Requesting CSR from PrivSvc...");

  const csr = await retry(
    async () => generateCsrViaPrivSvc(),
    5,
    1000
  );

  const deviceId = csr.deviceId;

  console.log("[Enroll] CSR generated.");

  // ---- Enroll lock (prevents concurrent enroll attempts) ----
  const lockPath = store.getPaths().clientCert + ".enroll.lock";

  try {
    const fd = fs.openSync(lockPath, "wx");
    fs.closeSync(fd);
    console.log("[Enroll] Enroll lock acquired.");
  } catch {
    console.warn("[Enroll] Another enrollment process is already running. Waiting for lock release...");

    const start = Date.now();
    while (fs.existsSync(lockPath)) {
      await sleep(2000);

      if (Date.now() - start > 120000) {
        console.warn("[Enroll] Enroll lock timeout. Continuing anyway.");
        break;
      }
    }
  }

  while (true) {
    try {
      const serverBaseUrl = config.serverBaseUrl;
      console.log("[Enroll] Sending enrollment request to backend:", `${serverBaseUrl}/api/v1/security/enroll`);
      console.log("[Enroll] Enrollment payload:", {
        bootstrapToken: "[redacted]",
        deviceId,
        csrLength: csr.csrPem.length,
        agentVersion: config.agentVersion
      });

      const payload = {
        bootstrapToken: enrollmentToken,
        csrPem: csr.csrPem.trim(),
        deviceId,
        agentVersion: config.agentVersion
      };

      const res = await retry(
        async () => {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 15000);

          let response;
          try {
            response = await fetch(`${serverBaseUrl}/api/v1/security/enroll`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json"
              },
              body: JSON.stringify(payload),
              signal: controller.signal
            });
          } finally {
            clearTimeout(timeout);
          }

        if (!response.ok) {
          const txt = await response.text().catch(() => "");

          // Terminal errors (do not retry)
          if (
            response.status === 401 ||
            (response.status === 403 && txt.includes("Token expired"))
          ) {
            throw new Error(`ENROLL_FATAL: ${txt}`);
          }

            throw new Error(`Enroll HTTP ${response.status}: ${txt}`);
        }

        return response;
        },
        5,
        2000
      );

      const responseBody = await res.text();

      console.log("[Enroll] Response status:", res.status);
      // NEVER log the raw enrollment response body. It contains the
      // clientCertPem and caBundlePem (bearer-equivalent material on a
      // compromised endpoint). Log only shape + sizes so we can still
      // diagnose issues without leaking cert material into journald /
      // launchd logs / anywhere downstream log shippers might scrape.
      const _bodySummary = (() => {
        try {
          const parsed = JSON.parse(responseBody);
          return {
            tenantId: parsed?.tenantId ?? null,
            deviceId: parsed?.deviceId ?? null,
            hasClientCertPem:
              typeof parsed?.mTls?.clientCertPem === "string" &&
              parsed.mTls.clientCertPem.includes("BEGIN CERTIFICATE"),
            hasCaBundlePem:
              typeof parsed?.mTls?.caBundlePem === "string" &&
              parsed.mTls.caBundlePem.includes("BEGIN CERTIFICATE"),
            clientCertBytes: parsed?.mTls?.clientCertPem?.length ?? 0,
            caBundleBytes: parsed?.mTls?.caBundlePem?.length ?? 0
          };
        } catch {
          return { parseOk: false, bytes: responseBody.length };
        }
      })();
      console.log("[Enroll] Response body summary:", _bodySummary);

      const data = JSON.parse(responseBody) as EnrollResponse;

      if (!data.tenantId || !data.deviceId) {
        throw new Error("[Enroll] Backend response missing tenantId/deviceId");
      }

      console.log("[Enroll] Enrollment successful. Tenant:", data.tenantId, "Device:", data.deviceId);

      const paths = store.getPaths();

      console.log("[Enroll] Installing certificates via PrivSvc...");

      const certInstall = await installCertViaPrivSvc(
        data.mTls.clientCertPem,
        data.mTls.caBundlePem
      );

      console.log("[Enroll] Certificate installation completed.");
      console.log("[Enroll] Installed client cert thumbprint:", certInstall.clientCertThumbprint);

      fs.writeFileSync(paths.clientCert, data.mTls.clientCertPem, "utf8");
      fs.writeFileSync(paths.caBundle, data.mTls.caBundlePem, "utf8");

      const state: EnrollmentState = {
        tenantId: data.tenantId,
        deviceId: data.deviceId,
        enrolledAtUtc: new Date().toISOString(),
        mtls: {
          clientCertPath: paths.clientCert,
          caBundlePath: paths.caBundle,
          clientCertThumbprint: certInstall.clientCertThumbprint,
          issuingCaThumbprint: certInstall.issuingCaThumbprint,
          issuingCaThumbprints: certInstall.issuingCaThumbprints
        } as any,
        bootstrap: {
          channel: "stable",
          capabilities: ["amp"],
        }
      };

      store.save(state);
      // Intentionally terse: full `state` prints the cert paths and
      // thumbprints which aren't secret, but we've had incidents where
      // this log got piped into a SaaS log shipper. Keep identifiers
      // only; paths are deterministic anyway.
      console.log("[Enroll] Enrollment state saved:", {
        tenantId: state.tenantId,
        deviceId: state.deviceId,
        enrolledAtUtc: state.enrolledAtUtc,
        clientCertThumbprint: state.mtls?.clientCertThumbprint
      });
      try {
        fs.unlinkSync(lockPath);
        console.log("[Enroll] Enroll lock released.");
      } catch {}

      try {
        await writeEnrollmentMetadata({
          tenantId: data.tenantId,
          enrolledAtUtc: state.enrolledAtUtc,
          agentVersion: config.agentVersion
        });
      } catch (err) {
        console.warn("[Enroll] Failed to persist enrollment metadata:", err);
      }

      clearEnrollmentTokenFile();
      // El aviso de "no enrolado" que quedó en disco de un arranque anterior
      // dejaría a alguien persiguiendo un problema ya resuelto.
      clearBlockedMarker();

      return state;

    } catch (err) {
      if (err instanceof Error && err.message.includes("ENROLL_FATAL")) {
        console.error("[Enroll] Fatal enrollment error:", err.message);
        try { fs.unlinkSync(lockPath); } catch {}
        throw err; // stop agent startup
      }

      console.error("[Enroll] Enrollment attempt failed. Retrying in 30s.", err);
      await sleep(30000);
    }
  }
}
