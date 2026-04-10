// src/bootstrap/enroll.ts
import fs from "fs";
import crypto from "crypto";
import { EnrollmentStore } from "./enrollment-store";
import { EnrollmentState } from "./enrollment-state";
import { buildEnrollmentPayload } from "./enroll-payload";
import { config } from "./config";
import { readEnrollmentToken } from "./token-source";
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

  const request = JSON.stringify({
    v: 1,
    id: `csr_${Date.now()}`,
    method: "crypto.csr.generate",
    params: {
      tenantId,
      deviceId,
      reuseExistingKey: true
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

// Helper to install certificates via PrivSvc IPC
async function installCertViaPrivSvc(clientCertPem: string, caBundlePem: string): Promise<{ clientCertThumbprint: string; issuingCaThumbprint?: string }> {
  const net = await import("net");

  const deviceId = getDeviceId();
  const tenantId = "bootstrap";

  const request = JSON.stringify({
    v: 1,
    id: `cert_install_${Date.now()}`,
    method: "crypto.cert.install",
    params: {
      deviceId: deviceId,
      clientCertPem: clientCertPem,
      caBundlePem: caBundlePem
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
            issuingCaThumbprint: result.issuingCaThumbprint ? String(result.issuingCaThumbprint) : undefined
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

  const enrollmentToken = readEnrollmentToken();

  if (!enrollmentToken) {
    console.error("[Enroll] ENROLLMENT_TOKEN not found in env/registry.");
    throw new Error("Missing ENROLLMENT_TOKEN. Agent is not enrolled.");
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
      console.log("[Enroll] Response body:", responseBody);

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
          issuingCaThumbprint: certInstall.issuingCaThumbprint
        } as any,
        bootstrap: {
          channel: "stable",
          capabilities: ["amp"],
        }
      };

      store.save(state);
      console.log("[Enroll] Enrollment state saved:", state);
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