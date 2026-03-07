// src/bootstrap/enroll.ts
import fs from "fs";
import crypto from "crypto";
import { EnrollmentStore } from "./enrollment-store";
import { EnrollmentState } from "./enrollment-state";
import { buildEnrollmentPayload } from "./enroll-payload";
import { config } from "./config";

type EnrollResponse = {
  tenantId: string;
  deviceId: string;
  issuedAtUtc: string;
  mTls: {
    clientCertPem: string;
    caBundlePem: string;
  };
  bootstrapPolicy: {
    channel: "stable" | "beta" | "pilot";
    capabilities: string[];
  };
};

async function generateCsrViaPrivSvc(): Promise<{ csrPem: string }> {
  // IPC with PrivSvc over named pipe (already used elsewhere in agent)
  const net = await import("net");

  const request = JSON.stringify({
    v: 1,
    id: `csr_${Date.now()}`,
    method: "win.crypto.csr.generate",
    params: {
      reuseExistingKey: true
    },
    meta: {}
  });

  return new Promise((resolve, reject) => {
    const client = net.createConnection({ path: "\\\\.\\pipe\\tracenium.privsvc.v1" });

    let response = "";

    client.on("connect", () => {
      client.write(request + "\n");
    });

    client.on("data", (data) => {
      response += data.toString();
    });

    client.on("end", () => {
      try {
        const parsed = JSON.parse(response);
        if (!parsed.ok) {
          return reject(new Error(parsed.error?.message || "CSR generation failed"));
        }
        resolve({ csrPem: parsed.result.csrPem });
      } catch (err) {
        reject(err);
      }
    });

    client.on("error", reject);
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
      capabilities: ["amm"],
    }
  };

  return state;
}

export async function ensureEnrolled(): Promise<EnrollmentState> {
  const store = new EnrollmentStore();
  const existing = store.load();
  if (existing?.tenantId && existing?.deviceId) return existing;

  // token siempre requerido (aunque sea local)
  const enrollmentToken = config.enrollmentToken;
  if (!enrollmentToken) {
    throw new Error("Missing ENROLLMENT_TOKEN. Agent is not enrolled.");
  }

  // modo local explícito (mientras backend no está listo)
  if (isLocalEnrollEnabled()) {
    const state = buildLocalEnrollmentState(store);
    store.save(state);
    return state;
  }

  const csr = await generateCsrViaPrivSvc();
  const payload = {
    ...(await buildEnrollmentPayload()),
    csrPem: csr.csrPem
  };
  const res = await fetch(`${config.serverBaseUrl}/api/v1/security/enroll`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${enrollmentToken}`
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Enroll failed: ${res.status} ${text}`);
  }

  const data = (await res.json()) as EnrollResponse;

  const paths = store.getPaths();
  fs.writeFileSync(paths.clientCert, data.mTls.clientCertPem, "utf8");
  fs.writeFileSync(paths.caBundle, data.mTls.caBundlePem, "utf8");

  const state: EnrollmentState = {
    tenantId: data.tenantId,
    deviceId: data.deviceId,
    enrolledAtUtc: new Date().toISOString(),
    mtls: {
      clientCertPath: paths.clientCert,
      caBundlePath: paths.caBundle,
    },
    bootstrap: {
      channel: data.bootstrapPolicy.channel,
      capabilities: data.bootstrapPolicy.capabilities,
    }
  };

  store.save(state);
  return state;
}