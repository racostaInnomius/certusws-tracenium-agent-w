// src/bootstrap/config.ts
import dotenv from "dotenv";
import pkg from "../../package.json";
dotenv.config();

function required(name: string, value?: string): string {
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export const config = {
    // gRPC endpoint (host:port)
    grpcEndpoint: required(
    "GRPC_ENDPOINT",
    process.env.GRPC_ENDPOINT
  ),

  serverBaseUrl: (() => {
  const raw = process.env.SERVER_BASE_URL;
  const hasValidEnv = typeof raw === "string" && raw.trim().length > 0;

  if (hasValidEnv) {
    const url = raw!.trim();
    console.log(`[Config] SERVER_BASE_URL=${url} (env)`);
    return url;
  }

  // Try reading from Windows registry
  try {
    if (process.platform === "win32") {
      const { execSync } = require("child_process");
      const output = execSync(
        'reg query "HKLM\\Software\\CertusWS\\Tracenium" /v ServerBaseUrl',
        { encoding: "utf8" }
      );

      const match = output.match(/ServerBaseUrl\s+REG_\w+\s+(.+)/i);
      if (match && match[1]) {
        const url = match[1].trim();
        if (url.length > 0) {
          console.log(`[Config] SERVER_BASE_URL=${url} (registry)`);
          return url;
        }
      }
    }
  } catch {
    // ignore registry errors
  }

  const fallback = "http://localhost:3000";
  console.warn(`[Config] SERVER_BASE_URL not set (env/registry), using default: ${fallback}`);
  return fallback;
})(),
  certRenewalBaseUrl: (() => {
    const raw = process.env.CERT_RENEWAL_BASE_URL;
    if (typeof raw === "string" && raw.trim().length > 0) {
      const url = raw.trim();
      console.log(`[Config] CERT_RENEWAL_BASE_URL=${url} (env)`);
      return url;
    }

    try {
      if (process.platform === "win32") {
        const { execSync } = require("child_process");
        const output = execSync(
          'reg query "HKLM\\Software\\CertusWS\\Tracenium" /v CertRenewalBaseUrl',
          { encoding: "utf8" }
        );

        const match = output.match(/CertRenewalBaseUrl\s+REG_\w+\s+(.+)/i);
        if (match && match[1]) {
          const url = match[1].trim();
          if (url.length > 0) {
            console.log(`[Config] CERT_RENEWAL_BASE_URL=${url} (registry)`);
            return url;
          }
        }
      }
    } catch {
      // ignore registry errors
    }

    return undefined;
  })(),
  agentId: process.env.AGENT_ID || "auto",
  enrollmentToken: process.env.ENROLLMENT_TOKEN || "",
  // Hard-coded to package.json. NO env-var override:
  //
  // The macOS installer's old postinstall used to write
  // `AGENT_VERSION=1.1.2` into /Library/Application Support/Tracenium/
  // Agent/.env, and dotenv loaded it at boot. Even after we replaced
  // the bundle on disk via self-update, that stale .env shadowed
  // pkg.version and the agent kept self-reporting 1.1.2 forever.
  //
  // We now (a) stopped writing AGENT_VERSION to .env in postinstall
  // and (b) ignore process.env.AGENT_VERSION entirely. The bundled
  // package.json is the only source. esbuild inlines the JSON
  // import at bundle time, so a release is `bump package.json,
  // build, ship` — no other file to keep in sync. Dev override is
  // still possible by editing package.json before bundling.
  agentVersion: pkg.version,
  coreVersion: pkg.version,
  channel: (process.env.CHANNEL as "stable" | "beta" | "pilot") || "stable",
};
