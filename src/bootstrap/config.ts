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
  // Single source of truth for agent / core versions: the repo's
  // package.json. Previously hardcoded as a fallback string ("1.1.4"
  // / "1.1.2" / etc.), which silently desynced from package.json
  // whenever a release bumped one but not the other. Net effect:
  // operators saw 1.1.3 advertised in the binary metadata, an agent
  // installed it, but the running agent self-reported the OLD
  // hardcoded version after restart (the .pkg I built carried a
  // bundle whose agentVersion fallback was still pointing at the
  // previous release because nobody had edited config.ts).
  //
  // Reading from package.json fixes it: bumping `version` in
  // package.json is the only change needed for a release. esbuild
  // inlines the JSON import at bundle time, so there's no runtime
  // file-read cost or path-resolution surprise on different platforms.
  agentVersion: process.env.AGENT_VERSION || pkg.version,
  coreVersion: process.env.CORE_VERSION || pkg.version,
  channel: (process.env.CHANNEL as "stable" | "beta" | "pilot") || "stable",
};
