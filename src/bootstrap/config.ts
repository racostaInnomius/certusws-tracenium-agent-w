// src/bootstrap/config.ts
import dotenv from "dotenv";
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
  agentId: process.env.AGENT_ID || "auto", 
  enrollmentToken: process.env.ENROLLMENT_TOKEN || "",
  agentVersion: process.env.AGENT_VERSION || "1.0.76",
  coreVersion: process.env.CORE_VERSION || "1.0.76",
  channel: (process.env.CHANNEL as "stable" | "beta" | "pilot") || "stable",
};
