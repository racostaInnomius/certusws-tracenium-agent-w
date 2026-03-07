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

  serverBaseUrl: process.env.SERVER_BASE_URL || "http://localhost:3000",
  agentId: process.env.AGENT_ID || "auto", 
  enrollmentToken: process.env.ENROLLMENT_TOKEN || "",
  agentVersion: process.env.AGENT_VERSION || "0.1.0",
  coreVersion: process.env.CORE_VERSION || "0.1.0",
  channel: (process.env.CHANNEL as "stable" | "beta" | "pilot") || "stable",
};
