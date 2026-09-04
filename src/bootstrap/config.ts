// src/bootstrap/config.ts
import { readRegistryValue } from "./registry";
import dotenv from "dotenv";
import pkg from "../../package.json";
dotenv.config();

function required(name: string, value?: string): string {
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

/**
 * Normaliza el GRPC_ENDPOINT para que el operador pueda omitir el
 * puerto cuando es 443 (caso típico).
 *
 * Aceptamos tres formatos:
 *   "grpc.tracenium.com"        → "grpc.tracenium.com:443"   (default)
 *   "grpc.tracenium.com:443"    → "grpc.tracenium.com:443"   (explícito)
 *   "grpc.tracenium.com:50051"  → "grpc.tracenium.com:50051" (override)
 *
 * El default a 443 facilita la migración: corporate firewalls ya tienen
 * 443 outbound permitido (HTTPS estándar), evitando change-control para
 * abrir puertos custom como 50051. Operadores que necesiten otro puerto
 * (ej. transición desde la versión legacy en :50051) siguen pudiendo
 * pasarlo explícito.
 *
 * IPv6 soportado vía bracket syntax estándar: "[::1]:443".
 */
const REGISTRY_KEY = "HKLM\\Software\\CertusWS\\Tracenium";

function resolveGrpcEndpoint(raw: string): string {
  const value = (raw || "").trim();
  if (!value) {
    throw new Error("Missing required environment variable: GRPC_ENDPOINT");
  }
  // IPv6 bracket-form preserva el puerto si lo trae: "[::1]:443"
  // sin puerto: "[::1]" — agregar :443.
  if (value.startsWith("[")) {
    return value.includes("]:") ? value : `${value}:443`;
  }
  // IPv4 / hostname: presencia de ":" indica puerto explícito.
  return value.includes(":") ? value : `${value}:443`;
}

export const config = {
    // gRPC endpoint (host[:port], defaults to :443 if port omitted)
    grpcEndpoint: resolveGrpcEndpoint(process.env.GRPC_ENDPOINT || ""),

  serverBaseUrl: (() => {
  const raw = process.env.SERVER_BASE_URL;
  const hasValidEnv = typeof raw === "string" && raw.trim().length > 0;

  if (hasValidEnv) {
    const url = raw!.trim();
    console.log(`[Config] SERVER_BASE_URL=${url} (env)`);
    return url;
  }

  const read = readRegistryValue(REGISTRY_KEY, "ServerBaseUrl");
  if (read.value) {
    console.log(`[Config] SERVER_BASE_URL=${read.value} (registry)`);
    return read.value;
  }

  // ⚠️ EL FALLO SE REGISTRA. La versión anterior tenía un `catch {}` mudo, y
  // eso convirtió "no pude leer el registro" en "hablo con localhost para
  // siempre" sin dejar una sola línea que lo explicara.
  console.warn(`[Config] no se pudo leer ServerBaseUrl del registro: ${read.detail}`);

  // ⚠️ EN WINDOWS NO HAY FALLBACK A localhost, Y ESO ES DELIBERADO.
  //
  // El MSI SIEMPRE escribe esta llave, así que en un Windows instalado la
  // única forma de llegar aquí es que la LECTURA fallara — un equipo roto, no
  // el portátil de un desarrollador. Devolver `http://localhost:3000` ahí
  // convierte un problema de arranque en un agente que se pasa semanas
  // conectándose a sí mismo: los updates fallan con ECONNREFUSED a ::1:3000 y
  // la renovación del certificado apunta al mismo sitio, todo en silencio.
  //
  // Dejándolo sin resolver, `getApiBaseUrl` lanza `update_api_base_url_missing`
  // — un error con nombre que viaja en el ACK y dice qué pasa.
  //
  // Fuera de Windows no hay registro que leer, así que el fallback sigue
  // siendo lo correcto: es el caso del desarrollador con nada configurado.
  if (process.platform === "win32") {
    console.error("[Config] SERVER_BASE_URL sin resolver en Windows — revisar la llave del registro");
    return undefined as unknown as string;
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

    const read = readRegistryValue(REGISTRY_KEY, "CertRenewalBaseUrl");
    if (read.value) {
      console.log(`[Config] CERT_RENEWAL_BASE_URL=${read.value} (registry)`);
      return read.value;
    }

    // Opcional por diseño: cert-renewal.ts cae a serverBaseUrl. Pero el motivo
    // se registra igual, porque cuando serverBaseUrl tampoco resuelve, la
    // renovación del certificado se queda sin destino y eso caduca el equipo.
    console.warn(`[Config] CERT_RENEWAL_BASE_URL sin resolver: ${read.detail}`);
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
