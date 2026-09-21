// src/domain/file-integrity-policy.ts
//
// ADR-0027 — la parte de la política que dice QUÉ ficheros vigilar
// (`compliance.fileIntegrity`), tal como la acepta el agente.
//
// El control plane ya la validó al guardarla. Aquí se vuelve a aplicar con
// las mismas cotas, porque quien recorre el disco también tiene que decidir
// cuándo parar: una política vieja, o una que llegue mal, no puede convertir
// un ciclo de cumplimiento en un recorrido de horas. Espejo de
// certusws-tracenium/modules/file-integrity/file-integrity-policy.ts.

export type FileIntegrityPlatform = "windows" | "macos" | "linux" | "any";
export type FileIntegrityPurpose = "system" | "audit_logs" | "application";

export type FileIntegritySet = {
  id: string;
  platform: FileIntegrityPlatform;
  purpose: FileIntegrityPurpose;
  path: string;
  recursive: boolean;
  maxDepth: number;
};

export type FileIntegrityPolicy = {
  enabled: boolean;
  sets: FileIntegritySet[];
  maxFilesPerDevice: number;
  maxFileBytes: number;
};

export const FIM_LIMITS = Object.freeze({
  maxSets: 25,
  maxPathChars: 512,
  maxDepth: 8,
  defaultMaxDepth: 4,
  defaultMaxFilesPerDevice: 5_000,
  maxFilesPerDeviceCeiling: 20_000,
  defaultMaxFileBytes: 8 * 1024 * 1024,
  maxFileBytesCeiling: 64 * 1024 * 1024,
});

const ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const PLATFORMS = new Set<FileIntegrityPlatform>(["windows", "macos", "linux", "any"]);
const PURPOSES = new Set<FileIntegrityPurpose>(["system", "audit_logs", "application"]);

/** Absoluta, sin comodines y sin `..`. La misma regla que el control plane. */
export function isAcceptablePath(raw: unknown): boolean {
  if (typeof raw !== "string") return false;
  const p = raw.trim();
  if (!p || p.length > FIM_LIMITS.maxPathChars) return false;
  if (/[*?]/.test(p)) return false;
  if (p.split(/[\\/]+/).some((seg) => seg === "..")) return false;
  return /^[a-zA-Z]:[\\/]/.test(p) || p.startsWith("\\\\") || p.startsWith("/");
}

/**
 * null = el tenant no vigila nada. Un conjunto que no pasa la regla se DESCARTA
 * en vez de tumbar la política entera: el resto de la vigilancia sigue.
 */
export function sanitizeFileIntegrityPolicy(raw: unknown): FileIntegrityPolicy | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  const seen = new Set<string>();
  const sets: FileIntegritySet[] = [];
  for (const entry of Array.isArray(r.sets) ? r.sets.slice(0, FIM_LIMITS.maxSets) : []) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
    const s = entry as Record<string, unknown>;
    const id = typeof s.id === "string" ? s.id.trim().toLowerCase() : "";
    if (!ID_RE.test(id) || seen.has(id) || !isAcceptablePath(s.path)) continue;
    seen.add(id);
    const depth = Number(s.maxDepth);
    sets.push({
      id,
      platform: PLATFORMS.has(s.platform as FileIntegrityPlatform) ? (s.platform as FileIntegrityPlatform) : "any",
      purpose: PURPOSES.has(s.purpose as FileIntegrityPurpose) ? (s.purpose as FileIntegrityPurpose) : "system",
      path: String(s.path).trim(),
      recursive: s.recursive === true,
      maxDepth: Number.isInteger(depth) && depth >= 1 && depth <= FIM_LIMITS.maxDepth ? depth : FIM_LIMITS.defaultMaxDepth,
    });
  }
  const clamp = (v: unknown, dflt: number, min: number, max: number) =>
    typeof v === "number" && Number.isInteger(v) ? Math.min(Math.max(v, min), max) : dflt;
  return {
    enabled: r.enabled === undefined ? sets.length > 0 : r.enabled === true,
    sets,
    maxFilesPerDevice: clamp(r.maxFilesPerDevice, FIM_LIMITS.defaultMaxFilesPerDevice, 1, FIM_LIMITS.maxFilesPerDeviceCeiling),
    maxFileBytes: clamp(r.maxFileBytes, FIM_LIMITS.defaultMaxFileBytes, 1024, FIM_LIMITS.maxFileBytesCeiling),
  };
}

/** ¿Este conjunto se vigila en esta plataforma? */
export function appliesTo(set: FileIntegritySet, platform: NodeJS.Platform): boolean {
  if (set.platform === "any") return true;
  return (
    (set.platform === "windows" && platform === "win32") ||
    (set.platform === "macos" && platform === "darwin") ||
    (set.platform === "linux" && platform === "linux")
  );
}
