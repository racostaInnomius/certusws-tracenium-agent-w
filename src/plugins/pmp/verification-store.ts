// src/plugins/pmp/verification-store.ts
//
// La foto previa de cada patch_install (ADR-0038 F1), en disco: tiene que
// sobrevivir al reinicio que viene después, que es justo cuando se usa.
// Las últimas 20, por jobId.

import fs from "fs";
import path from "path";
import type { VerificationBaseline } from "./verification";

const KEEP = 20;

function file(): string {
  const base =
    process.platform === "win32"
      ? path.join(process.env.ProgramData || "C:\\ProgramData", "Tracenium")
      : process.platform === "darwin"
        ? "/Library/Application Support/Tracenium"
        : "/var/lib/tracenium";
  const dir = process.env.TRACENIUM_STATE_DIR || path.join(base, "state");
  fs.mkdirSync(dir, { recursive: true });
  return path.join(dir, "pmp-verification.json");
}

function load(): VerificationBaseline[] {
  try {
    const raw = JSON.parse(fs.readFileSync(file(), "utf8"));
    return Array.isArray(raw) ? raw : [];
  } catch {
    return [];
  }
}

export function saveBaseline(b: VerificationBaseline): void {
  const all = load().filter((x) => x.jobId !== b.jobId);
  all.push(b);
  const target = file();
  const tmp = `${target}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(all.slice(-KEEP)), "utf8");
  fs.renameSync(tmp, target);
}

export function loadBaseline(jobId: string): VerificationBaseline | null {
  return load().find((x) => x.jobId === jobId) ?? null;
}
