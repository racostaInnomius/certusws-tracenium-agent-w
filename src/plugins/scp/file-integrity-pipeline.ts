// src/plugins/scp/file-integrity-pipeline.ts
//
// ADR-0027 F3 — de la lectura de ficheros al mensaje `fim`.
//
// Viaja SOLO, en su propio evento del outbox (persistencia, reintento y ACK
// por evento), y el control plane lo atiende aparte: un mensaje de FIM no
// puede tumbar el snapshot de cumplimiento ni al revés.
//
// Cuándo se manda:
//   · la PRIMERA vez, y cada vez que cambian los conjuntos declarados → la
//     foto completa (`files`). El control plane la toma como línea base de
//     esos conjuntos y NO avisa de ella: añadir un conjunto a la política no
//     puede disparar una alerta por cada fichero que ya estaba ahí.
//   · con cambios → sólo el delta.
//   · sin cambios → un latido al día con los recuentos. Sin él, el informe se
//     queda viejo y el control plane dejaría de considerar activa la
//     vigilancia a los 7 días, aunque funcione perfectamente.
//
// ⚠️ La lección de las impresoras: si NO se pudo mirar, la línea base local no
// se toca. Grabar un vacío que en realidad es «no pude» lo convertiría en
// «se borró todo» en la siguiente pasada.

import crypto from "crypto";
import fsp from "fs/promises";
import { createReadStream } from "fs";
import type { FileIntegrityPolicy } from "../../domain/file-integrity-policy";
import { keyOf, scanFileIntegrity, type FsLike, type ScannedFile } from "../../domain/file-integrity-scan";

export const FIM_FACTS_NAMESPACE = "fim";
const DAY_MS = 86_400_000;

/** El sistema de ficheros real. El agente lee como LocalSystem / root: sin PrivSvc ni scripts. */
export const realFs: FsLike = {
  lstat: (p) => fsp.lstat(p),
  readdir: (p) => fsp.readdir(p),
  sha256: (p) =>
    new Promise((resolve, reject) => {
      const h = crypto.createHash("sha256");
      createReadStream(p)
        .on("error", reject)
        .on("data", (chunk) => h.update(chunk))
        .on("end", () => resolve(h.digest("hex")));
    }),
};

export type WireFile = { setId: string; path: string; sha256: string | null; hashed: boolean; sizeBytes: number; modifiedAtUtc: string };

const wire = (f: ScannedFile): WireFile => ({
  setId: f.setId, path: f.path, sha256: f.sha256, hashed: f.hashed, sizeBytes: f.sizeBytes, modifiedAtUtc: f.modifiedAtUtc,
});

/** Qué cambió entre la línea base y la lectura de ahora. Puro. */
export function computeFileIntegrityDelta(current: ScannedFile[], previous: ScannedFile[]) {
  const before = new Map(previous.map((f) => [keyOf(f.setId, f.path), f]));
  const now = new Map(current.map((f) => [keyOf(f.setId, f.path), f]));
  const added: WireFile[] = [];
  const changed: WireFile[] = [];
  const removed: WireFile[] = [];
  for (const [k, f] of now) {
    const p = before.get(k);
    if (!p) added.push(wire(f));
    // Un fichero sin hash (demasiado grande) sólo puede compararse por tamaño.
    else if (f.hashed && p.hashed ? f.sha256 !== p.sha256 : f.sizeBytes !== p.sizeBytes || f.hashed !== p.hashed) changed.push(wire(f));
  }
  for (const [k, p] of before) if (!now.has(k)) removed.push(wire(p));
  return { added, removed, changed, hasChanges: added.length + removed.length + changed.length > 0 };
}

/** Huella de la declaración: si cambia, se manda foto nueva en vez de delta. */
export function setsFingerprint(policy: FileIntegrityPolicy | null, platform: NodeJS.Platform): string {
  const sets = (policy?.enabled ? policy.sets : [])
    .map((s) => ({ id: s.id, platform: s.platform, path: s.path, recursive: s.recursive, maxDepth: s.maxDepth }))
    .sort((a, b) => a.id.localeCompare(b.id));
  return crypto.createHash("sha256").update(JSON.stringify({ platform, sets, max: policy?.maxFilesPerDevice, bytes: policy?.maxFileBytes })).digest("hex");
}

export type FimDeps = {
  platform: NodeJS.Platform;
  policy: FileIntegrityPolicy | null;
  fs: FsLike;
  now: number;
  getState: (key: string) => string | null | undefined;
  setState: (key: string, value: string) => void;
  enqueue: (payload: unknown) => unknown;
  loadBaseline: () => ScannedFile[];
  replaceBaseline: (files: ScannedFile[]) => void;
  schemaVersion: string;
};

export type FimPassResult = { sent: boolean; kind: "photo" | "delta" | "heartbeat" | "none"; scope: string; files: number };

export async function runFileIntegrityPass(d: FimDeps): Promise<FimPassResult> {
  const previous = d.loadBaseline();
  const lastFull = Number(d.getState("fim:lastFullRehashAt") || 0);
  const fullRehash = !lastFull || d.now - lastFull >= DAY_MS;
  const previousMap = new Map(previous.map((f) => [keyOf(f.setId, f.path), { sha256: f.sha256, sizeBytes: f.sizeBytes, mtimeMs: f.mtimeMs }]));

  const scan = await scanFileIntegrity({ policy: d.policy, platform: d.platform, fs: d.fs, previous: previousMap, fullRehash });

  const lastSent = Number(d.getState("fim:lastSentAt") || 0);
  const heartbeatDue = !lastSent || d.now - lastSent >= DAY_MS;
  const scopeChanged = d.getState("fim:lastScope") !== scan.scope;
  const fingerprint = setsFingerprint(d.policy, d.platform);
  const setsChanged = d.getState("fim:setsFingerprint") !== fingerprint;

  const counts = { files: scan.files.length, unreadable: scan.unreadable };
  const base = {
    scope: scan.scope,
    sets: scan.sets,
    setIds: scan.setIds,
    counts,
    truncated: scan.truncated,
    ...(scan.error ? { error: scan.error } : {}),
  };

  let payload: Record<string, unknown> | null = null;
  let kind: FimPassResult["kind"] = "none";

  if (scan.scope !== "collected") {
    // No se miró: se dice por qué (si cambió o toca latido) y la base no se toca.
    if (scopeChanged || heartbeatDue) {
      payload = { ...base, hasChanges: false };
      kind = "heartbeat";
    }
  } else if (setsChanged || previous.length === 0) {
    // La declaración cambió (o es la primera vez): foto completa, también vacía,
    // para que el control plane registre que se miró.
    payload = { ...base, files: scan.files.map(wire), hasChanges: true };
    kind = "photo";
  } else {
    const delta = computeFileIntegrityDelta(scan.files, previous);
    if (delta.hasChanges) {
      payload = { ...base, delta: { added: delta.added, removed: delta.removed, changed: delta.changed }, hasChanges: true };
      kind = "delta";
    } else if (heartbeatDue || scopeChanged) {
      payload = { ...base, hasChanges: false };
      kind = "heartbeat";
    }
  }

  if (payload) {
    d.enqueue({ schemaVersion: d.schemaVersion, namespaces: { [FIM_FACTS_NAMESPACE]: payload } });
    d.setState("fim:lastSentAt", String(d.now));
    d.setState("fim:lastScope", scan.scope);
  }
  if (scan.scope === "collected") {
    // Tras encolar: el outbox garantiza la entrega, así que la base ya puede
    // reflejar lo que se mandó (o, sin cambios, las fechas nuevas de ficheros
    // tocados pero idénticos, para no rehashearlos en cada ciclo).
    d.replaceBaseline(scan.files);
    d.setState("fim:setsFingerprint", fingerprint);
    if (fullRehash) d.setState("fim:lastFullRehashAt", String(d.now));
  }
  return { sent: Boolean(payload), kind, scope: scan.scope, files: scan.files.length };
}
