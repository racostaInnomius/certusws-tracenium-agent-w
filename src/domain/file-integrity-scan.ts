// src/domain/file-integrity-scan.ts
//
// ADR-0027 F3 — recorrer los conjuntos declarados y hashear lo que hay.
//
// Con un sistema de ficheros inyectable, para que las reglas se prueben sin
// tocar el disco:
//
//   · Enlaces simbólicos NO se siguen: un enlace puede sacar el recorrido del
//     conjunto declarado o meterlo en un bucle.
//   · Se para en el tope de ficheros y se DICE (`truncated`).
//   · Un fichero mayor que el tope de hasheo se cuenta, con `hashed: false`.
//     Es un hecho, no un hueco.
//   · Un error de permisos cuenta como `unreadable`; una ruta declarada que no
//     existe en este equipo no es un error (un conjunto «any» puede apuntar a
//     algo que sólo tiene otro sistema).
//
// ⚠️ Rehasheo. Hashear miles de ficheros en cada ciclo es caro, así que un
// fichero con el MISMO tamaño y la MISMA fecha que en la lectura anterior
// reutiliza su hash. Cambiar un fichero conservando fecha y tamaño es posible
// para quien lo intenta, así que una vez al día se rehashea todo
// (`fullRehash`). Es la resolución que se declara, no un hueco escondido.

import path from "path";
import { appliesTo, type FileIntegrityPolicy } from "./file-integrity-policy";

export type FsStat = { isFile(): boolean; isDirectory(): boolean; isSymbolicLink(): boolean; size: number; mtimeMs: number };

export type FsLike = {
  lstat(p: string): Promise<FsStat>;
  readdir(p: string): Promise<string[]>;
  sha256(p: string): Promise<string>;
};

export type ScannedFile = {
  setId: string;
  path: string;
  sha256: string | null;
  hashed: boolean;
  sizeBytes: number;
  modifiedAtUtc: string;
  mtimeMs: number;
};

export type FileIntegrityScope = "collected" | "not_configured" | "unsupported" | "unavailable";

export type FileIntegrityScan = {
  scope: FileIntegrityScope;
  sets: number;
  /**
   * Los conjuntos que se recorrieron. El control plane lo necesita para no
   * confundir «conjunto retirado de la política» (sin avisos) con «conjunto
   * vigilado que se quedó vacío» (que SÍ avisa: alguien pudo borrarlo todo).
   */
  setIds: string[];
  files: ScannedFile[];
  unreadable: number;
  truncated: boolean;
  error: string | null;
};

export type PreviousEntry = { sha256: string | null; sizeBytes: number; mtimeMs: number };

export const keyOf = (setId: string, p: string) => `${setId}|${p}`;

const SUPPORTED = new Set<NodeJS.Platform>(["win32", "darwin", "linux"]);

function isPermissionError(err: any): boolean {
  return err?.code === "EACCES" || err?.code === "EPERM" || err?.code === "EBUSY";
}

export async function scanFileIntegrity(opts: {
  policy: FileIntegrityPolicy | null;
  platform: NodeJS.Platform;
  fs: FsLike;
  previous: Map<string, PreviousEntry>;
  fullRehash: boolean;
}): Promise<FileIntegrityScan> {
  const { policy, platform, fs, previous, fullRehash } = opts;
  const empty = (scope: FileIntegrityScope, sets = 0, error: string | null = null): FileIntegrityScan => ({
    scope, sets, setIds: [], files: [], unreadable: 0, truncated: false, error,
  });

  if (!SUPPORTED.has(platform)) return empty("unsupported");
  if (!policy || !policy.enabled) return empty("not_configured");
  const sets = policy.sets.filter((s) => appliesTo(s, platform));
  if (sets.length === 0) return empty("not_configured");

  const join = platform === "win32" ? path.win32.join : path.posix.join;
  const files: ScannedFile[] = [];
  let unreadable = 0;
  let truncated = false;

  const record = async (setId: string, p: string, st: FsStat) => {
    const prev = previous.get(keyOf(setId, p));
    let sha: string | null = null;
    let hashed = false;
    if (st.size <= policy.maxFileBytes) {
      const reuse = !fullRehash && prev && prev.sha256 && prev.sizeBytes === st.size && prev.mtimeMs === st.mtimeMs;
      if (reuse) {
        sha = prev!.sha256;
        hashed = true;
      } else {
        try {
          sha = await fs.sha256(p);
          hashed = true;
        } catch (err: any) {
          if (!isPermissionError(err) && err?.code !== "ENOENT") throw err;
          // Se pudo listar pero no leer: existe y no sabemos qué hay dentro.
          unreadable += 1;
          return;
        }
      }
    }
    files.push({ setId, path: p, sha256: sha, hashed, sizeBytes: st.size, modifiedAtUtc: new Date(st.mtimeMs).toISOString(), mtimeMs: st.mtimeMs });
  };

  const walk = async (setId: string, dir: string, depth: number, recursive: boolean, maxDepth: number): Promise<void> => {
    let names: string[];
    try {
      names = await fs.readdir(dir);
    } catch (err: any) {
      if (isPermissionError(err)) { unreadable += 1; return; }
      if (err?.code === "ENOENT" || err?.code === "ENOTDIR") return;
      throw err;
    }
    for (const name of [...names].sort()) {
      if (files.length >= policy.maxFilesPerDevice) { truncated = true; return; }
      const p = join(dir, name);
      let st: FsStat;
      try {
        st = await fs.lstat(p);
      } catch (err: any) {
        if (isPermissionError(err)) { unreadable += 1; continue; }
        if (err?.code === "ENOENT") continue; // se borró entre el listado y el stat
        throw err;
      }
      if (st.isSymbolicLink()) continue;
      if (st.isFile()) await record(setId, p, st);
      else if (st.isDirectory() && recursive && depth < maxDepth) await walk(setId, p, depth + 1, recursive, maxDepth);
    }
  };

  try {
    for (const set of sets) {
      if (files.length >= policy.maxFilesPerDevice) { truncated = true; break; }
      let st: FsStat;
      try {
        st = await fs.lstat(set.path);
      } catch (err: any) {
        if (isPermissionError(err)) { unreadable += 1; continue; }
        if (err?.code === "ENOENT" || err?.code === "ENOTDIR") continue; // no existe en ESTE equipo
        throw err;
      }
      if (st.isSymbolicLink()) continue;
      if (st.isFile()) await record(set.id, set.path, st);
      else if (st.isDirectory()) await walk(set.id, set.path, 1, set.recursive, set.maxDepth);
    }
  } catch (err: any) {
    return { ...empty("unavailable", sets.length, String(err?.message || err).slice(0, 300)) };
  }

  return { scope: "collected", sets: sets.length, setIds: sets.map((s) => s.id), files, unreadable, truncated, error: null };
}
