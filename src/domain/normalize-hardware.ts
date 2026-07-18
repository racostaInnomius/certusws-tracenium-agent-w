// src/domain/normalize-hardware.ts
//
// Normalizes the raw `systeminformation` hardware objects into stable, slim
// shapes before they ship in the AMP hardware namespace.
//
// Why:
//   * buildHardwareNamespace used to embed si.cpu / si.graphics / si.memLayout
//     / si.diskLayout VERBATIM. Those objects carry a lot of noise (cache
//     descriptors, CPU flags, disk geometry, per-controller display data,
//     DIMM voltages, SMART temps) that no consumer reads, bloating every
//     hardware_payload row.
//   * The verbose blobs also make the dedup content-hash (md5 of
//     hardware_payload->'static') fragile: a cosmetic si change (field
//     reordering, a new noise field across si versions) flips the hash and
//     forces a spurious new inventory row even though nothing meaningful
//     changed.
//
// Contract preserved: the CPU fields any consumer actually reads —
// brand / manufacturer / vendor / model / physicalCores (backend
// dashboard + jobs.controller + cpu_model derivation) — are kept under the
// same names. graphics / memLayout / diskLayout (static) are not read by any
// serving path, so they are slimmed to their identifying fields only. The
// hardware RUNTIME disk list is built from the raw si.diskLayout separately
// and is unaffected by this normalization.

function s(v: any): string | undefined {
  if (v === null || v === undefined) return undefined;
  const t = String(v).trim();
  return t ? t : undefined;
}

function n(v: any): number | undefined {
  const num = Number(v);
  return Number.isFinite(num) ? num : undefined;
}

export interface NormalizedCpu {
  manufacturer?: string;
  brand?: string;
  vendor?: string;
  model?: string;
  cores?: number;
  physicalCores?: number;
  speed?: number;
}

export function normalizeCpu(cpu: any): NormalizedCpu | undefined {
  if (!cpu || typeof cpu !== "object") return undefined;
  return {
    manufacturer: s(cpu.manufacturer),
    brand: s(cpu.brand),
    vendor: s(cpu.vendor),
    model: s(cpu.model),
    cores: n(cpu.cores),
    physicalCores: n(cpu.physicalCores),
    speed: n(cpu.speed),
  };
}

export interface NormalizedGpu {
  vendor?: string;
  model?: string;
  vramMb?: number;
}

export function normalizeGraphics(graphics: any): { controllers: NormalizedGpu[] } | undefined {
  const controllers = Array.isArray(graphics?.controllers) ? graphics.controllers : null;
  if (!controllers) return undefined;
  return {
    controllers: controllers.map((c: any) => ({
      vendor: s(c?.vendor),
      model: s(c?.model),
      vramMb: n(c?.vram),
    })),
  };
}

export interface NormalizedMemStick {
  sizeBytes?: number;
  type?: string;
  clockSpeed?: number;
  manufacturer?: string;
}

export function normalizeMemLayout(memLayout: any): NormalizedMemStick[] | undefined {
  if (!Array.isArray(memLayout)) return undefined;
  return memLayout.map((m: any) => ({
    sizeBytes: n(m?.size),
    type: s(m?.type),
    clockSpeed: n(m?.clockSpeed),
    manufacturer: s(m?.manufacturer),
  }));
}

export interface NormalizedDisk {
  name?: string;
  type?: string;
  vendor?: string;
  sizeBytes?: number;
  interfaceType?: string;
}

export function normalizeDiskLayout(diskLayout: any): NormalizedDisk[] | undefined {
  if (!Array.isArray(diskLayout)) return undefined;
  return diskLayout.map((d: any) => ({
    name: s(d?.name),
    type: s(d?.type),
    vendor: s(d?.vendor),
    sizeBytes: n(d?.size),
    interfaceType: s(d?.interfaceType),
  }));
}
