// test/domain/normalize-hardware.test.ts
//
// The normalizers slim the raw systeminformation hardware objects to stable
// shapes. Two things matter and are asserted here:
//   1. The CPU fields consumers read (brand/manufacturer/vendor/model/
//      physicalCores) survive normalization under the same names.
//   2. si noise (cache/flags/geometry/SMART/displays/voltages) is dropped, so
//      the dedup content-hash only keys on meaningful hardware.

import { describe, it, expect } from "vitest";
import {
  normalizeCpu,
  normalizeGraphics,
  normalizeMemLayout,
  normalizeDiskLayout,
} from "../../src/domain/normalize-hardware";

describe("normalizeCpu", () => {
  it("keeps the consumer-read fields and drops si noise", () => {
    const raw = {
      manufacturer: "Intel",
      brand: "Core i7-1185G7",
      vendor: "GenuineIntel",
      model: "140",
      cores: 8,
      physicalCores: 4,
      speed: 3.0,
      // noise that must NOT survive:
      family: "6",
      stepping: "1",
      revision: "",
      flags: "fpu vme de pse tsc msr",
      cache: { l1d: 49152, l2: 5242880, l3: 12582912 },
      virtualization: true,
      governor: "performance",
    };
    const out = normalizeCpu(raw)!;
    expect(out).toEqual({
      manufacturer: "Intel",
      brand: "Core i7-1185G7",
      vendor: "GenuineIntel",
      model: "140",
      cores: 8,
      physicalCores: 4,
      speed: 3.0,
    });
    expect("flags" in out).toBe(false);
    expect("cache" in out).toBe(false);
    expect("virtualization" in out).toBe(false);
  });

  it("returns undefined for missing input", () => {
    expect(normalizeCpu(undefined)).toBeUndefined();
    expect(normalizeCpu(null)).toBeUndefined();
  });

  it("coerces empty strings / non-numbers to undefined", () => {
    const out = normalizeCpu({ brand: "  ", physicalCores: "n/a" })!;
    expect(out.brand).toBeUndefined();
    expect(out.physicalCores).toBeUndefined();
  });
});

describe("normalizeGraphics", () => {
  it("slims controllers to vendor/model/vram and drops displays", () => {
    const raw = {
      controllers: [
        { vendor: "NVIDIA", model: "RTX 4060", vram: 8192, bus: "PCI", vramDynamic: false, subDeviceId: "0x1" },
      ],
      displays: [{ model: "DELL", resolutionX: 3840 }],
    };
    const out = normalizeGraphics(raw)!;
    expect(out.controllers).toEqual([{ vendor: "NVIDIA", model: "RTX 4060", vramMb: 8192 }]);
    expect("displays" in out).toBe(false);
  });

  it("returns undefined when there are no controllers", () => {
    expect(normalizeGraphics({})).toBeUndefined();
    expect(normalizeGraphics(undefined)).toBeUndefined();
  });
});

describe("normalizeMemLayout", () => {
  it("maps size→sizeBytes and keeps type/clock/manufacturer", () => {
    const out = normalizeMemLayout([
      { size: 17179869184, type: "DDR4", clockSpeed: 3200, manufacturer: "Samsung", ecc: false, voltageConfigured: 1.2 },
    ])!;
    expect(out).toEqual([{ sizeBytes: 17179869184, type: "DDR4", clockSpeed: 3200, manufacturer: "Samsung" }]);
  });
  it("returns undefined for non-arrays", () => {
    expect(normalizeMemLayout(undefined)).toBeUndefined();
  });
});

describe("normalizeDiskLayout", () => {
  it("keeps identity fields and drops geometry/SMART", () => {
    const out = normalizeDiskLayout([
      { name: "Samsung SSD 980", type: "SSD", vendor: "Samsung", size: 512000000000, interfaceType: "NVMe", totalCylinders: 62260, smartStatus: "Ok", temperature: 41, serialNum: "S1" },
    ])!;
    expect(out).toEqual([{ name: "Samsung SSD 980", type: "SSD", vendor: "Samsung", sizeBytes: 512000000000, interfaceType: "NVMe" }]);
  });
  it("returns undefined for non-arrays", () => {
    expect(normalizeDiskLayout(null)).toBeUndefined();
  });
});
