import { describe, it, expect } from "vitest";
import {
  normalizeUuid,
  byteSwapUuid,
  uuidFromSmbiosSerial,
  buildMatchCandidates,
} from "../../src/connectors/vcenter/uuid-match";

// Real values captured from the lab during Inc 0 (ADR-0001). MSIG-VEEAM-SRV /
// vm-9637 — Windows Server 2022 guest on vCenter 8.0.3.
const AGENT_UUID = "dd4f3942-f393-1a50-8614-c6fa55f75468";
const VCENTER_UUID = "42394fdd-93f3-501a-8614-c6fa55f75468";
const AGENT_SERIAL = "VMware-42 39 4f dd 93 f3 50 1a-86 14 c6 fa 55 f7 54 68";

describe("normalizeUuid", () => {
  it("lowercases and keeps canonical dashed form", () => {
    expect(normalizeUuid("DD4F3942-F393-1A50-8614-C6FA55F75468")).toBe(AGENT_UUID);
  });

  it("accepts undashed hex and re-inserts dashes", () => {
    expect(normalizeUuid("dd4f3942f3931a508614c6fa55f75468")).toBe(AGENT_UUID);
  });

  it("strips wrapping braces", () => {
    expect(normalizeUuid(`{${AGENT_UUID}}`)).toBe(AGENT_UUID);
  });

  it("rejects non-UUID input rather than guessing", () => {
    expect(normalizeUuid("not-a-uuid")).toBeNull();
    expect(normalizeUuid("")).toBeNull();
    expect(normalizeUuid(undefined)).toBeNull();
    expect(normalizeUuid(12345)).toBeNull();
    // 31 hex chars — one short
    expect(normalizeUuid("dd4f3942f3931a508614c6fa55f7546")).toBeNull();
  });
});

describe("byteSwapUuid", () => {
  it("maps the real agent uuid onto the real vCenter config.uuid", () => {
    expect(byteSwapUuid(AGENT_UUID)).toBe(VCENTER_UUID);
  });

  it("is involutive", () => {
    expect(byteSwapUuid(byteSwapUuid(AGENT_UUID)!)).toBe(AGENT_UUID);
  });

  it("swaps only the first three fields", () => {
    expect(byteSwapUuid("00112233-4455-6677-8899-aabbccddeeff")).toBe(
      "33221100-5544-7766-8899-aabbccddeeff"
    );
  });

  it("returns null for garbage", () => {
    expect(byteSwapUuid("nope")).toBeNull();
  });
});

describe("uuidFromSmbiosSerial", () => {
  it("derives the vCenter config.uuid directly from the SMBIOS serial", () => {
    // The serial carries raw byte order, so NO swap is needed here.
    expect(uuidFromSmbiosSerial(AGENT_SERIAL)).toBe(VCENTER_UUID);
  });

  it("ignores case and the VMware- prefix", () => {
    expect(uuidFromSmbiosSerial("vmware-4239 4fdd 93f3 501a 8614 c6fa 55f7 5468")).toBe(
      VCENTER_UUID
    );
  });

  it("returns null for non-VMware or malformed serials", () => {
    expect(uuidFromSmbiosSerial("None")).toBeNull();
    expect(uuidFromSmbiosSerial("System Serial Number")).toBeNull();
    expect(uuidFromSmbiosSerial(undefined)).toBeNull();
  });
});

describe("buildMatchCandidates", () => {
  it("emits raw, swapped and serial-derived candidates in priority order", () => {
    const c = buildMatchCandidates({ uuid: AGENT_UUID, serial: AGENT_SERIAL, virtual: true });
    expect(c).toEqual([
      { uuid: AGENT_UUID, source: "uuid_raw" },
      { uuid: VCENTER_UUID, source: "uuid_swapped" },
    ]);
    // serial-derived value equals the swapped one, so it is de-duplicated —
    // which is itself the cross-check that both keys agree.
  });

  it("keeps the serial candidate when it disagrees with the swap", () => {
    const other = "11111111-2222-3333-4444-555555555555";
    const c = buildMatchCandidates({
      uuid: AGENT_UUID,
      serial: `VMware-${other.replace(/-/g, "").match(/../g)!.join(" ")}`,
      virtual: true,
    });
    expect(c.map((x) => x.source)).toEqual(["uuid_raw", "uuid_swapped", "serial_smbios"]);
    expect(c[2].uuid).toBe(other);
  });

  it("returns nothing for a physical machine — never correlate a non-VM", () => {
    expect(buildMatchCandidates({ uuid: AGENT_UUID, serial: AGENT_SERIAL, virtual: false })).toEqual([]);
    expect(buildMatchCandidates({ uuid: AGENT_UUID, virtual: undefined })).toEqual([]);
  });

  it("accepts the stringly-typed 'true' some providers report", () => {
    expect(buildMatchCandidates({ uuid: AGENT_UUID, virtual: "true" }).length).toBeGreaterThan(0);
  });

  it("returns nothing when the VM has no usable identifiers", () => {
    expect(buildMatchCandidates({ uuid: "None", serial: "None", virtual: true })).toEqual([]);
  });

  it("still works when only the serial is present", () => {
    const c = buildMatchCandidates({ serial: AGENT_SERIAL, virtual: true });
    expect(c).toEqual([{ uuid: VCENTER_UUID, source: "serial_smbios" }]);
  });
});
