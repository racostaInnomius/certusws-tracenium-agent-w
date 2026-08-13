import { describe, it, expect } from "vitest";
import {
  parseSnapshotTree,
  parseCurrentSnapshot,
  parseVmSummaries,
  parsePropertyValue,
  parsePrivilegeResults,
  parsePrivilegeList,
  parseFault,
  morefOfType,
  firstTag,
  decodeXml,
  escapeXml,
} from "../../src/connectors/vcenter/vim-parse";

/**
 * Verbatim response captured from the lab vCenter (8.0.3 build-24322831)
 * during the Inc 0 spike, for vm-9637 / MSIG-VEEAM-SRV while a snapshot was
 * live. This is the exact payload that a naive `<name>` scan mis-parsed as
 * "snapshot.rootSnapshotList", producing a FALSE "no snapshots" result.
 */
const REAL_SNAPSHOT_XML = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<soapenv:Body>
<RetrievePropertiesResponse xmlns="urn:vim25">
<returnval>
<obj type="VirtualMachine">vm-9637</obj>
<propSet>
<name>name</name>
<val xsi:type="xsd:string">MSIG-VEEAM-SRV</val>
</propSet>
<propSet>
<name>snapshot</name>
<val xsi:type="VirtualMachineSnapshotInfo">
<currentSnapshot type="VirtualMachineSnapshot">snapshot-13889</currentSnapshot>
<rootSnapshotList>
<snapshot type="VirtualMachineSnapshot">snapshot-13889</snapshot>
<vm type="VirtualMachine">vm-9637</vm>
<name>tracenium-prepatch-spike-lqol1w</name>
<description>ADR-0001 Inc0 spike — safe to delete</description>
<id>1</id>
<createTime>2026-08-12T14:24:35.901637Z</createTime>
<state>poweredOff</state>
<quiesced>true</quiesced>
<backupManifest>[datastore3] MSIG-VEEAM-SRV/MSIG-VEEAM-SRV-vss_manifests1.zip</backupManifest>
<replaySupported>false</replaySupported>
</rootSnapshotList>
</val>
</propSet>
</returnval>
</RetrievePropertiesResponse>
</soapenv:Body>
</soapenv:Envelope>`;

describe("parseSnapshotTree — regression against the Inc 0 false negative", () => {
  it("finds the live snapshot in the real captured payload", () => {
    const snaps = parseSnapshotTree(REAL_SNAPSHOT_XML);
    expect(snaps).toHaveLength(1);
    expect(snaps[0].moref).toBe("snapshot-13889");
    // The whole point: the NAME must be the snapshot's, never the PropertySpec's.
    expect(snaps[0].name).toBe("tracenium-prepatch-spike-lqol1w");
    expect(snaps[0].name).not.toBe("snapshot");
  });

  it("never reports the PropertySpec name as a snapshot name", () => {
    for (const s of parseSnapshotTree(REAL_SNAPSHOT_XML)) {
      expect(["snapshot", "snapshot.rootSnapshotList", "name"]).not.toContain(s.name);
    }
  });

  it("captures description, createTime, state and quiesce flag", () => {
    const [s] = parseSnapshotTree(REAL_SNAPSHOT_XML);
    expect(s.description).toBe("ADR-0001 Inc0 spike — safe to delete");
    expect(s.createTime).toBe("2026-08-12T14:24:35.901637Z");
    expect(s.state).toBe("poweredOff");
    expect(s.quiesced).toBe(true);
  });

  it("returns [] when the VM genuinely has no snapshots", () => {
    const empty = `<returnval><obj type="VirtualMachine">vm-1</obj>
      <propSet><name>name</name><val>NOSNAP</val></propSet></returnval>`;
    expect(parseSnapshotTree(empty)).toEqual([]);
  });

  it("parses several snapshots including nested children", () => {
    const multi = `<val>
      <rootSnapshotList>
        <snapshot type="VirtualMachineSnapshot">snapshot-1</snapshot>
        <vm type="VirtualMachine">vm-9</vm>
        <name>first</name><description>d1</description><id>1</id>
        <createTime>2026-01-01T00:00:00Z</createTime><state>poweredOn</state><quiesced>false</quiesced>
        <childSnapshotList>
          <snapshot type="VirtualMachineSnapshot">snapshot-2</snapshot>
          <vm type="VirtualMachine">vm-9</vm>
          <name>second</name><description>d2</description><id>2</id>
          <createTime>2026-01-02T00:00:00Z</createTime><state>poweredOff</state><quiesced>true</quiesced>
        </childSnapshotList>
      </rootSnapshotList></val>`;
    const snaps = parseSnapshotTree(multi);
    expect(snaps.map((s) => s.moref)).toEqual(["snapshot-1", "snapshot-2"]);
    expect(snaps.map((s) => s.name)).toEqual(["first", "second"]);
    expect(snaps[1].quiesced).toBe(true);
  });

  it("does not mistake currentSnapshot for a tree entry", () => {
    const onlyCurrent = `<val><currentSnapshot type="VirtualMachineSnapshot">snapshot-99</currentSnapshot></val>`;
    expect(parseSnapshotTree(onlyCurrent)).toEqual([]);
  });
});

describe("parseCurrentSnapshot", () => {
  it("extracts the current snapshot moref", () => {
    expect(parseCurrentSnapshot(REAL_SNAPSHOT_XML)).toBe("snapshot-13889");
  });

  it("returns null when absent", () => {
    expect(parseCurrentSnapshot("<val></val>")).toBeNull();
  });
});

describe("parseVmSummaries", () => {
  it("reads VM rows with uuid and instanceUuid", () => {
    const xml = `<RetrievePropertiesResponse>
      <returnval><obj type="VirtualMachine">vm-9637</obj>
        <propSet><name>name</name><val>MSIG-VEEAM-SRV</val></propSet>
        <propSet><name>config.uuid</name><val>42394FDD-93F3-501A-8614-C6FA55F75468</val></propSet>
        <propSet><name>config.instanceUuid</name><val>5039E9DA-E891-D295-9E1F-02230A259668</val></propSet>
      </returnval>
      <returnval><obj type="VirtualMachine">vm-3081</obj>
        <propSet><name>name</name><val>SRV-W2K22</val></propSet>
        <propSet><name>config.uuid</name><val>4227feb2-8d4e-c321-fe3d-f60c4c6a65b6</val></propSet>
      </returnval>
    </RetrievePropertiesResponse>`;
    const vms = parseVmSummaries(xml);
    expect(vms).toHaveLength(2);
    expect(vms[0].uuid).toBe("42394fdd-93f3-501a-8614-c6fa55f75468"); // lowercased
    expect(vms[0].name).toBe("MSIG-VEEAM-SRV");
    expect(vms[1].moref).toBe("vm-3081");
  });

  it("ignores returnvals that are not VMs", () => {
    expect(parseVmSummaries(`<returnval><obj type="HostSystem">host-1</obj></returnval>`)).toEqual([]);
  });
});

describe("parsePropertyValue", () => {
  it("reads a scalar property by name", () => {
    const xml = `<returnval><obj type="Task">task-5</obj>
      <propSet><name>info.state</name><val xsi:type="TaskInfoState">success</val></propSet></returnval>`;
    expect(parsePropertyValue(xml, "info.state")).toBe("success");
  });

  it("returns null for an absent property instead of guessing", () => {
    expect(parsePropertyValue("<returnval></returnval>", "info.state")).toBeNull();
  });
});

describe("privilege parsing", () => {
  it("maps HasPrivilegeOnEntity booleans in request order", () => {
    const xml = `<HasPrivilegeOnEntityResponse>
      <returnval>true</returnval><returnval>false</returnval><returnval>true</returnval>
    </HasPrivilegeOnEntityResponse>`;
    expect(parsePrivilegeResults(xml)).toEqual([true, false, true]);
  });

  it("reads the server's advertised privilege list", () => {
    const xml = `<propSet><name>privilegeList</name><val>
      <privId>VirtualMachine.State.CreateSnapshot</privId>
      <privId>VirtualMachine.State.RemoveSnapshot</privId>
    </val></propSet>`;
    expect(parsePrivilegeList(xml)).toEqual([
      "VirtualMachine.State.CreateSnapshot",
      "VirtualMachine.State.RemoveSnapshot",
    ]);
  });
});

describe("parseFault", () => {
  it("prefers localizedMessage", () => {
    const xml = `<soapenv:Fault><faultstring>generic</faultstring>
      <detail><NoPermissionFault><localizedMessage>Permission to perform this operation was denied.</localizedMessage></NoPermissionFault></detail>
    </soapenv:Fault>`;
    expect(parseFault(xml)).toBe("Permission to perform this operation was denied.");
  });

  it("falls back to faultstring", () => {
    expect(parseFault(`<soapenv:Fault><faultstring>Cannot complete login due to an incorrect user name or password.</faultstring></soapenv:Fault>`))
      .toContain("incorrect user name or password");
  });

  it("returns null when the response is not a fault", () => {
    expect(parseFault("<returnval>ok</returnval>")).toBeNull();
  });
});

describe("moref / tag helpers", () => {
  it("extracts a typed moref", () => {
    expect(morefOfType(`<returnval type="Task">task-42</returnval>`, "Task")).toBe("task-42");
  });

  it("does not match a different managed object type", () => {
    expect(morefOfType(`<returnval type="Folder">group-d1</returnval>`, "Task")).toBeNull();
  });

  it("reads namespaced simple tags", () => {
    expect(firstTag("<urn:apiVersion>8.0.3.0</urn:apiVersion>", "apiVersion")).toBe("8.0.3.0");
  });
});

describe("xml entity round-trip", () => {
  it("escapes and decodes symmetrically", () => {
    const raw = `p@ss&<>"'word`;
    expect(decodeXml(escapeXml(raw))).toBe(raw);
  });

  it("escapes ampersands without double-encoding on decode", () => {
    expect(escapeXml("a&b")).toBe("a&amp;b");
    expect(decodeXml("a&amp;b")).toBe("a&b");
  });
});

import { parseVmDatastoreRefs, parseDatastoreSummaries } from "../../src/connectors/vcenter/vim-parse";

/** Verbatim response captured from the lab for vm-9637 (MSIG-VEEAM-SRV). */
const REAL_VM_DATASTORE_XML = `<returnval>
<obj type="VirtualMachine">vm-9637</obj>
<propSet>
<name>datastore</name>
<val xsi:type="ArrayOfManagedObjectReference">
<ManagedObjectReference type="Datastore" xsi:type="ManagedObjectReference">datastore-9389</ManagedObjectReference>
</val>
</propSet>
</returnval>`;

describe("parseVmDatastoreRefs — against the real captured shape", () => {
  it("extracts the datastore moref", () => {
    expect(parseVmDatastoreRefs(REAL_VM_DATASTORE_XML)).toEqual(["datastore-9389"]);
  });

  it("extracts several datastores for a multi-disk VM", () => {
    const multi = REAL_VM_DATASTORE_XML.replace(
      "</val>",
      `<ManagedObjectReference type="Datastore" xsi:type="ManagedObjectReference">datastore-42</ManagedObjectReference></val>`
    );
    expect(parseVmDatastoreRefs(multi)).toEqual(["datastore-9389", "datastore-42"]);
  });

  it("ignores managed object references of other types", () => {
    const withNetwork = REAL_VM_DATASTORE_XML.replace(
      "</val>",
      `<ManagedObjectReference type="Network" xsi:type="ManagedObjectReference">network-1</ManagedObjectReference></val>`
    );
    expect(parseVmDatastoreRefs(withNetwork)).toEqual(["datastore-9389"]);
  });

  it("returns [] when the VM reports none", () => {
    expect(parseVmDatastoreRefs("<returnval></returnval>")).toEqual([]);
  });
});

describe("parseDatastoreSummaries", () => {
  it("reads capacity figures, using the real lab numbers", () => {
    const xml = `<returnval><obj type="Datastore">datastore-9389</obj>
      <propSet><name>name</name><val>datastore3</val></propSet>
      <propSet><name>summary.capacity</name><val xsi:type="xsd:long">24003196printf</val></propSet>
      <propSet><name>summary.freeSpace</name><val xsi:type="xsd:long">4497273584844</val></propSet>
      <propSet><name>summary.uncommitted</name><val xsi:type="xsd:long">0</val></propSet>
      </returnval>`;
    const rows = parseDatastoreSummaries(xml.replace("24003196printf", "24003196289024"));
    expect(rows).toHaveLength(1);
    expect(rows[0].name).toBe("datastore3");
    expect(rows[0].capacity).toBe(24003196289024);
    expect(rows[0].freeSpace).toBe(4497273584844);
    expect(rows[0].uncommitted).toBe(0);
  });

  it("leaves capacity NaN when vCenter omits it, rather than defaulting to 0", () => {
    // 0 would read as "completely full" and block patching on a healthy store.
    const rows = parseDatastoreSummaries(
      `<returnval><obj type="Datastore">ds-1</obj><propSet><name>name</name><val>x</val></propSet></returnval>`
    );
    expect(Number.isNaN(rows[0].capacity)).toBe(true);
  });

  it("ignores returnvals that are not datastores", () => {
    expect(parseDatastoreSummaries(`<returnval><obj type="VirtualMachine">vm-1</obj></returnval>`)).toEqual([]);
  });
});
