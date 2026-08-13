import { describe, it, expect } from "vitest";
import { VimClient, VimFault } from "../../src/connectors/vcenter/vim-client";

/**
 * The client is mostly I/O, so we exercise it through a seam: replace the
 * private SOAP `call` with a scripted responder and assert on the REQUESTS it
 * builds and how it interprets replies. No sockets involved.
 */
function clientWith(responder: (inner: string) => string | Promise<string>) {
  const c = new VimClient({
    host: "10.130.130.3",
    port: 443,
    tlsThumbprintSha256: "62a20ae2d752fc78934a1134f3b4ecc31914899a6b9cd8ce72279808e15c337d",
  });
  const sent: string[] = [];
  (c as any).call = async (inner: string) => {
    sent.push(inner);
    return responder(inner);
  };
  // Pretend RetrieveServiceContent already ran.
  (c as any).content = {
    sessionManager: "SessionManager",
    authorizationManager: "AuthorizationManager",
    propertyCollector: "propertyCollector",
    viewManager: "ViewManager",
    rootFolder: "group-d1",
    searchIndex: "SearchIndex",
    apiType: "VirtualCenter",
    apiVersion: "8.0.3.0",
    productName: "VMware vCenter Server 8.0.3",
  };
  return { c, sent };
}

const taskState = (state: string) =>
  `<returnval><obj type="Task">task-1</obj><propSet><name>info.state</name><val>${state}</val></propSet></returnval>`;

describe("waitForTask", () => {
  it("returns once the task reports success", async () => {
    const { c } = clientWith(() => taskState("success"));
    await expect(c.waitForTask("task-1", { sleep: async () => {} })).resolves.toBeUndefined();
  });

  it("polls while the task is running", async () => {
    let n = 0;
    const { c } = clientWith(() => taskState(++n < 3 ? "running" : "success"));
    await c.waitForTask("task-1", { sleep: async () => {}, pollMs: 1 });
    expect(n).toBe(3);
  });

  it("NEVER asks for info.error alongside info.state", async () => {
    // Regression: requesting the nested optional property together with the
    // state makes vCenter fault when there is no error at all. That aborted the
    // Inc 0 run mid-flight and left an orphaned snapshot on the VM.
    const { c, sent } = clientWith(() => taskState("success"));
    await c.waitForTask("task-1", { sleep: async () => {} });
    for (const body of sent) {
      expect(body).toContain("info.state");
      expect(body).not.toContain("info.error");
    }
  });

  it("fetches the error detail only after the state says error", async () => {
    const seen: string[] = [];
    const { c } = clientWith((inner) => {
      seen.push(inner);
      if (inner.includes("info.error")) {
        return `<soapenv:Fault><faultstring>Insufficient disk space on datastore</faultstring></soapenv:Fault>`;
      }
      return taskState("error");
    });
    await expect(c.waitForTask("task-1", { sleep: async () => {} })).rejects.toThrow(VimFault);
    expect(seen.some((s) => s.includes("info.error"))).toBe(true);
    // state was queried before the error detail
    expect(seen[0]).toContain("info.state");
    expect(seen[0]).not.toContain("info.error");
  });

  it("still fails cleanly when the error detail cannot be read", async () => {
    const { c } = clientWith((inner) => {
      if (inner.includes("info.error")) throw new Error("boom");
      return taskState("error");
    });
    await expect(c.waitForTask("task-1", { sleep: async () => {} })).rejects.toThrow(/failed/);
  });

  it("times out instead of polling forever", async () => {
    let clock = 0;
    const { c } = clientWith(() => taskState("running"));
    await expect(
      c.waitForTask("task-1", {
        sleep: async () => { clock += 1500; },
        now: () => clock,
        timeoutMs: 5000,
      })
    ).rejects.toThrow(/timed out/);
  });
});

describe("request construction", () => {
  it("builds a snapshot request with the configured memory/quiesce flags", async () => {
    const { c, sent } = clientWith(() => `<returnval type="Task">task-9</returnval>`);
    const task = await c.createSnapshot("vm-9637", "pre-patch", "desc", false, true);
    expect(task).toBe("task-9");
    expect(sent[0]).toContain("<urn:_this type=\"VirtualMachine\">vm-9637</urn:_this>");
    expect(sent[0]).toContain("<urn:memory>false</urn:memory>");
    expect(sent[0]).toContain("<urn:quiesce>true</urn:quiesce>");
  });

  it("escapes values that would otherwise break the XML body", async () => {
    const { c, sent } = clientWith(() => `<returnval type="Task">task-9</returnval>`);
    await c.createSnapshot("vm-1", `a<b>&"c"`, "d'e", false, false);
    expect(sent[0]).toContain("a&lt;b&gt;&amp;&quot;c&quot;");
    expect(sent[0]).not.toContain(`a<b>`);
  });

  it("throws when vCenter returns no task reference", async () => {
    const { c } = clientWith(() => `<returnval></returnval>`);
    await expect(c.createSnapshot("vm-1", "n", "d", false, true)).rejects.toThrow(/no task reference/);
  });

  it("finds a VM by bios uuid and by instance uuid distinctly", async () => {
    const { c, sent } = clientWith(() => `<returnval type="VirtualMachine">vm-9637</returnval>`);
    await c.findVmByUuid("42394fdd-93f3-501a-8614-c6fa55f75468");
    expect(sent[0]).toContain("<urn:instanceUuid>false</urn:instanceUuid>");
    await c.findVmByUuid("5039e9da-e891-d295-9e1f-02230a259668", true);
    expect(sent[1]).toContain("<urn:instanceUuid>true</urn:instanceUuid>");
  });

  it("returns null when no VM matches", async () => {
    const { c } = clientWith(() => `<returnval></returnval>`);
    expect(await c.findVmByUuid("00000000-0000-0000-0000-000000000000")).toBeNull();
  });
});

describe("privilege probing", () => {
  it("sends one privId per requested privilege and maps the answers in order", async () => {
    const { c, sent } = clientWith(
      () => `<returnval>true</returnval><returnval>false</returnval>`
    );
    const res = await c.hasPrivilegeOnEntity("sess-1", ["A.B", "C.D"], { moref: "group-d1", type: "Folder" });
    expect(res).toEqual([true, false]);
    expect(sent[0]).toContain("<urn:privId>A.B</urn:privId>");
    expect(sent[0]).toContain("<urn:privId>C.D</urn:privId>");
    expect(sent[0]).toContain(`<urn:entity type="Folder">group-d1</urn:entity>`);
  });

  it("short-circuits without a request when nothing is asked", async () => {
    const { c, sent } = clientWith(() => { throw new Error("should not be called"); });
    expect(await c.hasPrivilegeOnEntity("s", [], { moref: "group-d1", type: "Folder" })).toEqual([]);
    expect(sent).toHaveLength(0);
  });
});

describe("snapshot listing", () => {
  it("reads the tree via the shared parser", async () => {
    const { c } = clientWith(
      () => `<returnval><obj type="VirtualMachine">vm-9637</obj><propSet><name>snapshot</name><val>
        <currentSnapshot type="VirtualMachineSnapshot">snapshot-13889</currentSnapshot>
        <rootSnapshotList>
          <snapshot type="VirtualMachineSnapshot">snapshot-13889</snapshot>
          <vm type="VirtualMachine">vm-9637</vm>
          <name>tracenium-prepatch-abc</name><description>d</description><id>1</id>
          <createTime>2026-08-12T14:24:35Z</createTime><state>poweredOff</state><quiesced>true</quiesced>
        </rootSnapshotList></val></propSet></returnval>`
    );
    const snaps = await c.listSnapshots("vm-9637");
    expect(snaps).toHaveLength(1);
    expect(snaps[0].name).toBe("tracenium-prepatch-abc");
    expect(await c.currentSnapshot("vm-9637")).toBe("snapshot-13889");
  });

  it("reports an empty tree for a VM with no snapshots", async () => {
    const { c } = clientWith(() => `<returnval><obj type="VirtualMachine">vm-1</obj></returnval>`);
    expect(await c.listSnapshots("vm-1")).toEqual([]);
    expect(await c.currentSnapshot("vm-1")).toBeNull();
  });
});
