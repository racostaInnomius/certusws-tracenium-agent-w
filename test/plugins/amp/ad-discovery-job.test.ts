// test/plugins/amp/ad-discovery-job.test.ts
//
// Cobertura — el job `ad_discovery` en el agente: autorización por la política,
// llamada a privsvc y resultado por el outbox. Y las tres listas de un job
// (backend → case del agente → router del PrivSvc), porque romper una lo mata en
// silencio (memoria project_cdp_job_routing_gap).

import { describe, it, expect, vi } from "vitest";
import fs from "fs";
import path from "path";
import {
  AD_DISCOVERY_BUDGET_MS,
  AD_DISCOVERY_FACTS_NAMESPACE,
  AD_DISCOVERY_JOB_TYPE,
  AD_DISCOVERY_METHOD,
  runAdDiscoveryJob,
} from "../../../src/plugins/amp/ad-discovery-job";
import { getTimeoutForMethod, laneForMethod } from "../../../src/priv/privsvc-client-windows";

const ROOT = path.resolve(__dirname, "../../..");
const read = (rel: string) => fs.readFileSync(path.join(ROOT, rel), "utf8");
const RUN = "3f1c2b7a-8d4e-4f6a-9b1c-2d3e4f5a6b7c";

function deps(over: Partial<Parameters<typeof runAdDiscoveryJob>[0]> = {}) {
  const enqueued: any[] = [];
  const d = {
    platform: "win32" as NodeJS.Platform,
    isCollector: () => true,
    call: vi.fn(async () => ({ ok: true, result: { collector: "ad-computers/1", partOfDomain: true, domain: "corp.local", computers: [{ objectGuid: "a" }, { objectGuid: "b" }], truncated: false, error: null } })),
    enqueue: (p: unknown) => { enqueued.push(p); return enqueued.length; },
    meta: { tenantId: "111", deviceId: "wsus" },
    ...over,
  };
  return { d, enqueued };
}

describe("runAdDiscoveryJob", () => {
  it("⭐ llama a privsvc con el runId y el presupuesto, y manda el resultado por el outbox", async () => {
    const { d, enqueued } = deps();
    const ack = await runAdDiscoveryJob(d, { jobId: "j1", payload: { runId: RUN, trigger: "manual" } });
    expect(ack).toEqual({ status: 0, message: `ad_discovery_complete;run=${RUN};computers=2` });
    expect(d.call).toHaveBeenCalledWith(expect.objectContaining({ method: AD_DISCOVERY_METHOD, params: { runId: RUN, budgetMs: AD_DISCOVERY_BUDGET_MS } }));
    expect(enqueued).toHaveLength(1);
    expect(Object.keys(enqueued[0].namespaces)).toEqual([AD_DISCOVERY_FACTS_NAMESPACE]);
    expect(enqueued[0].namespaces.ad_discovery).toMatchObject({ kind: "result", runId: RUN, domain: "corp.local" });
  });

  it("⚠️ el error del script también viaja: el backend cierra la corrida con el motivo", async () => {
    const { d, enqueued } = deps({ call: vi.fn(async () => ({ ok: true, result: { error: "COMException: The server is not operational", computers: [] } })) });
    const ack = await runAdDiscoveryJob(d, { jobId: "j1", payload: { runId: RUN, trigger: "scheduled" } });
    expect(ack.message).toBe(`ad_discovery_complete;run=${RUN};error=1`);
    expect(enqueued[0].namespaces.ad_discovery.error).toContain("not operational");
  });

  it("⚠️ un equipo que ya no es colector no lee AD", async () => {
    const { d, enqueued } = deps({ isCollector: () => false });
    const ack = await runAdDiscoveryJob(d, { jobId: "j1", payload: { runId: RUN, trigger: "manual" } });
    expect(ack).toEqual({ status: 2, message: `ad_discovery_failed;run=${RUN};reason=not_collector` });
    expect(d.call).not.toHaveBeenCalled();
    expect(enqueued).toHaveLength(0);
  });

  it("fuera de Windows, o con un payload malo, falla con motivo y sin llamar a nada", async () => {
    const mac = deps({ platform: "darwin" });
    expect((await runAdDiscoveryJob(mac.d, { jobId: "j", payload: { runId: RUN, trigger: "manual" } })).message).toBe("ad_discovery_failed;reason=platform_not_supported");
    const bad = deps();
    expect((await runAdDiscoveryJob(bad.d, { jobId: "j", payload: { runId: "x", trigger: "manual" } })).message).toBe("ad_discovery_failed;reason=bad_payload:run_id");
    expect(bad.d.call).not.toHaveBeenCalled();
  });

  it("un fallo de privsvc sale como ACK de error con un motivo que no rompe el formato", async () => {
    const down = deps({ call: vi.fn(async () => { throw new Error("pipe; broken=yes"); }) });
    const a = await runAdDiscoveryJob(down.d, { jobId: "j", payload: { runId: RUN, trigger: "manual" } });
    expect(a.status).toBe(2);
    expect(a.message).toBe(`ad_discovery_failed;run=${RUN};reason=privsvc_unreachable:pipe_ broken_yes`);
    const untrusted = deps({ call: vi.fn(async () => ({ ok: false, error: { code: "script_untrusted" } })) });
    expect((await runAdDiscoveryJob(untrusted.d, { jobId: "j", payload: { runId: RUN, trigger: "manual" } })).message).toBe(`ad_discovery_failed;run=${RUN};reason=script_untrusted`);
  });
});

describe("ad_discovery — los tres saltos", () => {
  it("1 · el backend acepta el tipo y atiende el namespace (si el repo hermano está al lado)", () => {
    const backend = path.resolve(ROOT, "../certusws-tracenium/modules");
    if (!fs.existsSync(backend)) return;
    expect(fs.readFileSync(path.join(backend, "orchestrator/job-types.ts"), "utf8")).toContain(`AD_DISCOVERY: "${AD_DISCOVERY_JOB_TYPE}"`);
    expect(fs.readFileSync(path.join(backend, "discovery/discovery-logic.ts"), "utf8")).toContain(`AD_DISCOVERY_FACTS_NAMESPACE = "${AD_DISCOVERY_FACTS_NAMESPACE}"`);
  });

  it("2 · el agent-core tiene el case", () => {
    const stream = read("src/transport/grpc-stream.ts");
    expect(stream).toContain("case AD_DISCOVERY_JOB_TYPE: {");
    expect(stream).toContain("runAdDiscoveryJob(");
  });

  it("3 · el router del PrivSvc enruta el método al lector", () => {
    expect(read("privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/Router.cs")).toContain(`"${AD_DISCOVERY_METHOD}" => AdComputers.Handle(req)`);
  });

  it("⭐ presupuestos en orden: script < handler < cliente IPC, y carril lento", () => {
    const shape = read("privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AdComputersShape.cs");
    const handler = Number(/const int HandlerCeilingMs\s*=\s*([\d_]+)/.exec(shape)![1].replace(/_/g, ""));
    const overhead = Number(/const int ProcessOverheadMs\s*=\s*([\d_]+)/.exec(shape)![1].replace(/_/g, ""));
    expect(AD_DISCOVERY_BUDGET_MS).toBeLessThanOrEqual(handler - overhead);
    expect(getTimeoutForMethod(AD_DISCOVERY_METHOD)).toBeGreaterThan(handler);
    expect(laneForMethod(AD_DISCOVERY_METHOD)).toBe("slow");
  });

  it("el script llega al build, al MSI y a la firma", () => {
    expect(read("privsvc/windows/Tracenium.PrivSvc.Windows/Tracenium.PrivSvc.Windows.csproj")).toContain('Include="Scripts\\ad-computers.ps1"');
    expect(read("scripts/build-windows-binaries.sh")).toMatch(/for name in [^\n]*ad-computers\.ps1/);
    expect(read("windows/installer/wix/PrivSvc.wxs")).toContain("binaries\\PrivSvc\\Scripts\\ad-computers.ps1");
    // La firma cubre la carpeta entera de Scripts con filtro ps1.
    expect(read(".github/workflows/release.yml")).toMatch(/PrivSvc\\Scripts\s*\n\s*files-folder-filter:\s*ps1/);
  });
});
