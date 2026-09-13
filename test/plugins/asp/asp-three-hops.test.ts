// test/plugins/asp/asp-three-hops.test.ts
//
// ADR-0022 — «las tres listas» de un job, caminadas de una vez.
//
// Un tipo de job nuevo tiene que atravesar TRES sitios, y romper cualquiera lo
// mata en silencio (memoria project_cdp_job_routing_gap: las fases 2 y 3 de
// ADR-0011 se desplegaron con el backend y el PrivSvc hechos y SIN el case del
// agent-core; el agente respondía `unsupported jobType` y nada ocurría):
//
//   1. el backend acepta `asp_assess`       (modules/orchestrator/job-types.ts)
//   2. el agent-core tiene su case          (src/transport/grpc-stream.ts)
//   3. el PrivSvc de Windows enruta el método IPC que ese case llama
//                                            (Ipc/Router.cs → AspCollector)
//
// y dos saltos más que la fase 0 hace obligatorios: el cliente IPC de Windows
// le da presupuesto (si no, 8 s de default y carril serial) y el script firmado
// llega al MSI y a la firma.
//
// Los repos se despliegan por separado: el nombre del tipo de job se PINEA en
// runner.ts y aquí se comprueba contra el backend cuando el repo hermano está al
// lado (workspace de desarrollo).

import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { ASP_COLLECT_METHOD, ASP_JOB_TYPE } from "../../../src/plugins/asp/runner";
import { getTimeoutForMethod, laneForMethod } from "../../../src/priv/privsvc-client-windows";

const ROOT = path.resolve(__dirname, "../../..");
const read = (rel: string) => fs.readFileSync(path.join(ROOT, rel), "utf8");

describe("asp_assess — los tres saltos", () => {
  it("1 · el backend acepta el tipo (si el repo hermano está al lado)", () => {
    const backend = path.resolve(ROOT, "../certusws-tracenium/modules/orchestrator/job-types.ts");
    if (!fs.existsSync(backend)) return;
    const src = fs.readFileSync(backend, "utf8");
    expect(src).toContain(`ASP_ASSESS: "${ASP_JOB_TYPE}"`);
    expect(src).toMatch(/value === JOB_TYPES\.ASP_ASSESS/);
  });

  it("2 · el agent-core tiene el case y llama al método del runner", () => {
    const stream = read("src/transport/grpc-stream.ts");
    expect(stream).toContain(`case "${ASP_JOB_TYPE}": {`);
    expect(stream).toContain("runAspAssessment(");
    const runner = read("src/plugins/asp/runner.ts");
    expect(runner).toContain("method: ASP_COLLECT_METHOD");
  });

  it("3 · el router del PrivSvc de Windows enruta el método al colector", () => {
    const router = read("privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/Router.cs");
    expect(router).toContain(`"${ASP_COLLECT_METHOD}" => AspCollector.HandleCollect(req)`);
  });

  it("⭐ el cliente IPC de Windows le da presupuesto por encima del handler, y va al carril lento", () => {
    // AspCollectorShape.HandlerCeilingMs = 300 s. Sin entrada caería al default
    // de 8 s y al carril serial, que es exactamente cómo murió patch_install.
    const handler = Number(/HandlerCeilingMs\s*=\s*([\d_]+)/.exec(read("privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AspCollectorShape.cs"))![1].replace(/_/g, ""));
    expect(getTimeoutForMethod(ASP_COLLECT_METHOD)).toBeGreaterThan(handler);
    expect(laneForMethod(ASP_COLLECT_METHOD)).toBe("slow");
  });

  it("el script firmado llega al binario, al MSI y a la firma", () => {
    const script = "privsvc/windows/Tracenium.PrivSvc.Windows/Scripts/asp-ad-collector.ps1";
    expect(fs.existsSync(path.join(ROOT, script))).toBe(true);
    expect(read("privsvc/windows/Tracenium.PrivSvc.Windows/Tracenium.PrivSvc.Windows.csproj")).toContain('Include="Scripts\\asp-ad-collector.ps1"');
    expect(read("scripts/build-windows-binaries.sh")).toContain("stage_asp_collector \"x64\"");
    expect(read("scripts/build-windows-binaries.sh")).toContain("stage_asp_collector \"arm64\"");
    expect(read("windows/installer/wix/PrivSvc.wxs")).toContain("binaries\\PrivSvc\\Scripts\\asp-ad-collector.ps1");
    const release = read(".github/workflows/release.yml");
    expect(release).toContain("build\\win-binaries\\x64\\PrivSvc\\Scripts");
    expect(release).toContain("build\\win-binaries\\arm64\\PrivSvc\\Scripts");
    // El colector busca el script donde el csproj y el MSI lo dejan.
    expect(read("privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AspCollector.cs")).toContain('Path.Combine(AppContext.BaseDirectory, "Scripts", AspCollectorShape.ScriptFileName)');
  });
});
