// test/plugins/pmp-change-verification.test.ts
//
// ADR-0038 F2 — la foto previa de cualquier cambio y «qué escucha el equipo».

import { describe, expect, it } from "vitest";
import { wantsBaseline, captureChangeBaseline } from "../../src/plugins/pmp/change-baseline";
import { observeListeners, parseTasklistPidServices, unitFromCgroup } from "../../src/plugins/pmp/listeners";
import { compareVerification } from "../../src/plugins/pmp/verification";
import { encodeDiscoverAck } from "../../src/plugins/pmp/verification-ack";

describe("wantsBaseline", () => {
  it("⭐ un parche siempre; los demás cambios sólo si el control plane lo pide", () => {
    expect(wantsBaseline("patch_install", {})).toBe(true);
    expect(wantsBaseline("patch_install", { mode: "download" })).toBe(false);
    for (const t of ["software_install", "device_reboot", "patch_remediate"]) {
      expect(wantsBaseline(t, {})).toBe(false);
      expect(wantsBaseline(t, { verification: { checks: [] } })).toBe(true);
    }
    expect(wantsBaseline("software_install", { verification: [] })).toBe(false);
    expect(wantsBaseline("agent_update", { verification: {} })).toBe(false);
  });

  it("un ensayo de remediación no cambia nada: sin foto; un lote, si algún fix escribe", () => {
    const v = { verification: {} };
    expect(wantsBaseline("patch_remediate", { ...v, mode: "dry_run" })).toBe(false);
    expect(wantsBaseline("patch_remediate", { ...v, mode: "revert" })).toBe(true);
    expect(wantsBaseline("patch_remediate", { ...v, items: [{ mode: "dry_run" }, { mode: "revert_dry_run" }] })).toBe(false);
    expect(wantsBaseline("patch_remediate", { ...v, items: [{ mode: "dry_run" }, { mode: "apply" }] })).toBe(true);
  });
});

describe("listeners", () => {
  it("PID → servicios de tasklist /svc", () => {
    const out = '"svchost.exe","1204","RpcEptMapper,RpcSs"\r\n"sqlservr.exe","4410","MSSQLSERVER"\r\n"explorer.exe","5000","N/A"\r\n';
    const m = parseTasklistPidServices(out);
    expect(m.get(1204)).toEqual(["RpcEptMapper", "RpcSs"]);
    expect(m.get(4410)).toEqual(["MSSQLSERVER"]);
    expect(m.has(5000)).toBe(false);
  });

  it("la unidad systemd del cgroup (v2 y v1)", () => {
    expect(unitFromCgroup("0::/system.slice/nginx.service\n")).toBe("nginx.service");
    expect(unitFromCgroup("12:pids:/user.slice\n1:name=systemd:/system.slice/postgresql@16-main.service\n")).toBe("postgresql@16-main.service");
    expect(unitFromCgroup("0::/user.slice/user-1000.slice/session-2.scope\n")).toBeNull();
  });

  it("⭐ puerto + proceso + servicio en Windows; el que no se sabe de quién es, sólo con el puerto", async () => {
    const deps: any = {
      platform: "win32",
      exec: async () => ({ code: 0, stdout: '"sqlservr.exe","4410","MSSQLSERVER"\r\n', stderr: "" }),
      readFile: async () => "",
    };
    const r = await observeListeners(deps, {
      listPorts: async () => [1433, 49666],
      owners: async () => new Map([[1433, { pid: 4410, name: "sqlservr.exe" }]]),
    });
    expect(r).toEqual({ ok: true, listeners: [{ port: 1433, process: "sqlservr.exe", services: ["MSSQLSERVER"] }, { port: 49666 }] });
  });

  it("si no se puede leer, lo dice (no «no escucha nada»)", async () => {
    const r = await observeListeners({ platform: "linux" } as any, { listPorts: async () => { throw new Error("netstat missing"); }, owners: async () => new Map() });
    expect(r).toEqual({ ok: false, reason: "netstat missing" });
  });
});

describe("la foto previa y el veredicto", () => {
  it("⭐ guarda lo que escuchaba ANTES, y el veredicto lo devuelve como observado", async () => {
    const saved: any[] = [];
    const deps: any = {
      platform: "linux",
      exec: async (cmd: string, args: string[]) => ({ code: 0, stdout: args[0] === "list-units" ? "nginx.service loaded active running x\n" : "nginx.service enabled enabled\n", stderr: "" }),
      readFile: async () => "0::/system.slice/nginx.service\n",
      lstat: async () => ({}),
      sha256File: async () => "",
    };
    // observeListeners usa los lectores de CDP de verdad; aquí basta con que no reviente.
    await captureChangeBaseline("job-1", { verification: { checks: [] } }, { deps, save: (b) => saved.push(b) });
    expect(saved).toHaveLength(1);
    expect(saved[0].services).toEqual({ ok: true, services: ["nginx.service"] });

    const baseline = { ...saved[0], listeners: [{ port: 443, process: "nginx", services: ["nginx.service"] }] };
    const r = compareVerification("job-1", baseline, [{ ok: true, services: ["nginx.service"] }], [], []);
    expect(r.status).toBe("passed");
    expect(r.observed).toEqual({ listeners: [{ port: 443, process: "nginx", services: ["nginx.service"] }] });
  });

  it("verify_discover viaja como el veredicto: prefijo + b64url", () => {
    const msg = encodeDiscoverAck({ listeners: { ok: true, listeners: [{ port: 22 }] }, services: { ok: true, services: ["sshd.service"] } });
    const m = /^verify_discover:ok;result=([A-Za-z0-9_-]+)$/.exec(msg)!;
    expect(JSON.parse(Buffer.from(m[1], "base64url").toString())).toEqual({ listeners: { ok: true, listeners: [{ port: 22 }] }, services: { ok: true, services: ["sshd.service"] } });
  });
});
