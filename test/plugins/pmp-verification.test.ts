// test/plugins/pmp-verification.test.ts
//
// ADR-0038 F1 — «¿quién valida que los servicios levantaron tras el reboot?».

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import http from "http";
import net from "net";
import {
  compareVerification,
  parseAutoStartServices,
  parseChecks,
  parseSystemctlNames,
  parseTasklistServices,
  parseTriggerStartServices,
  runCheck,
  snapshotServices,
  type VerificationBaseline,
} from "../../src/plugins/pmp/verification";
import { encodeVerificationAck } from "../../src/plugins/pmp/verification-ack";

// Salida real de `tasklist /svc /FO CSV /NH` (Windows Server 2022, recortada).
const TASKLIST = [
  '"System Idle Process","0","N/A"',
  '"svchost.exe","1012","BrokerInfrastructure,DcomLaunch,PlugPlay,Power,SystemEventsBroker"',
  '"svchost.exe","1340","RpcEptMapper,RpcSs"',
  '"sqlservr.exe","2280","MSSQLSERVER"',
  '"w3wp.exe","3311","No disponible"',
  '"svchost.exe","4410","TermService"',
].join("\r\n");

// `reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v Start` (recortada).
const REG_START = [
  "",
  "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DcomLaunch",
  "    Start    REG_DWORD    0x2",
  "",
  "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\MSSQLSERVER",
  "    Start    REG_DWORD    0x2",
  "",
  "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\PlugPlay",
  "    Start    REG_DWORD    0x3",
  "",
  "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TermService",
  "    Start    REG_DWORD    0x2",
  "",
  "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TermService\\Parameters",
  "    Start    REG_DWORD    0x4",
  "",
  "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SystemEventsBroker",
  "    Start    REG_DWORD    0x2",
  "",
  "Fin de la búsqueda: 6 coincidencias encontradas.",
].join("\r\n");

const REG_TRIGGER = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SystemEventsBroker\\TriggerInfo\r\n";

describe("parsers (Windows sin PowerShell, sin texto traducible)", () => {
  it("tasklist /svc: nombres de servicio, sin «N/A» ni su traducción", () => {
    const s = parseTasklistServices(TASKLIST);
    expect([...s].sort()).toEqual(["brokerinfrastructure", "dcomlaunch", "mssqlserver", "plugplay", "power", "rpceptmapper", "rpcss", "systemeventsbroker", "termservice"]);
  });

  it("reg query: sólo Start=0x2 de la clave DIRECTA del servicio", () => {
    const a = parseAutoStartServices(REG_START);
    expect([...a].sort()).toEqual(["dcomlaunch", "mssqlserver", "systemeventsbroker", "termservice"]);
  });

  it("TriggerInfo: los de arranque por desencadenador", () => {
    expect([...parseTriggerStartServices(REG_TRIGGER)]).toEqual(["systemeventsbroker"]);
  });

  it("systemctl: primera columna, sólo .service", () => {
    expect([...parseSystemctlNames("nginx.service loaded active running A high performance web server\nssh.service loaded active running OpenBSD\n")]).toEqual(["nginx.service", "ssh.service"]);
  });
});

describe("snapshotServices (Windows): en marcha ∩ automático − desencadenador − los que paran solos", () => {
  it("⭐ la foto de un SQL Server", async () => {
    const exec = async (cmd: string, args: string[]) => {
      if (cmd === "tasklist") return { code: 0, stdout: TASKLIST, stderr: "" };
      if (args.includes("TriggerInfo")) return { code: 0, stdout: REG_TRIGGER, stderr: "" };
      return { code: 0, stdout: REG_START, stderr: "" };
    };
    const snap = await snapshotServices({ platform: "win32", exec } as any);
    expect(snap).toEqual({ ok: true, services: ["dcomlaunch", "mssqlserver", "termservice"] });
  });

  it("si no se puede leer, lo dice: nunca «0 servicios»", async () => {
    const exec = async () => ({ code: 5, stdout: "", stderr: "access denied" });
    expect(await snapshotServices({ platform: "win32", exec } as any)).toEqual({ ok: false, reason: "tasklist exited 5" });
  });

  it("macOS: no soportado (nivel 1), con motivo", async () => {
    expect((await snapshotServices({ platform: "darwin", exec: async () => ({ code: 0, stdout: "", stderr: "" }) } as any)).ok).toBe(false);
  });
});

const base = (services: string[], checksBefore = [] as any[], checks = [] as any[]): VerificationBaseline => ({
  jobId: "8d9ab682-0c40-45f1-8318-a12b1218f8d6",
  capturedAt: "2026-10-02T03:00:00.000Z",
  services: { ok: true, services },
  checks,
  checksBefore,
});

describe("compareVerification", () => {
  const J = "8d9ab682-0c40-45f1-8318-a12b1218f8d6";

  it("🔴 un servicio que estaba arriba y no volvió en NINGUNA muestra → failed", () => {
    const r = compareVerification(J, base(["mssqlserver", "termservice"]), [
      { ok: true, services: ["termservice"] },
      { ok: true, services: ["termservice"] },
    ], [], []);
    expect(r.status).toBe("failed");
    expect(r.services).toEqual({ level: 1, status: "compared", watched: 2, regressions: ["mssqlserver"] });
  });

  it("⚠️ uno que arrancó tarde (sólo en la segunda muestra) NO es regresión", () => {
    const r = compareVerification(J, base(["mssqlserver"]), [
      { ok: true, services: [] },
      { ok: true, services: ["mssqlserver"] },
    ], [], []);
    expect(r.status).toBe("passed");
  });

  it("🔴 una comprobación que pasaba antes y falla después → regresión", () => {
    const checks = [{ id: "web", kind: "http", url: "http://localhost/health" }];
    const r = compareVerification(J, base([], [{ id: "web", ok: true, detail: "HTTP 200" }], checks), [{ ok: true, services: [] }], checks as any, [[{ id: "web", ok: false, detail: "ECONNREFUSED" }]]);
    expect(r.status).toBe("failed");
    expect(r.checks[0]).toMatchObject({ before: true, after: false, regression: true, alreadyFailing: false });
  });

  it("⭐ una comprobación que YA fallaba antes no culpa al parche", () => {
    const checks = [{ id: "web", kind: "http", url: "http://localhost/health" }];
    const r = compareVerification(J, base([], [{ id: "web", ok: false, detail: "HTTP 500" }], checks), [{ ok: true, services: [] }], checks as any, [[{ id: "web", ok: false, detail: "HTTP 500" }]]);
    expect(r.status).toBe("passed");
    expect(r.checks[0]).toMatchObject({ regression: false, alreadyFailing: true });
  });

  it("sin foto previa: el nivel 1 dice por qué; sin comprobaciones, no_baseline (no «passed»)", () => {
    const r = compareVerification(J, null, [{ ok: true, services: ["x"] }], [], []);
    expect(r.status).toBe("no_baseline");
    expect(r.services).toMatchObject({ status: "unavailable", reason: "no pre-install snapshot on this device" });
  });
});

describe("parseChecks: lo que manda el control plane se valida aquí también", () => {
  it("acepta las cinco formas y descarta lo raro", () => {
    const c = parseChecks([
      { id: "a", kind: "service", name: "MSSQLSERVER" },
      { id: "b", kind: "process", name: "python3" },
      { id: "c", kind: "port", port: 1433 },
      { id: "d", kind: "tcp", host: "10.0.0.5", port: 445 },
      { id: "e", kind: "http", url: "https://localhost:8443/health", expectStatus: [200], tlsVerify: false },
      { id: "f", kind: "service", name: "x & del C:\\" },
      { id: "g", kind: "port", port: 70000 },
      { id: "h", kind: "exec", cmd: "rm -rf /" },
    ]);
    expect(c.map((x) => x.id)).toEqual(["a", "b", "c", "d", "e"]);
  });
});

describe("runCheck — TCP y HTTP de verdad, contra servidores locales", () => {
  let httpServer: http.Server;
  let tcpServer: net.Server;
  let httpPort = 0;
  let tcpPort = 0;
  beforeAll(async () => {
    httpServer = http.createServer((req, res) => {
      if (req.url === "/health") { res.writeHead(200); res.end("status: OK"); }
      else { res.writeHead(500); res.end("boom"); }
    });
    await new Promise<void>((r) => httpServer.listen(0, "127.0.0.1", () => r()));
    httpPort = (httpServer.address() as any).port;
    tcpServer = net.createServer((s) => s.end());
    await new Promise<void>((r) => tcpServer.listen(0, "127.0.0.1", () => r()));
    tcpPort = (tcpServer.address() as any).port;
  });
  afterAll(() => { httpServer.close(); tcpServer.close(); });
  const d = {} as any;

  it("HTTP 200 con el texto esperado → ok; 500 → no", async () => {
    expect(await runCheck(d, { id: "h", kind: "http", url: `http://127.0.0.1:${httpPort}/health`, bodyContains: "OK" })).toMatchObject({ ok: true });
    expect(await runCheck(d, { id: "h", kind: "http", url: `http://127.0.0.1:${httpPort}/x` })).toMatchObject({ ok: false, detail: "HTTP 500" });
  });

  it("TCP abierto → ok; cerrado → no, con el motivo", async () => {
    expect(await runCheck(d, { id: "t", kind: "tcp", host: "127.0.0.1", port: tcpPort })).toMatchObject({ ok: true });
    const closed = await runCheck(d, { id: "t", kind: "tcp", host: "127.0.0.1", port: 1, timeoutMs: 1000 });
    expect(closed.ok).toBe(false);
    expect(closed.detail).toMatch(/ECONNREFUSED|no answer/);
  });
});

describe("encodeVerificationAck", () => {
  it("patch_verify:<estado>;result=<b64url(JSON)> que el backend separa por ; y =", () => {
    const r = compareVerification("8d9ab682-0c40-45f1-8318-a12b1218f8d6", base(["a"]), [{ ok: true, services: [] }], [], []);
    const msg = encodeVerificationAck(r);
    const m = /^patch_verify:(\w+);result=([A-Za-z0-9_-]+)$/.exec(msg)!;
    expect(m[1]).toBe("failed");
    expect(JSON.parse(Buffer.from(m[2], "base64url").toString("utf8")).services.regressions).toEqual(["a"]);
  });
});
