// test/plugins/live-query.test.ts
//
// ADR-0029 F2 — la consulta en vivo en el agente. Las salidas son las REALES
// de cada comando, incluidas las de un Windows en español: lo que se rompe en
// silencio es emparejar contra texto que el sistema traduce, y confundir «no
// pude mirarlo» con «no».

import { describe, expect, it, vi } from "vitest";
import { parseLiveQueryJob } from "../../src/domain/live-query-question";
import {
  commMatches,
  parseLsofListen,
  parseProcNetListeners,
  parseRegQuery,
  parseScStartType,
  parseScState,
  parseTasklistVerbose,
  parseWindowsNetstatListeners,
  runProbe,
  type ExecFn,
  type ProbeDeps,
} from "../../src/plugins/live-query/probes";
import { runLiveQueryJob } from "../../src/plugins/live-query/live-query-job";

const Q = "11111111-2222-3333-4444-555555555555";

// ── Salidas reales ───────────────────────────────────────────────────

const TASKLIST_ANYDESK = [
  '"AnyDesk.exe","4242","Console","1","31.204 KB","Running","ACME\\ana","0:00:12","AnyDesk"',
  '"AnyDesk.exe","5120","Services","0","12.880 KB","Unknown","NT AUTHORITY\\SYSTEM","0:00:01","N/A"',
].join("\r\n");
const TASKLIST_NONE_ES = "INFORMACIÓN: no hay tareas ejecutándose que coincidan con los criterios especificados.\r\n";
const TASKLIST_EXPLORER = [
  '"explorer.exe","7788","Console","1","98.112 KB","Running","ACME\\ana","0:01:40","N/A"',
  '"explorer.exe","9912","RDP-Tcp#3","3","77.404 KB","Running","ACME\\soporte","0:00:20","N/A"',
].join("\r\n");

const SC_QUERY_ES = `
NOMBRE_SERVICIO: Spooler
        TIPO               : 110  WIN32_OWN_PROCESS  (interactive)
        ESTADO             : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        CÓD_SALIDA_WIN32   : 0  (0x0)
`;
const SC_QC_ES = `
[SC] QueryServiceConfig CORRECTO

NOMBRE_SERVICIO: Spooler
        TIPO               : 110  WIN32_OWN_PROCESS  (interactive)
        TIPO_INICIO        : 2   AUTO_START  (DELAYED)
        CONTROL_ERROR      : 1   NORMAL
`;

const NETSTAT_ES = `
Conexiones activas

  Proto  Dirección local          Dirección remota        Estado           PID
  TCP    0.0.0.0:135            0.0.0.0:0              ESCUCHANDO       1044
  TCP    0.0.0.0:3389           0.0.0.0:0              ESCUCHANDO       1288
  TCP    10.0.0.12:3389         10.0.0.50:51544        ESTABLECIDO      1288
  TCP    10.0.0.12:52000        52.1.2.3:3389          ESTABLECIDO      9000
  TCP    [::]:445               [::]:0                 ESCUCHANDO       4
  UDP    0.0.0.0:3389           *:*                                     1288
`;

const REG_DWORD = `
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System
    EnableLUA    REG_DWORD    0x1

`;
const REG_DEFAULT_ES = `
HKEY_LOCAL_MACHINE\\SOFTWARE\\Acme
    (Predeterminado)    REG_SZ    Acme Agent 4.2

`;
const REG_EMPTY_SZ = `
HKEY_LOCAL_MACHINE\\SOFTWARE\\Acme
    Ring    REG_SZ

`;

const PS_MAC = `  101 root             /usr/sbin/cupsd
 4242 ana              /Applications/AnyDesk.app/Contents/MacOS/AnyDesk
 5555 ana              /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
`;
const PS_LINUX = `    1 root     systemd
  812 root     tracenium-agent
  990 www-data nginx
`;

const LSOF_MAC = `COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
nginx     812 root    6u  IPv4 0x1a2b3c4d5e6f7a8b      0t0  TCP *:8443 (LISTEN)
`;

// /proc/net/tcp: 0.0.0.0:22 LISTEN, 127.0.0.1:5432 LISTEN, una conexión establecida al 22.
const PROC_TCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   113        0 1002 1 0000000000000000 100 0 0 10 0
   2: 0C00000A:0016 3200000A:C958 01 00000000:00000000 02:00000000 00000000     0        0 1003 4 0000000000000000 20 4 29 10 -1
`;

// ── Dobles ───────────────────────────────────────────────────────────

type Script = Record<string, { code: number | null; stdout?: string } | Error>;
function fakeExec(script: Script): ExecFn & { calls: string[][] } {
  const calls: string[][] = [];
  const fn = (async (cmd: string, args: string[]) => {
    calls.push([cmd, ...args]);
    const key = [cmd, ...args].join(" ");
    const hit = Object.entries(script).find(([k]) => key.startsWith(k));
    if (!hit) throw new Error(`unexpected command: ${key}`);
    if (hit[1] instanceof Error) throw hit[1];
    return { code: hit[1].code, stdout: hit[1].stdout ?? "", stderr: "" };
  }) as ExecFn & { calls: string[][] };
  fn.calls = calls;
  return fn;
}

function deps(platform: NodeJS.Platform, script: Script, extra: Partial<ProbeDeps> = {}): ProbeDeps {
  return {
    platform,
    exec: fakeExec(script),
    lstat: async () => {
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    },
    sha256File: async () => "a".repeat(64),
    readFile: async () => {
      throw new Error("no file");
    },
    ...extra,
  };
}

// ── Revalidación ─────────────────────────────────────────────────────

describe("la pregunta se revalida en el agente", () => {
  it("⭐ las mismas reglas que el backend: nada fuera del catálogo, sin rutas raras, sin valores de credenciales", () => {
    expect(parseLiveQueryJob({ queryId: Q, probe: "process", params: { name: "AnyDesk.exe" } })).toMatchObject({ ok: true });
    expect(parseLiveQueryJob({ queryId: Q, probe: "shell", params: { cmd: "whoami" } })).toMatchObject({ ok: false, error: "probe" });
    expect(parseLiveQueryJob({ queryId: Q, probe: "process", params: { name: "C:\\x\\a.exe" } })).toMatchObject({ ok: false, error: "name_is_path" });
    expect(parseLiveQueryJob({ queryId: Q, probe: "file", params: { path: "/etc/../root/x" } })).toMatchObject({ ok: false, error: "path:dotdot" });
    expect(parseLiveQueryJob({ queryId: Q, probe: "file", params: { path: "\\\\srv\\share\\x" } })).toMatchObject({ ok: false });
    expect(parseLiveQueryJob({ queryId: Q, probe: "registry", params: { key: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", value: "DefaultPassword" } })).toMatchObject({ ok: false, error: "registry:credential_value" });
    expect(parseLiveQueryJob({ queryId: Q, probe: "registry", params: { key: "HKCU\\Software\\x", value: "a" } })).toMatchObject({ ok: false, error: "registry:registry_root" });
    expect(parseLiveQueryJob({ queryId: Q, probe: "port", params: { port: 0 } })).toMatchObject({ ok: false, error: "port" });
    expect(parseLiveQueryJob({ queryId: "x", probe: "port", params: { port: 22 } })).toMatchObject({ ok: false, queryId: null });
  });
});

// ── Parsers ──────────────────────────────────────────────────────────

describe("parsers con salidas reales", () => {
  it("tasklist: sólo filas CSV (el «no hay tareas» sale traducido) y el usuario en la 7ª columna", () => {
    expect(parseTasklistVerbose(TASKLIST_ANYDESK)).toEqual([
      { image: "AnyDesk.exe", pid: 4242, user: "ACME\\ana" },
      { image: "AnyDesk.exe", pid: 5120, user: "NT AUTHORITY\\SYSTEM" },
    ]);
    expect(parseTasklistVerbose(TASKLIST_NONE_ES)).toEqual([]);
  });

  it("⚠️ sc.exe en español: el estado y el arranque salen de las constantes, no de las etiquetas", () => {
    expect(parseScState(SC_QUERY_ES)).toBe("running");
    expect(parseScStartType(SC_QC_ES)).toBe("auto (delayed)");
    expect(parseScState("        STATE              : 1  STOPPED")).toBe("stopped");
  });

  it("⚠️ netstat en español: escucha = remoto 0.0.0.0:0 o [::]:0, sin leer «ESCUCHANDO»", () => {
    expect(parseWindowsNetstatListeners(NETSTAT_ES, 3389)).toEqual([{ address: "0.0.0.0", pid: 1288 }]);
    expect(parseWindowsNetstatListeners(NETSTAT_ES, 445)).toEqual([{ address: "[::]", pid: 4 }]);
    // Una conexión SALIENTE al 3389 de otro equipo no es escuchar en el 3389.
    expect(parseWindowsNetstatListeners(NETSTAT_ES, 52000)).toEqual([]);
  });

  it("reg query: tipo y dato; el valor por defecto sale traducido y no se busca por nombre", () => {
    expect(parseRegQuery(REG_DWORD)).toEqual({ type: "REG_DWORD", data: "0x1" });
    expect(parseRegQuery(REG_DEFAULT_ES)).toEqual({ type: "REG_SZ", data: "Acme Agent 4.2" });
    expect(parseRegQuery(REG_EMPTY_SZ)).toEqual({ type: "REG_SZ", data: "" });
  });

  it("ps: macOS da la ruta (con espacios), Linux el nombre truncado a 15", () => {
    expect(commMatches("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "Google Chrome", "darwin")).toBe(true);
    // TASK_COMM_LEN = 16 con el NUL: Linux guarda 15 caracteres del nombre.
    expect(commMatches("tracenium-agent", "tracenium-agent-w", "linux")).toBe(true);
    expect(commMatches("tracenium-agent", "tracenium-agent-w", "darwin")).toBe(false);
    expect(commMatches("/usr/sbin/cupsd", "cups", "darwin")).toBe(false);
  });

  it("lsof y /proc/net/tcp", () => {
    expect(parseLsofListen(LSOF_MAC)).toEqual([{ command: "nginx", pid: 812, address: "*" }]);
    expect(parseProcNetListeners(PROC_TCP, 22)).toEqual(["0.0.0.0"]);
    expect(parseProcNetListeners(PROC_TCP, 5432)).toEqual(["127.0.0.1"]);
    expect(parseProcNetListeners(PROC_TCP, 443)).toEqual([]);
  });
});

// ── Sondas ───────────────────────────────────────────────────────────

describe("sondas", () => {
  it("⭐ proceso en Windows: «AnyDesk» es «AnyDesk.exe», y lanza tasklist sin shell", async () => {
    const d = deps("win32", { tasklist: { code: 0, stdout: TASKLIST_ANYDESK } });
    const r = await runProbe(d, { probe: "process", params: { name: "AnyDesk" } });
    expect(r).toEqual({ outcome: "answered", answer: { running: true, count: 2, instances: [{ pid: 4242, user: "ACME\\ana" }, { pid: 5120, user: "NT AUTHORITY\\SYSTEM" }] } });
    expect((d.exec as any).calls[0]).toEqual(["tasklist", "/V", "/FO", "CSV", "/NH", "/FI", "IMAGENAME eq AnyDesk.exe"]);
  });

  it("⚠️ «no pude mirarlo» NO es «no»: si el comando no arranca, es error, no running=false", async () => {
    const r = await runProbe(deps("win32", { tasklist: new Error("could not run tasklist (ENOENT)") }), { probe: "process", params: { name: "x.exe" } });
    expect(r).toEqual({ outcome: "error", error: "could not run tasklist (ENOENT)" });
    const r2 = await runProbe(deps("darwin", { ps: { code: 1 } }), { probe: "process", params: { name: "x" } });
    expect(r2.outcome).toBe("error");
  });

  it("proceso en macOS por ps", async () => {
    const r = await runProbe(deps("darwin", { ps: { code: 0, stdout: PS_MAC } }), { probe: "process", params: { name: "AnyDesk" } });
    expect(r).toMatchObject({ outcome: "answered", answer: { running: true, count: 1, instances: [{ pid: 4242, user: "ana" }] } });
  });

  it("⭐ servicio: 1060 es «no existe» en cualquier idioma; el resto, estado y arranque", async () => {
    expect(await runProbe(deps("win32", { "sc.exe query": { code: 1060, stdout: "[SC] EnumQueryServicesStatus:OpenService ERROR 1060:" } }), { probe: "service", params: { name: "Nope" } })).toEqual({
      outcome: "answered",
      answer: { exists: false },
    });
    expect(await runProbe(deps("win32", { "sc.exe query": { code: 0, stdout: SC_QUERY_ES }, "sc.exe qc": { code: 0, stdout: SC_QC_ES } }), { probe: "service", params: { name: "Spooler" } })).toEqual({
      outcome: "answered",
      answer: { exists: true, state: "running", startMode: "auto (delayed)" },
    });
    expect((await runProbe(deps("win32", { "sc.exe query": { code: 5 } }), { probe: "service", params: { name: "X" } })).outcome).toBe("error");
  });

  it("servicio en Linux (systemd) y macOS (launchd)", async () => {
    const linux = await runProbe(
      deps("linux", { systemctl: { code: 0, stdout: "LoadState=loaded\nActiveState=failed\nUnitFileState=enabled\nDescription=A high performance web server\n" } }),
      { probe: "service", params: { name: "nginx" } }
    );
    expect(linux).toEqual({ outcome: "answered", answer: { exists: true, state: "stopped", startMode: "enabled", displayName: "A high performance web server" } });
    expect(await runProbe(deps("linux", { systemctl: { code: 0, stdout: "LoadState=not-found\nActiveState=inactive\n" } }), { probe: "service", params: { name: "nope" } })).toEqual({ outcome: "answered", answer: { exists: false } });
    expect(await runProbe(deps("darwin", { launchctl: { code: 113 } }), { probe: "service", params: { name: "com.nope" } })).toEqual({ outcome: "answered", answer: { exists: false } });
    expect(await runProbe(deps("darwin", { launchctl: { code: 0, stdout: "system/com.acme.agent = {\n\tstate = running\n}" } }), { probe: "service", params: { name: "com.acme.agent" } })).toMatchObject({
      answer: { exists: true, state: "running" },
    });
  });

  it("⭐ fichero: hash si es pequeño; enlace sin seguir; una ruta de Windows en un Mac no aplica", async () => {
    const file = { isFile: () => true, isDirectory: () => false, isSymbolicLink: () => false, size: 824, mtimeMs: Date.parse("2026-09-21T10:00:00Z") };
    const d = deps("win32", {}, { lstat: async () => file });
    expect(await runProbe(d, { probe: "file", params: { path: "C:\\Windows\\System32\\drivers\\etc\\hosts" } })).toEqual({
      outcome: "answered",
      answer: { exists: true, sizeBytes: 824, modifiedAt: "2026-09-21T10:00:00.000Z", sha256: "a".repeat(64) },
    });
    const big = deps("linux", {}, { lstat: async () => ({ ...file, size: 20 * 1024 * 1024 }), sha256File: vi.fn() });
    expect(await runProbe(big, { probe: "file", params: { path: "/var/log/big.log" } })).toMatchObject({ answer: { exists: true, sha256: null } });
    expect(big.sha256File).not.toHaveBeenCalled();
    expect(await runProbe(deps("darwin", {}), { probe: "file", params: { path: "C:\\x.txt" } })).toEqual({ outcome: "unsupported" });
    expect(await runProbe(deps("linux", {}), { probe: "file", params: { path: "/etc/nope" } })).toEqual({ outcome: "answered", answer: { exists: false } });
    const denied = deps("linux", {}, { lstat: async () => { throw Object.assign(new Error("EACCES"), { code: "EACCES" }); } });
    expect(await runProbe(denied, { probe: "file", params: { path: "/root/x" } })).toMatchObject({ outcome: "error" });
  });

  it("registro: vista 64 y luego 32; salida 1 en las dos = no existe; fuera de Windows no aplica", async () => {
    const d = deps("win32", { "reg.exe query HKLM\\SOFTWARE\\Acme /v Ring /reg:64": { code: 1 }, "reg.exe query HKLM\\SOFTWARE\\Acme /v Ring /reg:32": { code: 0, stdout: REG_DWORD.replace("EnableLUA", "Ring") } });
    expect(await runProbe(d, { probe: "registry", params: { key: "HKLM\\SOFTWARE\\Acme", value: "Ring" } })).toEqual({ outcome: "answered", answer: { exists: true, type: "REG_DWORD", data: "0x1" } });
    expect(await runProbe(deps("win32", { "reg.exe": { code: 1 } }), { probe: "registry", params: { key: "HKLM\\SOFTWARE\\Acme", value: "Ring" } })).toEqual({ outcome: "answered", answer: { exists: false } });
    const def = deps("win32", { "reg.exe query HKLM\\SOFTWARE\\Acme /ve": { code: 0, stdout: REG_DEFAULT_ES } });
    expect(await runProbe(def, { probe: "registry", params: { key: "HKLM\\SOFTWARE\\Acme", value: "" } })).toMatchObject({ answer: { data: "Acme Agent 4.2" } });
    expect(await runProbe(deps("darwin", {}), { probe: "registry", params: { key: "HKLM\\SOFTWARE\\Acme", value: "Ring" } })).toEqual({ outcome: "unsupported" });
  });

  it("puerto en las tres plataformas", async () => {
    const win = deps("win32", { "netstat -ano": { code: 0, stdout: NETSTAT_ES }, "tasklist /V /FO CSV /NH /FI PID eq 1288": { code: 0, stdout: '"svchost.exe","1288","Services","0","9.000 KB","Unknown","NT AUTHORITY\\NETWORK SERVICE","0:00:03","N/A"' } });
    expect(await runProbe(win, { probe: "port", params: { port: 3389 } })).toEqual({ outcome: "answered", answer: { listening: true, process: "svchost.exe", address: "0.0.0.0" } });
    expect(await runProbe(deps("win32", { "netstat -ano": { code: 0, stdout: NETSTAT_ES } }), { probe: "port", params: { port: 8080 } })).toEqual({ outcome: "answered", answer: { listening: false } });
    expect(await runProbe(deps("darwin", { lsof: { code: 0, stdout: LSOF_MAC } }), { probe: "port", params: { port: 8443 } })).toEqual({ outcome: "answered", answer: { listening: true, process: "nginx", address: "*" } });
    expect(await runProbe(deps("darwin", { lsof: { code: 1 } }), { probe: "port", params: { port: 8443 } })).toEqual({ outcome: "answered", answer: { listening: false } });
    const linux = deps("linux", {}, { readFile: async (p) => (p.endsWith("tcp") ? PROC_TCP : "  sl\n"), listenerName: async () => "sshd" });
    expect(await runProbe(linux, { probe: "port", params: { port: 22 } })).toEqual({ outcome: "answered", answer: { listening: true, process: "sshd", address: "0.0.0.0" } });
  });

  it("usuarios: dueños de explorer.exe en Windows (consola y RDP), `who` en macOS/Linux", async () => {
    expect(await runProbe(deps("win32", { tasklist: { code: 0, stdout: TASKLIST_EXPLORER } }), { probe: "logged_on_users", params: {} })).toEqual({
      outcome: "answered",
      answer: { users: ["ACME\\ana", "ACME\\soporte"] },
    });
    expect(await runProbe(deps("win32", { tasklist: { code: 0, stdout: TASKLIST_NONE_ES } }), { probe: "logged_on_users", params: {} })).toEqual({ outcome: "answered", answer: { users: [] } });
    expect(await runProbe(deps("darwin", { who: { code: 0, stdout: "ana      console  Sep 21 08:01\nana      ttys000  Sep 21 09:10\nsoporte  ttys001  Sep 21 09:30 (10.0.0.5)\n" } }), { probe: "logged_on_users", params: {} })).toEqual({
      outcome: "answered",
      answer: { users: ["ana", "soporte"] },
    });
  });
});

// ── El job ───────────────────────────────────────────────────────────

describe("el job live_query", () => {
  const job = (payload: unknown, over: Record<string, unknown> = {}) => {
    const enqueue = vi.fn(() => 1);
    const run = runLiveQueryJob(
      { probe: deps("darwin", { ps: { code: 0, stdout: PS_MAC } }), ampEnabled: () => true, enqueue, ...over } as any,
      { jobId: "job-1", payload }
    );
    return { run, enqueue };
  };

  it("⭐ la respuesta viaja SOLA en su namespace, con el queryId; el ACK dice el desenlace", async () => {
    const { run, enqueue } = job({ queryId: Q, probe: "process", params: { name: "AnyDesk" } });
    expect(await run).toEqual({ status: 0, message: `live_query_answered;query=${Q};outcome=answered` });
    const sent = (enqueue.mock.calls[0] as any)[0];
    expect(Object.keys(sent.namespaces)).toEqual(["live_query"]);
    expect(sent.namespaces.live_query).toMatchObject({ queryId: Q, probe: "process", outcome: "answered", answer: { running: true, count: 1 } });
    expect(sent.schemaVersion).toBeTruthy();
  });

  it("⚠️ una pregunta que el agente rechaza se contesta con el motivo (no se queda en «no answer»)", async () => {
    const { run, enqueue } = job({ queryId: Q, probe: "registry", params: { key: "HKLM\\X", value: "DefaultPassword" } });
    expect((await run).status).toBe(2);
    expect((enqueue.mock.calls[0] as any)[0].namespaces.live_query).toMatchObject({ queryId: Q, outcome: "error", error: "rejected by the agent: registry:credential_value" });
  });

  it("sin AMP en la política no se lee nada", async () => {
    const { run, enqueue } = job({ queryId: Q, probe: "process", params: { name: "AnyDesk" } }, { ampEnabled: () => false });
    expect((await run).message).toContain("amp_disabled");
    expect((enqueue.mock.calls[0] as any)[0].namespaces.live_query.outcome).toBe("error");
  });

  it("una sonda que se cuelga sale como error por tiempo, no como silencio", async () => {
    const hang = deps("darwin", {}, { exec: (() => new Promise(() => {})) as any });
    const enqueue = vi.fn(() => 1);
    const ack = await runLiveQueryJob({ probe: hang, ampEnabled: () => true, enqueue, budgetMs: 20 }, { jobId: "j", payload: { queryId: Q, probe: "process", params: { name: "x" } } });
    expect(ack.message).toContain("outcome=error");
    expect((enqueue.mock.calls[0] as any)[0].namespaces.live_query).toMatchObject({ outcome: "error", error: "timeout after 0 s" });
  });
});
