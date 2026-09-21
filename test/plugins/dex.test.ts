// test/plugins/dex.test.ts
//
// ADR-0030 F2 — la experiencia del equipo en el agente. Salidas REALES: el
// registro de eventos de Windows en XML, powercfg, ioreg de un MacBook con
// macOS actual, cabeceras .ips de DiagnosticReports (incluidas las simuladas),
// coredumpctl. Cada caso es una manera de mentir que hay que evitar.

import { describe, expect, it, vi } from "vitest";
import { DexWindowAggregator, cpuPercent, memPercentFromFree, parseVmStat, readCpuTimes } from "../../src/plugins/dex/dex-windows";
import {
  classifyMacReport,
  parseBatteryReportXml,
  parseCoredumpctlJson,
  parseIoregBattery,
  parseIpsTimestamp,
  parseWevtutilXml,
  readStabilityEvents,
  toStabilityEvent,
  type SourceDeps,
} from "../../src/plugins/dex/dex-sources";
import { DexCollector, type DexCollectorDeps } from "../../src/plugins/dex/dex-collector";

// ── Salidas reales ───────────────────────────────────────────────────

const APP_ERROR_W10 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Application Error'/><EventID Qualifiers='0'>1000</EventID><Version>0</Version><Level>2</Level><Task>100</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2026-09-20T15:04:11.2913467Z'/><EventRecordID>81234</EventRecordID><Correlation/><Execution ProcessID='0' ThreadID='0'/><Channel>Application</Channel><Computer>FINANZAS-03.acme.local</Computer><Security/></System><EventData><Data>OUTLOOK.EXE</Data><Data>16.0.17928.20156</Data><Data>66e1d3c4</Data><Data>mso20win32client.dll</Data><Data>0.0.0.0</Data><Data>66e1d0a1</Data><Data>c0000005</Data><Data>0000000000a1b2c3</Data><Data>2c48</Data><Data>01db0b3c</Data><Data>C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE</Data></EventData></Event>`;
const APP_ERROR_W11 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Application Error' Guid='{a0e9b465-b939-57d7-b27d-95d8e925ff57}'/><EventID>1000</EventID><TimeCreated SystemTime='2026-09-20T16:10:00.0000000Z'/><EventRecordID>81240</EventRecordID><Channel>Application</Channel></System><EventData><Data Name='AppName'>ms-teams.exe</Data><Data Name='AppVersion'>24.0.0.0</Data><Data Name='ModuleName'>ntdll.dll</Data><Data Name='ExceptionCode'>c0000409</Data></EventData></Event>`;
const APP_HANG = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Application Hang'/><EventID Qualifiers='0'>1002</EventID><TimeCreated SystemTime='2026-09-20T17:00:00.0000000Z'/><EventRecordID>81299</EventRecordID><Channel>Application</Channel></System><EventData><Data>EXCEL.EXE</Data><Data>16.0.17928.20156</Data></EventData></Event>`;
const BUGCHECK = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WER-SystemErrorReporting' Guid='{ABCE23E7-DE45-4366-8631-84FA6C525952}' EventSourceName='BugCheck'/><EventID Qualifiers='16384'>1001</EventID><TimeCreated SystemTime='2026-09-19T08:00:05.0000000Z'/><EventRecordID>5501</EventRecordID><Channel>System</Channel></System><EventData><Data Name='param1'>0x0000009f (0x0000000000000003, 0xffffc40f5a3b7060, 0xfffff8012c4a7850, 0xffffc40f62b7c8a0)</Data><Data Name='param2'>C:\\Windows\\Minidump\\091926-12453-01.dmp</Data><Data Name='param3'>7d3c1b9e-8b1f-4a55-9d2e-3a1c0f9e2b11</Data></EventData></Event>`;
const KP41 = (code: string, rec: string) =>
  `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Kernel-Power' Guid='{331c3b3a-2005-44c2-ac5e-77220c37d6b4}'/><EventID>41</EventID><TimeCreated SystemTime='2026-09-19T07:59:58.0000000Z'/><EventRecordID>${rec}</EventRecordID><Channel>System</Channel></System><EventData><Data Name='BugcheckCode'>${code}</Data><Data Name='BugcheckParameter1'>0x0</Data><Data Name='SleepInProgress'>0</Data><Data Name='PowerButtonTimestamp'>0</Data></EventData></Event>`;
const BOOT_100 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Diagnostics-Performance' Guid='{CFC18EC0-96B1-4EBA-961B-622CAEE05B0A}'/><EventID>100</EventID><TimeCreated SystemTime='2026-09-21T08:00:40.0000000Z'/><EventRecordID>912</EventRecordID><Channel>Microsoft-Windows-Diagnostics-Performance/Operational</Channel></System><EventData><Data Name='BootTsVersion'>2</Data><Data Name='BootStartTime'>2026-09-21T07:58:00.0000000Z</Data><Data Name='BootEndTime'>2026-09-21T08:00:40.0000000Z</Data><Data Name='BootTime'>160000</Data><Data Name='MainPathBootTime'>60000</Data></EventData></Event>`;

const BATTERY_REPORT = `<?xml version="1.0" encoding="utf-8"?><BatteryReport xmlns="http://schemas.microsoft.com/battery/2012"><ReportInformation/><Batteries><Battery><Id>DELL 7FHT</Id><Manufacturer>SMP</Manufacturer><SerialNumber>1234</SerialNumber><Chemistry>LiP</Chemistry><LongTerm>1</LongTerm><RelativeCapacity>0</RelativeCapacity><DesignCapacity>56002</DesignCapacity><FullChargeCapacity>32696</FullChargeCapacity><CycleCount>612</CycleCount></Battery></Batteries></BatteryReport>`;
const BATTERY_REPORT_DESKTOP = `<?xml version="1.0" encoding="utf-8"?><BatteryReport xmlns="http://schemas.microsoft.com/battery/2012"><Batteries/></BatteryReport>`;

// ioreg de un MacBook con macOS 27 (Apple Silicon): cifras dentro de BatteryData, sin espacios.
const IOREG_MODERN = `+-o AppleSmartBattery  <class AppleSmartBattery, id 0x1000004e2, registered, matched, active, busy 0 (0 ms), retain 7>
    {
      "BatteryData" = {"FullChargeCapacity"=7435,"NominalChargeCapacity"=7679,"FullyCharged"=1,"DesignCapacity"=8579,"CycleCount"=298}
      "MaxCapacity" = 100
      "CycleCount" = 298
    }`;
const IOREG_INTEL = `+-o AppleSmartBattery  <class AppleSmartBattery>
    {
      "DesignCapacity" = 6669
      "MaxCapacity" = 5500
      "CycleCount" = 830
    }`;

const IPS_REAL = `{"app_name":"node","timestamp":"2026-09-17 09:18:08.00 -0600","app_version":"","slice_uuid":"a1","build_version":"","platform":1,"share_with_app_devs":0,"is_first_party":0,"bug_type":"309","os_version":"macOS 27.0 (26A428)","roots_installed":0,"name":"node","incident_id":"B1"}`;
const IPS_SIMULATED = `{"is_simulated":1,"app_name":"textunderstandingd","timestamp":"2026-09-21 10:04:52.00 -0600","bug_type":"309","name":"textunderstandingd"}`;
const IPS_JETSAM = `{"bug_type":"298","timestamp":"2026-09-20 11:00:00.00 -0600"}`;

const VM_STAT = `Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                                     5427.
Pages active:                                 290838.
Pages inactive:                               288290.
Pages speculative:                              1287.
Pages throttled:                                   0.
Pages wired down:                             192020.
Pages purgeable:                               10609.`;

// ── Ventanas y muestras ──────────────────────────────────────────────

describe("muestras y ventanas", () => {
  it("CPU entre dos lecturas de os.cpus(), sin subprocesos", () => {
    const a = readCpuTimes([{ times: { user: 100, nice: 0, sys: 50, idle: 850, irq: 0 } }])!;
    const b = readCpuTimes([{ times: { user: 400, nice: 0, sys: 150, idle: 1450, irq: 0 } }])!;
    expect(cpuPercent(a, b)).toBe(40);
    // Contador reiniciado o sin avance: no se inventa un número.
    expect(cpuPercent(b, a)).toBeNull();
    expect(cpuPercent(null, b)).toBeNull();
  });

  it("⚠️ memoria en macOS por vm_stat: con os.freemem() un Mac sano parecería lleno", () => {
    const vm = parseVmStat(VM_STAT)!;
    expect(vm.availableBytes).toBe((5427 + 288290 + 1287 + 10609) * 16384);
    const total = 19327352832;
    expect(memPercentFromFree(vm.availableBytes, total)).toBeCloseTo(74.1, 0);
    // Lo que diría os.freemem() (sólo las libres): 99,5 % — falso.
    expect(memPercentFromFree(5427 * 16384, total)).toBeGreaterThan(99);
  });

  it("⭐ ventanas alineadas a su rejilla, media y pico, y el hueco de un equipo dormido NO se rellena", () => {
    const agg = new DexWindowAggregator();
    const t0 = Date.parse("2026-09-21T10:00:30Z");
    agg.add(t0, 20, 50);
    agg.add(t0 + 60_000, 80, 60);
    agg.add(t0 + 120_000, null, 70); // una lectura de CPU fallida no cuenta como 0
    // Dormido 40 min: la siguiente muestra cae en otra ventana.
    agg.add(Date.parse("2026-09-21T10:47:10Z"), 10, 40);
    agg.closeElapsed(Date.parse("2026-09-21T11:05:00Z"));
    expect(agg.pendingWindows()).toEqual([
      { startUtc: "2026-09-21T10:00:00.000Z", minutes: 15, samples: 3, cpuAvgPct: 50, cpuMaxPct: 80, memAvgPct: 60, memMaxPct: 70 },
      { startUtc: "2026-09-21T10:45:00.000Z", minutes: 15, samples: 1, cpuAvgPct: 10, cpuMaxPct: 10, memAvgPct: 40, memMaxPct: 40 },
    ]);
  });

  it("acknowledge quita sólo lo enviado; lo cerrado mientras tanto se queda", () => {
    const agg = new DexWindowAggregator();
    agg.add(Date.parse("2026-09-21T10:00:00Z"), 1, 1);
    agg.closeElapsed(Date.parse("2026-09-21T10:20:00Z"));
    const sent = agg.pendingWindows();
    agg.add(Date.parse("2026-09-21T10:20:00Z"), 2, 2);
    agg.closeElapsed(Date.parse("2026-09-21T10:40:00Z"));
    agg.acknowledge(sent);
    expect(agg.pendingWindows().map((w) => w.startUtc)).toEqual(["2026-09-21T10:15:00.000Z"]);
  });
});

// ── Windows ──────────────────────────────────────────────────────────

describe("Windows: registro de eventos en XML (sin texto traducido)", () => {
  it("⭐ crash de app con datos por posición (W10) y por nombre (W11); cuelgue; pantallazo con su código", () => {
    const app = parseWevtutilXml(APP_ERROR_W10 + APP_ERROR_W11 + APP_HANG, "Application").map(toStabilityEvent);
    expect(app).toEqual([
      { key: "Application:81234", kind: "app_crash", occurredAtUtc: "2026-09-20T15:04:11.291Z", app: "OUTLOOK.EXE", detail: "c0000005" },
      { key: "Application:81240", kind: "app_crash", occurredAtUtc: "2026-09-20T16:10:00.000Z", app: "ms-teams.exe", detail: "c0000409" },
      { key: "Application:81299", kind: "app_hang", occurredAtUtc: "2026-09-20T17:00:00.000Z", app: "EXCEL.EXE", detail: null },
    ]);
    const sys = parseWevtutilXml(BUGCHECK, "System").map(toStabilityEvent);
    expect(sys).toEqual([{ key: "System:5501", kind: "os_crash", occurredAtUtc: "2026-09-19T08:00:05.000Z", app: null, detail: "0x0000009f" }]);
  });

  it("⚠️ un pantallazo deja también un Kernel-Power 41 con bugcheck: no cuenta dos veces; sin bugcheck es apagado inesperado", () => {
    const ev = parseWevtutilXml(KP41("159", "5500") + KP41("0", "6100"), "System").map(toStabilityEvent);
    expect(ev).toEqual([null, { key: "System:6100", kind: "unexpected_shutdown", occurredAtUtc: "2026-09-19T07:59:58.000Z", app: null, detail: null }]);
  });

  it("un cursor por registro: Application al tope no hace saltar a System, y viceversa", async () => {
    const exec = vi.fn(async (_cmd: string, args: string[]) => {
      if (args[1] === "Application") return { code: 0, stdout: APP_ERROR_W10, stderr: "" };
      return { code: 0, stdout: BUGCHECK, stderr: "" };
    });
    const d = { platform: "win32", exec } as unknown as SourceDeps;
    const r = await readStabilityEvents(d, { System: "2026-09-18T00:00:00.000Z" }, "2026-09-14T00:00:00.000Z");
    expect(r.scope).toBe("collected");
    expect(r.cursors).toEqual({ Application: "2026-09-20T15:04:11.291Z", System: "2026-09-19T08:00:05.000Z" });
    // Cada registro pidió desde SU cursor (o el de por defecto).
    expect(exec.mock.calls[0][1][2]).toContain("@SystemTime>'2026-09-14T00:00:00.000Z'");
    expect(exec.mock.calls[1][1][2]).toContain("@SystemTime>'2026-09-18T00:00:00.000Z'");
    expect(exec.mock.calls[0][0]).toBe("wevtutil");
  });

  it("⚠️ si no se pudo leer ningún registro, scope unavailable (no «cero crashes»)", async () => {
    const d = { platform: "win32", exec: async () => ({ code: 5, stdout: "", stderr: "Access is denied." }) } as unknown as SourceDeps;
    expect(await readStabilityEvents(d, {}, "2026-09-14T00:00:00.000Z")).toMatchObject({ scope: "unavailable", events: [] });
  });

  it("arranque (Diagnostics-Performance 100) y batería (powercfg XML)", async () => {
    const e = parseWevtutilXml(BOOT_100, "Diagnostics-Performance")[0];
    expect(e.named.BootTime).toBe("160000");
    expect(parseBatteryReportXml(BATTERY_REPORT)).toEqual({ present: true, designCapacityMwh: 56002, fullChargeCapacityMwh: 32696, cycleCount: 612, healthPct: 58.38 });
    expect(parseBatteryReportXml(BATTERY_REPORT_DESKTOP)).toEqual({ present: false });
  });
});

// ── macOS ────────────────────────────────────────────────────────────

describe("macOS: DiagnosticReports e ioreg", () => {
  it("⚠️ los crashes SIMULADOS (is_simulated, ExcUserFault) no cuentan; los reales sí; Jetsam no es inestabilidad", () => {
    expect(classifyMacReport("node-2026-09-17-091808.ips", IPS_REAL, 0)).toEqual({ key: "node-2026-09-17-091808.ips", kind: "app_crash", occurredAtUtc: "2026-09-17T15:18:08.000Z", app: "node", detail: null });
    expect(classifyMacReport("ExcUserFault_textunderstandingd-2026-09-21-100452.ips", IPS_SIMULATED, 0)).toBeNull();
    expect(classifyMacReport("JetsamEvent-2026-09-20-110000.ips", IPS_JETSAM, 0)).toBeNull();
    expect(classifyMacReport("Google Chrome_2026-09-19-023027_JPR-MacBookPro.diag", null, 0)).toBeNull();
    expect(classifyMacReport("panic-full-2026-09-19-080000.panic", null, Date.parse("2026-09-19T08:00:00Z"))).toMatchObject({ kind: "os_crash" });
    expect(parseIpsTimestamp("2026-09-20 10:15:02.00 -0500")).toBe("2026-09-20T15:15:02.000Z");
  });

  it("⭐ los informes en Retired/ también se leen (macOS los mueve ahí al enviarlos)", async () => {
    const tree: Record<string, string[]> = {
      "/Users": ["ana"],
      "/Library/Logs/DiagnosticReports": [],
      "/Library/Logs/DiagnosticReports/Retired": [],
      "/Users/ana/Library/Logs/DiagnosticReports": ["ExcUserFault_textunderstandingd-2026-09-21-100452.ips"],
      "/Users/ana/Library/Logs/DiagnosticReports/Retired": ["node-2026-09-17-091808.ips"],
    };
    const files: Record<string, string> = {
      "/Users/ana/Library/Logs/DiagnosticReports/ExcUserFault_textunderstandingd-2026-09-21-100452.ips": IPS_SIMULATED,
      "/Users/ana/Library/Logs/DiagnosticReports/Retired/node-2026-09-17-091808.ips": IPS_REAL,
    };
    const d = {
      platform: "darwin",
      readDir: async (p: string) => {
        if (!(p in tree)) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
        return tree[p];
      },
      stat: async () => ({ mtimeMs: Date.parse("2026-09-21T11:00:00Z"), isFile: () => true }),
      readFile: async (p: string) => files[p],
    } as unknown as SourceDeps;
    const r = await readStabilityEvents(d, {}, "2026-09-14T00:00:00.000Z");
    expect(r.events.map((e) => e.app)).toEqual(["node"]);
    expect(r.scope).toBe("collected");
  });

  it("⚠️ ioreg de macOS actual: cifras dentro de BatteryData y sin espacios; salud = Nominal / Design", () => {
    expect(parseIoregBattery(IOREG_MODERN)).toEqual({ present: true, cycleCount: 298, healthPct: 89.51 });
    expect(parseIoregBattery(IOREG_INTEL)).toEqual({ present: true, cycleCount: 830, healthPct: 82.47 });
    expect(parseIoregBattery("")).toEqual({ present: false });
  });
});

// ── Linux ────────────────────────────────────────────────────────────

describe("Linux", () => {
  it("coredumpctl JSON: el ejecutable sin ruta y la señal", () => {
    expect(parseCoredumpctlJson(`[{"time":1726930000123456,"pid":1234,"uid":1000,"gid":1000,"sig":11,"corefile":"present","exe":"/usr/bin/gnome-shell","size":12345}]`)).toEqual([
      { key: "core:1726930000123456:1234", kind: "app_crash", occurredAtUtc: new Date(1726930000123).toISOString(), app: "gnome-shell", detail: "signal 11" },
    ]);
    expect(parseCoredumpctlJson("not json")).toEqual([]);
  });

  it("sin coredumpctl no se sabe (unsupported); «No coredumps found» es leído y vacío", async () => {
    const missing = { platform: "linux", exec: async () => { throw new Error("could not run coredumpctl (ENOENT)"); } } as unknown as SourceDeps;
    expect((await readStabilityEvents(missing, {}, "2026-09-14T00:00:00.000Z")).scope).toBe("unsupported");
    const none = { platform: "linux", exec: async () => ({ code: 1, stdout: "", stderr: "No coredumps found." }) } as unknown as SourceDeps;
    expect(await readStabilityEvents(none, {}, "2026-09-14T00:00:00.000Z")).toMatchObject({ scope: "collected", events: [] });
  });
});

// ── El colector ──────────────────────────────────────────────────────

function collector(over: Partial<DexCollectorDeps> = {}) {
  const state = new Map<string, string>();
  const sent: any[] = [];
  let now = Date.parse("2026-09-21T10:00:30Z");
  let cpu = { idle: 0, total: 0 };
  const deps: DexCollectorDeps = {
    enabled: () => true,
    nowMs: () => now,
    readCpu: () => {
      cpu = { idle: cpu.idle + 30, total: cpu.total + 100 };
      return cpu;
    },
    readMemPct: async () => 60,
    sources: {
      platform: "win32",
      exec: async (_c: string, args: string[]) =>
        args[1] === "Application" ? { code: 0, stdout: APP_ERROR_W10, stderr: "" } : args[1] === "System" ? { code: 0, stdout: "", stderr: "" } : args[0] === "qe" ? { code: 0, stdout: BOOT_100, stderr: "" } : { code: 0, stdout: "", stderr: "" },
      readFile: async () => BATTERY_REPORT,
      readDir: async () => [],
      stat: async () => ({ mtimeMs: 0, isFile: () => true }),
      tmpFile: () => "/tmp/x.xml",
      removeFile: async () => undefined,
      nowMs: () => now,
      uptimeSeconds: () => 3600,
    } as unknown as SourceDeps,
    getState: (k) => state.get(k) ?? null,
    setState: (k, v) => void state.set(k, v),
    enqueue: (p) => {
      sent.push(p);
      return sent.length;
    },
    ...over,
  };
  return { c: new DexCollector(deps), state, sent, tick: (ms: number) => (now += ms) };
}

describe("el colector", () => {
  it("⭐ el envío horario: ventanas cerradas, eventos, arranque y batería en el namespace dex, solo", async () => {
    const { c, sent, tick } = collector();
    for (let i = 0; i < 20; i++) {
      await c.sample();
      tick(60_000);
    }
    const payload = (await c.flush())!;
    expect(Object.keys(sent[0].namespaces)).toEqual(["dex"]);
    expect(payload.schema).toBe(1);
    // Sólo las CERRADAS: la de 10:15 sigue abierta y saldrá en el próximo envío.
    expect((payload.windows as any[]).map((w) => [w.startUtc, w.samples])).toEqual([["2026-09-21T10:00:00.000Z", 15]]);
    // La primera muestra no tiene lectura previa de CPU: no cuenta como 0.
    expect((payload.windows as any[])[0].cpuAvgPct).toBe(70);
    expect((payload.events as any[])[0]).toMatchObject({ kind: "app_crash", app: "OUTLOOK.EXE" });
    expect(payload.boot).toEqual({ bootUtc: "2026-09-21T07:58:00.000Z", durationMs: 160000 });
    expect(payload.battery).toMatchObject({ present: true, healthPct: 58.38 });
    expect(payload.scope).toEqual({ resources: "collected", events: "collected", boot: "collected", battery: "collected" });
  });

  it("⚠️ tras enviar: las ventanas salen de pendientes, el cursor avanza, el arranque no se repite, la batería espera un día", async () => {
    const { c, state, tick } = collector();
    await c.sample();
    tick(20 * 60_000);
    await c.sample();
    await c.flush();
    expect(JSON.parse(state.get("dex.pendingWindows")!)).toEqual([]);
    expect(JSON.parse(state.get("dex.cursors")!)).toMatchObject({ Application: "2026-09-20T15:04:11.291Z" });
    tick(60 * 60_000);
    const second = (await c.flush())!;
    expect(second.boot).toBeNull();
    expect(second.battery).toBeNull();
    expect((second.scope as any).battery).toBe("collected");
  });

  it("⭐ las ventanas cerradas sobreviven a un reinicio del agente (agent.db)", async () => {
    const first = collector();
    await first.c.sample();
    first.tick(20 * 60_000);
    await first.c.sample();
    const saved = first.state.get("dex.pendingWindows")!;
    expect(JSON.parse(saved)).toHaveLength(1);
    const again = collector({ getState: (k) => (k === "dex.pendingWindows" ? saved : null) });
    const payload = (await again.c.flush())!;
    expect((payload.windows as any[]).map((w) => w.startUtc)).toContain("2026-09-21T10:00:00.000Z");
  });

  it("sin AMP no se mide ni se envía", async () => {
    const { c, sent } = collector({ enabled: () => false });
    await c.sample();
    expect(await c.flush()).toBeNull();
    expect(sent).toHaveLength(0);
  });
});
