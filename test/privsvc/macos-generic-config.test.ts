// test/privsvc/macos-generic-config.test.ts
//
// `macos.config.set_value`. Mac simulado: /Library/Preferences en memoria
// (lo que devuelve `defaults`), lo que ve una app (osascript) con los
// valores que impone un perfil, pmset y launchctl. Lo que importa: sólo se
// escriben las claves que macOS respeta en local, un perfil que manda se
// dice, y lo guardado no pasa aunque lo pida el backend.

import { describe, it, expect, beforeEach } from "vitest";
import { applyGeneric, readGenericState, parseWrites, type MacGenericDeps } from "../../privsvc/macos/src/generic-config";

let local: Map<string, { type: string; value: string }>;
let forced: Map<string, unknown>;
let pmset: Record<string, number>;
let loaded: Set<string>;
let files: Set<string>;
let calls: string[];

const deps = (): MacGenericDeps => ({
  exists: (p) => files.has(p),
  copyFile: (_s, d) => void files.add(d),
  exec: async (bin, args) => {
    calls.push([bin, ...args].join(" "));
    const ok = (stdout = "") => ({ stdout, stderr: "", code: 0 });
    if (bin === "/usr/bin/defaults") {
      const [verb, file, key, type, value] = args;
      const id = `${file.replace("/Library/Preferences/", "")}:${key}`;
      if (verb === "read-type") return local.has(id) ? ok(`Type is ${local.get(id)!.type}\n`) : { stdout: "", stderr: "does not exist", code: 1 };
      if (verb === "read") return local.has(id) ? ok(local.get(id)!.value + "\n") : { stdout: "", stderr: "does not exist", code: 1 };
      if (verb === "write") {
        local.set(id, { type: type === "-bool" ? "boolean" : type === "-int" ? "integer" : "string", value: type === "-bool" ? (value === "true" ? "1" : "0") : value });
        return ok();
      }
      if (verb === "delete") return local.delete(id) ? ok() : { stdout: "", stderr: "not found", code: 1 };
    }
    if (bin === "/usr/bin/osascript") {
      const pairs: Array<[string, string]> = JSON.parse(/var pairs = (\[.*\]);/.exec(args[3])![1]);
      const v: Record<string, unknown> = {};
      const f: Record<string, boolean> = {};
      for (const [s, k] of pairs) {
        const id = `${s}:${k}`;
        if (forced.has(id)) { v[id] = forced.get(id); f[id] = true; continue; }
        const l = local.get(id);
        v[id] = l ? (l.type === "boolean" ? l.value === "1" : l.type === "integer" ? Number(l.value) : l.value) : null;
        f[id] = false;
      }
      return ok(JSON.stringify({ v, f }));
    }
    if (bin === "/usr/bin/pmset") {
      if (args[0] === "-g") return ok("Battery Power:\n" + Object.entries(pmset).map(([k, v]) => ` ${k} ${v}`).join("\n") + "\nAC Power:\n" + Object.entries(pmset).map(([k, v]) => ` ${k} ${v}`).join("\n") + "\n");
      pmset[args[1]] = Number(args[2]);
      return ok();
    }
    if (bin === "/bin/launchctl") {
      if (args[0] === "list") return ok("PID\tStatus\tLabel\n" + [...loaded].map((l) => `1\t0\t${l}`).join("\n") + "\n");
      if (args[0] === "bootstrap") { const label = /\/([^/]+)\.plist$/.exec(args[2])![1]; if (loaded.has(label)) return { stdout: "", stderr: "already loaded", code: 5 }; loaded.add(label); return ok(); }
      if (args[0] === "bootout") { loaded.delete(args[1].replace("system/", "")); return ok(); }
      return ok();
    }
    return { stdout: "", stderr: "unknown", code: 1 };
  },
});

beforeEach(() => {
  local = new Map([["com.apple.loginwindow:RetriesUntilHint", { type: "integer", value: "3" }]]);
  forced = new Map();
  pmset = { womp: 1, powernap: 1 };
  loaded = new Set(["com.apple.smbd"]);
  files = new Set(["/etc/security/audit_control.example"]);
  calls = [];
});

const w = (...writes: any[]) => ({ writes });

describe("parseWrites — la lista cerrada se repite aquí", () => {
  it("nunca una clave que sólo cumple un perfil", () => {
    expect(parseWrites(w({ kind: "macpref", domain: "com.apple.applicationaccess", key: "allowAirDrop", value: false })).ok).toBe(false);
    expect(parseWrites(w({ kind: "macpref", domain: "com.apple.loginwindow", key: "LoginHook", value: "/tmp/x.sh" })).ok).toBe(false);
  });
  it("desactivar File/Screen Sharing es la guarda; reactivarlos (revert) no", () => {
    expect(parseWrites(w({ kind: "launchd", label: "com.apple.screensharing", enabled: false }))).toMatchObject({ ok: false, message: expect.stringMatching(/guarded/) });
    expect(parseWrites(w({ kind: "launchd", label: "com.apple.smbd", enabled: true })).ok).toBe(true);
  });
  it("valores raros, pmset fuera de la lista, servicios desconocidos", () => {
    expect(parseWrites(w({ kind: "macpref", domain: "com.apple.loginwindow", key: "SHOWFULLNAME", value: { a: 1 } })).ok).toBe(false);
    expect(parseWrites(w({ kind: "macpref", domain: "com.apple.loginwindow", key: "SHOWFULLNAME", value: "a\nb" })).ok).toBe(false);
    expect(parseWrites(w({ kind: "pmset", key: "sleep", value: 0 })).ok).toBe(false);
    expect(parseWrites(w({ kind: "launchd", label: "com.apple.sshd", enabled: false })).ok).toBe(false);
  });
});

describe("aplicar", () => {
  it("defaults write en /Library/Preferences, y queda conforme", async () => {
    const payload = w({ kind: "macpref", domain: "com.apple.loginwindow", key: "SHOWFULLNAME", value: true }, { kind: "macpref", domain: "com.apple.loginwindow", key: "RetriesUntilHint", value: 0 });
    const r = await applyGeneric(payload, deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(calls).toContain("/usr/bin/defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true");
    expect(calls).toContain("/usr/bin/defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0");
    expect(await readGenericState(payload, deps())).toMatchObject({ ok: true, value: { isCompliant: true } });
  });

  it("⚠️ un perfil del cliente que fija la clave a otro valor se dice, no se da por aplicado", async () => {
    forced.set("com.apple.loginwindow:SHOWFULLNAME", false);
    const r = await applyGeneric(w({ kind: "macpref", domain: "com.apple.loginwindow", key: "SHOWFULLNAME", value: true }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 1 } });
    expect((r as any).value.stderrExcerpt).toMatch(/a configuration profile sets com.apple.loginwindow SHOWFULLNAME to false/);
  });

  it("borrar autoLoginUser; borrar lo que no existe también vale", async () => {
    local.set("com.apple.loginwindow:autoLoginUser", { type: "string", value: "ana" });
    const payload = w({ kind: "macpref", domain: "com.apple.loginwindow", key: "autoLoginUser", value: null });
    expect(await applyGeneric(payload, deps())).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(local.has("com.apple.loginwindow:autoLoginUser")).toBe(false);
    expect(await applyGeneric(payload, deps())).toMatchObject({ ok: true, value: { exitCode: 0 } });
  });

  it("pmset -a", async () => {
    const r = await applyGeneric(w({ kind: "pmset", key: "womp", value: 0 }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(calls).toContain("/usr/bin/pmset -a womp 0");
  });

  it("auditd: crea audit_control desde el ejemplo (CIS 3.1) y lo carga", async () => {
    const r = await applyGeneric(w({ kind: "launchd", label: "com.apple.auditd", enabled: true }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(files.has("/etc/security/audit_control")).toBe(true);
    expect(calls).toContain("/bin/launchctl enable system/com.apple.auditd");
    expect(calls).toContain("/bin/launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.auditd.plist");
  });
});

describe("estado para el revert", () => {
  it("dice si la clave existía y con qué valor tipado", async () => {
    const s = await readGenericState(
      w({ kind: "macpref", domain: "com.apple.loginwindow", key: "RetriesUntilHint", value: 0 }, { kind: "macpref", domain: "com.apple.loginwindow", key: "SHOWFULLNAME", value: true }, { kind: "pmset", key: "womp", value: 0 }, { kind: "launchd", label: "com.apple.smbd", enabled: true }),
      deps()
    );
    expect(s.ok && s.value.state.writes).toEqual([
      { kind: "macpref", domain: "com.apple.loginwindow", key: "RetriesUntilHint", present: true, value: 3, effective: 3, forced: false },
      { kind: "macpref", domain: "com.apple.loginwindow", key: "SHOWFULLNAME", present: false, value: null, effective: null, forced: false },
      { kind: "pmset", key: "womp", value: 1 },
      { kind: "launchd", label: "com.apple.smbd", loaded: true },
    ]);
  });
});
