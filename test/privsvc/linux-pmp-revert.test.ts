// test/privsvc/linux-pmp-revert.test.ts
//
// pmp.revert en Linux: deshacer un fix volviendo al `state` que
// pmp.read_check_state leyó ANTES de aplicarlo. El agente relee el estado
// tras la llamada y exige que coincida con stateBefore; estos tests fijan
// que el revert restaura el valor EFECTIVO por la misma vía segura que el
// fix (backup + `sshd -t` antes de dejarlo puesto), que no se inventa un
// valor cuando la base cambió, y que un stateBefore inválido no toca nada.

import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import fs from "fs";

const execFileMock = vi.fn();
vi.mock("child_process", () => ({
  execFile: (...args: unknown[]) => execFileMock(...args),
}));

const family = { value: "debian" };
vi.mock("../../privsvc/linux/src/distro", () => ({
  detectFamily: () => ({ id: family.value === "debian" ? "ubuntu" : "rhel", family: family.value }),
}));

vi.mock("../../privsvc/linux/src/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import {
  handlePmpRevert,
  planFirewallRevert,
  planSshRevert,
  validateFirewallBefore,
  validateSshDirectiveBefore,
  validateSshKexBefore,
} from "../../privsvc/linux/src/pmp-remediation";

const DROPIN = "/etc/ssh/sshd_config.d/99-tracenium-hardening.conf";
const WEAK_KEX = ["curve25519-sha256", "diffie-hellman-group14-sha1", "ecdh-sha2-nistp256"];
const SAFE_KEX_IN_DROPIN =
  "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256";

// ── Equipo simulado ────────────────────────────────────────────────
// Ficheros bajo /etc/ssh en memoria; `sshd -T` = drop-in si tiene la
// directiva, si no la base (lo que diría el sshd_config principal).
let files: Map<string, string>;
let base: Record<string, string>;
let sshdTest: { code: number; stderr: string };
let firewall: { ufwActive: boolean; firewalldRunning: boolean };
let hang = false;

function effective(): Record<string, string> {
  const out = { ...base };
  const seen = new Set<string>();
  for (const line of (files.get(DROPIN) ?? "").split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const m = t.match(/^([^\s=]+)[\s=]+(.*)$/);
    if (!m) continue;
    const k = m[1].toLowerCase();
    if (seen.has(k)) continue; // sshd: gana la primera
    seen.add(k);
    out[k] = m[2].trim();
  }
  return out;
}

function answerCommands() {
  execFileMock.mockImplementation((cmd: string, args: string[], _opts: unknown, cb: Function) => {
    if (hang) return; // nunca responde: para el timeout
    const key = `${cmd} ${args.join(" ")}`;
    const ok = (stdout = "") => cb(null, { stdout, stderr: "" });
    const bad = (code: number, stderr: string) =>
      cb(Object.assign(new Error("exit"), { code, stdout: "", stderr }));
    switch (key) {
      case "/usr/sbin/sshd -T":
        return ok(["port 22", ...Object.entries(effective()).map(([k, v]) => `${k} ${v}`)].join("\n"));
      case "/usr/sbin/sshd -t":
        return sshdTest.code === 0 ? ok() : bad(sshdTest.code, sshdTest.stderr);
      case "/usr/bin/systemctl reload ssh.service":
      case "/usr/bin/systemctl reload sshd.service":
        return ok();
      case "/usr/sbin/ufw status":
        return ok(`Status: ${firewall.ufwActive ? "active" : "inactive"}\n`);
      case "/usr/sbin/ufw disable":
        firewall.ufwActive = false;
        return ok("Firewall stopped and disabled on system startup\n");
      case "/usr/bin/firewall-cmd --state":
        return firewall.firewalldRunning ? ok("running\n") : bad(252, "not running");
      case "/usr/bin/systemctl disable --now firewalld.service":
        firewall.firewalldRunning = false;
        return ok();
      default:
        return bad(127, `unexpected command: ${key}`);
    }
  });
}

const commandsRun = () => execFileMock.mock.calls.map((c) => `${c[0]} ${(c[1] as string[]).join(" ")}`);

function fakeFs() {
  const isOurs = (p: unknown) => String(p).startsWith("/etc/ssh/");
  const enoent = (p: unknown) => Object.assign(new Error(`ENOENT: ${p}`), { code: "ENOENT" });
  const real = {
    readFileSync: fs.readFileSync,
    existsSync: fs.existsSync,
    copyFileSync: fs.copyFileSync,
    chmodSync: fs.chmodSync,
    writeFileSync: fs.writeFileSync,
    renameSync: fs.renameSync,
    unlinkSync: fs.unlinkSync,
  };
  vi.spyOn(fs, "readFileSync").mockImplementation(((p: any, ...rest: any[]) => {
    if (!isOurs(p)) return (real.readFileSync as any)(p, ...rest);
    if (!files.has(String(p))) throw enoent(p);
    return files.get(String(p));
  }) as any);
  vi.spyOn(fs, "existsSync").mockImplementation((p: any) => (isOurs(p) ? files.has(String(p)) : real.existsSync(p)));
  vi.spyOn(fs, "copyFileSync").mockImplementation(((a: any, b: any) => {
    if (!files.has(String(a))) throw enoent(a);
    files.set(String(b), files.get(String(a))!);
  }) as any);
  vi.spyOn(fs, "chmodSync").mockImplementation((() => {}) as any);
  vi.spyOn(fs, "writeFileSync").mockImplementation(((p: any, data: any) => {
    files.set(String(p), String(data));
  }) as any);
  vi.spyOn(fs, "renameSync").mockImplementation(((a: any, b: any) => {
    if (!files.has(String(a))) throw enoent(a);
    files.set(String(b), files.get(String(a))!);
    files.delete(String(a));
  }) as any);
  vi.spyOn(fs, "unlinkSync").mockImplementation(((p: any) => {
    if (!files.delete(String(p))) throw enoent(p);
  }) as any);
}

const backups = () => [...files.keys()].filter((k) => k.endsWith(".bak"));

const req = (checkId: string, stateBefore: unknown, timeoutSeconds?: number) =>
  ({
    v: 1,
    id: "r1",
    method: "pmp.revert",
    params: { checkId, params: { stateBefore }, ...(timeoutSeconds ? { timeoutSeconds } : {}) },
  }) as any;

const sshBefore = (directive: string, current: string) => ({
  directive,
  current,
  expected: "no",
  sshdEffective: true,
});

beforeEach(() => {
  vi.restoreAllMocks();
  execFileMock.mockReset();
  family.value = "debian";
  hang = false;
  files = new Map();
  base = { permitrootlogin: "prohibit-password", passwordauthentication: "yes", kexalgorithms: WEAK_KEX.join(",") };
  sshdTest = { code: 0, stderr: "" };
  firewall = { ufwActive: true, firewalldRunning: true };
  answerCommands();
  fakeFs();
});

afterEach(() => {
  vi.useRealTimers();
});

// ── Planificador del drop-in (puro) ────────────────────────────────

describe("planSshRevert", () => {
  it("quita nuestra directiva y deja las demás", () => {
    // Lo que deja setDirective tras dos fixes.
    const content = "PermitRootLogin no\n\nPasswordAuthentication no\n";
    expect(planSshRevert(content, "PasswordAuthentication")).toEqual({ action: "write", content: "PermitRootLogin no\n" });
    expect(planSshRevert(content, "PermitRootLogin")).toEqual({ action: "write", content: "PasswordAuthentication no\n" });
  });

  it("si era la única directiva, el fichero sobra", () => {
    expect(planSshRevert("PermitRootLogin no\n", "PermitRootLogin")).toEqual({ action: "remove" });
    // Sólo comentarios no cuentan como configuración.
    expect(planSshRevert("# hand note\nPermitRootLogin no\n", "PermitRootLogin")).toEqual({ action: "remove" });
  });

  it("sin nuestra directiva no hay nada que quitar", () => {
    expect(planSshRevert("PasswordAuthentication no\n", "PermitRootLogin")).toEqual({ action: "noop" });
    expect(planSshRevert("", "PermitRootLogin")).toEqual({ action: "noop" });
    // La forma comentada no es la directiva.
    expect(planSshRevert("#PermitRootLogin no\n", "PermitRootLogin")).toEqual({ action: "noop" });
  });

  it("quita TODAS las apariciones, sin importar mayúsculas ni la forma Clave=valor", () => {
    const content = "permitrootlogin no\nKexAlgorithms a,b\nPERMITROOTLOGIN=no\n";
    expect(planSshRevert(content, "PermitRootLogin")).toEqual({ action: "write", content: "KexAlgorithms a,b\n" });
  });

  it("no confunde una directiva con otra que empieza igual", () => {
    expect(planSshRevert("PasswordAuthenticationX no\n", "PasswordAuthentication")).toEqual({ action: "noop" });
  });
});

// ── Validación de stateBefore (pura) ───────────────────────────────

describe("validateSshDirectiveBefore", () => {
  it("acepta el shape exacto de readSshDirective", () => {
    expect(validateSshDirectiveBefore(sshBefore("PermitRootLogin", "prohibit-password"), "PermitRootLogin")).toEqual({
      ok: true,
      value: { current: "prohibit-password" },
    });
  });

  it.each([
    ["no es objeto", "x"],
    ["otra directiva", sshBefore("PasswordAuthentication", "yes")],
    ["clave desconocida", { ...sshBefore("PermitRootLogin", "yes"), extra: 1 }],
    ["sin current (sshd -T no lo dio)", { directive: "PermitRootLogin", expected: "no", sshdEffective: true }],
    ["sshd -T fallaba", { ...sshBefore("PermitRootLogin", "yes"), sshdEffective: false }],
    ["current vacío", sshBefore("PermitRootLogin", " ")],
    ["current multilínea", sshBefore("PermitRootLogin", "yes\nPasswordAuthentication yes")],
    ["current no string", { ...sshBefore("PermitRootLogin", "yes"), current: 1 }],
    ["expected no string", { ...sshBefore("PermitRootLogin", "yes"), expected: false }],
  ])("rechaza: %s", (_label, sb) => {
    expect(validateSshDirectiveBefore(sb, "PermitRootLogin").ok).toBe(false);
  });
});

describe("validateSshKexBefore", () => {
  it("acepta el shape de readSshKex", () => {
    const sb = { current: WEAK_KEX, offenders: ["diffie-hellman-group14-sha1"], expectedNoMatch: "/x/i" };
    expect(validateSshKexBefore(sb)).toEqual({ ok: true, value: { current: WEAK_KEX } });
  });
  it.each([
    ["lista vacía (sshd -T no respondió)", { current: [], offenders: [] }],
    ["entradas no string", { current: ["a", 2] }],
    ["current como string", { current: "a,b" }],
    ["clave desconocida", { current: ["a"], directive: "KexAlgorithms" }],
    ["offenders no lista", { current: ["a"], offenders: "x" }],
  ])("rechaza: %s", (_label, sb) => {
    expect(validateSshKexBefore(sb).ok).toBe(false);
  });
});

describe("validateFirewallBefore + planFirewallRevert", () => {
  it("valida ufw / firewalld y rechaza lo demás", () => {
    expect(validateFirewallBefore({ impl: "ufw", active: false })).toEqual({ ok: true, value: { impl: "ufw", active: false } });
    expect(validateFirewallBefore({ impl: "firewalld", running: false }).ok).toBe(true);
    expect(validateFirewallBefore({ impl: "unknown", note: "unsupported family: suse" }).ok).toBe(false);
    expect(validateFirewallBefore({ impl: "ufw", active: "no" }).ok).toBe(false);
    expect(validateFirewallBefore({ impl: "ufw", running: false }).ok).toBe(false);
    expect(validateFirewallBefore({ impl: "ufw", active: false, rules: [] }).ok).toBe(false);
  });

  it("sólo apaga si antes estaba apagado", () => {
    expect(planFirewallRevert({ impl: "ufw", active: true }, "debian")).toEqual({ ok: true, value: [] });
    expect(planFirewallRevert({ impl: "ufw", active: false }, "debian")).toEqual({
      ok: true,
      value: [{ bin: "/usr/sbin/ufw", args: ["disable"], change: "ufw-disabled" }],
    });
    expect(planFirewallRevert({ impl: "firewalld", running: true }, "rhel")).toEqual({ ok: true, value: [] });
    expect(planFirewallRevert({ impl: "firewalld", running: false }, "rhel")).toEqual({
      ok: true,
      value: [{ bin: "/usr/bin/systemctl", args: ["disable", "--now", "firewalld.service"], change: "firewalld-disabled-and-stopped" }],
    });
  });

  it("no borra reglas de ufw: el plan no tiene ningún `ufw delete`", () => {
    const plan = planFirewallRevert({ impl: "ufw", active: false }, "debian");
    expect(plan.ok && plan.value.some((s) => s.args[0] === "delete")).toBe(false);
  });

  it("un stateBefore de otra familia no se aplica", () => {
    expect(planFirewallRevert({ impl: "ufw", active: false }, "rhel").ok).toBe(false);
    expect(planFirewallRevert({ impl: "firewalld", running: false }, "debian").ok).toBe(false);
  });
});

// ── handlePmpRevert (cableado, con equipo simulado) ────────────────

describe("handlePmpRevert — errores antes de tocar nada", () => {
  it("checkId sin revert → unsupported_check", async () => {
    const res = await handlePmpRevert(req("linux.ssh.x11_forwarding_disabled", { current: "yes" }));
    expect(res.ok).toBe(false);
    expect(res.error?.code).toBe("unsupported_check");
    expect(commandsRun()).toEqual([]);
  });

  it("sin checkId → bad_request", async () => {
    const res = await handlePmpRevert(req("", {}));
    expect(res.error?.code).toBe("bad_request");
  });

  it.each([
    ["sin stateBefore", undefined],
    ["stateBefore lista", [1]],
    ["stateBefore null", null],
  ])("%s → bad_request", async (_label, sb) => {
    const res = await handlePmpRevert(req("linux.ssh.root_login_disabled", sb));
    expect(res.error?.code).toBe("bad_request");
    expect(commandsRun()).toEqual([]);
  });

  it("stateBefore de otro check → bad_request y el drop-in intacto", async () => {
    files.set(DROPIN, "PermitRootLogin no\n");
    const res = await handlePmpRevert(req("linux.ssh.root_login_disabled", sshBefore("PasswordAuthentication", "yes")));
    expect(res.error?.code).toBe("bad_request");
    expect(commandsRun()).toEqual([]);
    expect(files.get(DROPIN)).toBe("PermitRootLogin no\n");
  });

  it("firewall con stateBefore de ufw en un RHEL → bad_request", async () => {
    family.value = "rhel";
    const res = await handlePmpRevert(req("linux.firewall.enabled", { impl: "ufw", active: false }));
    expect(res.error?.code).toBe("bad_request");
    expect(commandsRun()).toEqual([]);
  });
});

describe("handlePmpRevert — SSH", () => {
  it("⭐ quita nuestra directiva, valida ANTES de recargar, y el efectivo vuelve al de antes", async () => {
    files.set(DROPIN, "PermitRootLogin no\n\nPasswordAuthentication no\n");

    const res = await handlePmpRevert(req("linux.ssh.root_login_disabled", sshBefore("PermitRootLogin", "prohibit-password")));

    expect(res.ok).toBe(true);
    expect(res.result).toMatchObject({
      exitCode: 0,
      stderrExcerpt: null,
      requiresReboot: false,
      changesApplied: ["PermitRootLogin-unset", "sshd-reloaded"],
    });
    expect(files.get(DROPIN)).toBe("PasswordAuthentication no\n");
    expect(backups()).toHaveLength(1);
    expect(commandsRun()).toEqual([
      "/usr/sbin/sshd -T",
      "/usr/sbin/sshd -t",
      "/usr/bin/systemctl reload ssh.service",
      "/usr/sbin/sshd -T",
    ]);
    expect(effective().permitrootlogin).toBe("prohibit-password");
  });

  it("si era la única directiva borra el drop-in (y valida igual)", async () => {
    files.set(DROPIN, "PasswordAuthentication no\n");

    const res = await handlePmpRevert(req("linux.ssh.password_auth_disabled", sshBefore("PasswordAuthentication", "yes")));

    expect(res.result).toMatchObject({ exitCode: 0, changesApplied: ["PasswordAuthentication-unset", "dropin-removed", "sshd-reloaded"] });
    expect(files.has(DROPIN)).toBe(false);
    expect(commandsRun()).toContain("/usr/sbin/sshd -t");
  });

  it("⭐ si la base cambió desde el fix NO se inventa el valor: queda quitada y exitCode 1", async () => {
    files.set(DROPIN, "PermitRootLogin no\n");
    base.permitrootlogin = "yes"; // alguien tocó sshd_config después del fix

    const res = await handlePmpRevert(req("linux.ssh.root_login_disabled", sshBefore("PermitRootLogin", "prohibit-password")));

    expect(res.ok).toBe(true);
    expect(res.result.exitCode).toBe(1);
    expect(res.result.stderrExcerpt).toMatch(/effective value is yes.*expected prohibit-password.*not overwriting/);
    expect(files.has(DROPIN)).toBe(false);
    // Nada con «prohibit-password» escrito por nosotros.
    for (const [k, v] of files) if (!k.endsWith(".bak")) expect(v).not.toMatch(/prohibit-password/);
  });

  it("si sshd -t rechaza, restaura el drop-in y no recarga", async () => {
    files.set(DROPIN, "PermitRootLogin no\n\nPasswordAuthentication no\n");
    sshdTest = { code: 255, stderr: "/etc/ssh/sshd_config line 9: Bad configuration option" };

    const res = await handlePmpRevert(req("linux.ssh.root_login_disabled", sshBefore("PermitRootLogin", "prohibit-password")));

    expect(res.result.exitCode).toBe(1);
    expect(res.result.changesApplied).toEqual([]);
    expect(res.result.stderrExcerpt).toMatch(/Bad configuration option/);
    expect(files.get(DROPIN)).toBe("PermitRootLogin no\n\nPasswordAuthentication no\n");
    expect(commandsRun().some((c) => c.includes("reload"))).toBe(false);
  });

  it("si al borrar el fichero sshd -t rechaza, lo repone", async () => {
    files.set(DROPIN, "PermitRootLogin no\n");
    sshdTest = { code: 255, stderr: "bad" };

    const res = await handlePmpRevert(req("linux.ssh.root_login_disabled", sshBefore("PermitRootLogin", "prohibit-password")));

    expect(res.result.exitCode).toBe(1);
    expect(files.get(DROPIN)).toBe("PermitRootLogin no\n");
  });

  it("ya está como antes → no toca nada", async () => {
    files.set(DROPIN, "PermitRootLogin no\n");
    // El fix fue no-op: nuestra directiva venía de un fix anterior.
    const res = await handlePmpRevert(req("linux.ssh.root_login_disabled", sshBefore("PermitRootLogin", "no")));

    expect(res.result).toMatchObject({ exitCode: 0, changesApplied: [] });
    expect(files.get(DROPIN)).toBe("PermitRootLogin no\n");
    expect(commandsRun()).toEqual(["/usr/sbin/sshd -T"]);
  });

  it("nuestra directiva no está y el valor difiere → exitCode 1 sin escribir nada", async () => {
    base.permitrootlogin = "no"; // lo cambió el operador en sshd_config, no nosotros

    const res = await handlePmpRevert(req("linux.ssh.root_login_disabled", sshBefore("PermitRootLogin", "yes")));

    expect(res.result.exitCode).toBe(1);
    expect(res.result.stderrExcerpt).toMatch(/not set by Tracenium/);
    expect(files.size).toBe(0);
    expect(commandsRun()).toEqual(["/usr/sbin/sshd -T"]);
  });

  it("KEX: quita KexAlgorithms y compara como conjunto (orden distinto = igual)", async () => {
    files.set(DROPIN, `PermitRootLogin no\n\nKexAlgorithms ${SAFE_KEX_IN_DROPIN}\n`);
    const shuffled = [...WEAK_KEX].reverse();

    const res = await handlePmpRevert(
      req("linux.cryptography.weak_ssh_kex_disabled", {
        current: shuffled,
        offenders: ["diffie-hellman-group14-sha1"],
        expectedNoMatch: "/(group1-sha1|group14-sha1|group-exchange-sha1|.+-sha1$)/i",
      })
    );

    expect(res.result).toMatchObject({ exitCode: 0, changesApplied: ["KexAlgorithms-unset", "sshd-reloaded"] });
    expect(files.get(DROPIN)).toBe("PermitRootLogin no\n");
  });
});

describe("handlePmpRevert — firewall", () => {
  it("⭐ antes estaba inactivo → `ufw disable`, sin tocar reglas", async () => {
    const res = await handlePmpRevert(req("linux.firewall.enabled", { impl: "ufw", active: false }));

    expect(res.result).toMatchObject({ exitCode: 0, changesApplied: ["ufw-disabled"] });
    expect(commandsRun()).toEqual(["/usr/sbin/ufw status", "/usr/sbin/ufw disable", "/usr/sbin/ufw status"]);
    expect(firewall.ufwActive).toBe(false);
  });

  it("antes ya estaba activo → nada que deshacer, ningún comando", async () => {
    const res = await handlePmpRevert(req("linux.firewall.enabled", { impl: "ufw", active: true }));

    expect(res.result).toMatchObject({ exitCode: 0, changesApplied: [] });
    expect(commandsRun()).toEqual([]);
    expect(firewall.ufwActive).toBe(true);
  });

  it("firewalld parado antes → disable --now", async () => {
    family.value = "rhel";
    const res = await handlePmpRevert(req("linux.firewall.enabled", { impl: "firewalld", running: false }));

    expect(res.result).toMatchObject({ exitCode: 0, changesApplied: ["firewalld-disabled-and-stopped"] });
    expect(firewall.firewalldRunning).toBe(false);
  });
});

describe("handlePmpRevert — timeout", () => {
  it("si no termina en timeoutSeconds → revert_timeout", async () => {
    vi.useFakeTimers();
    hang = true;
    files.set(DROPIN, "PermitRootLogin no\n");

    const pending = handlePmpRevert(req("linux.ssh.root_login_disabled", sshBefore("PermitRootLogin", "yes"), 5));
    await vi.advanceTimersByTimeAsync(5_000);
    const res = await pending;

    expect(res.ok).toBe(false);
    expect(res.error?.code).toBe("revert_timeout");
  });
});
