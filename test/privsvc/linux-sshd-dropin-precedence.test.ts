// test/privsvc/linux-sshd-dropin-precedence.test.ts
//
// sshd_config(5): «for each keyword, the first obtained value will be
// used», y el glob de `Include` se procesa «in lexical order». El fix de
// SSH escribía en 99-tracenium-hardening.conf creyendo que el último
// ganaba: en una imagen cloud de Ubuntu el 50-cloud-init.conf
// (`PasswordAuthentication yes`) se leía antes y el fix nunca surtía
// efecto (failed/post_state_mismatch sin explicación).
//
// Estos tests fijan: el drop-in es el 00-; la migración desde el 99- va
// directiva a directiva; tras el fix se comprueba el EFECTIVO y, si otro
// fichero manda, se dice cuál y en qué línea; y el revert quita la
// directiva de los dos ficheros. El equipo simulado aplica la regla de
// sshd de verdad (primer valor, drop-ins en orden de bytes), así que un
// 99- que «gana» aquí no puede colarse.

import { beforeEach, describe, expect, it, vi } from "vitest";
import fs from "fs";

const execFileMock = vi.fn();
vi.mock("child_process", () => ({
  execFile: (...args: unknown[]) => execFileMock(...args),
}));

vi.mock("../../privsvc/linux/src/distro", () => ({
  detectFamily: () => ({ id: "ubuntu", family: "debian" }),
}));

vi.mock("../../privsvc/linux/src/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import {
  explainSshdOverride,
  handlePmpRemediate,
  handlePmpRevert,
  planSshDropinChanges,
  sshdEarlierDefinitions,
} from "../../privsvc/linux/src/pmp-remediation";

const DIR = "/etc/ssh/sshd_config.d";
const MAIN = "/etc/ssh/sshd_config";
const OURS = `${DIR}/00-tracenium-hardening.conf`;
const LEGACY = `${DIR}/99-tracenium-hardening.conf`;
const CLOUD_INIT = `${DIR}/50-cloud-init.conf`;
const UBUNTU_MAIN = "Include /etc/ssh/sshd_config.d/*.conf\n\nKbdInteractiveAuthentication no\nUsePAM yes\nSubsystem sftp /usr/lib/openssh/sftp-server\n";
const WEAK_KEX = "curve25519-sha256,diffie-hellman-group14-sha1,ecdh-sha2-nistp256";

// ── Equipo simulado: sshd de verdad en lo que importa ──────────────
let files: Map<string, string>;
let sshdTest: { code: number; stderr: string };

const DEFAULTS: Record<string, string> = {
  permitrootlogin: "prohibit-password",
  passwordauthentication: "yes",
  kexalgorithms: WEAK_KEX,
};

function effective(): Record<string, string> {
  const out: Record<string, string> = {};
  const read = (content: string, top: boolean): boolean => {
    for (const line of content.split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const m = t.match(/^([^\s=]+)[\s=]+(.*)$/);
      if (!m) continue;
      const k = m[1].toLowerCase();
      if (k === "match") return false;
      if (k === "include" && top) {
        // Orden de bytes, *.conf, sin dotfiles: lo que hace el glob de sshd.
        const names = [...files.keys()]
          .filter((f) => f.startsWith(`${DIR}/`) && f.endsWith(".conf") && !f.slice(DIR.length + 1).includes("/"))
          .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
        for (const n of names) read(files.get(n)!, false);
        continue;
      }
      if (!(k in out)) out[k] = m[2].trim(); // gana la PRIMERA
    }
    return true;
  };
  read(files.get(MAIN) ?? "", true);
  return { ...DEFAULTS, ...out };
}

function answerCommands() {
  execFileMock.mockImplementation((cmd: string, args: string[], _opts: unknown, cb: Function) => {
    const key = `${cmd} ${args.join(" ")}`;
    const ok = (stdout = "") => cb(null, { stdout, stderr: "" });
    const bad = (code: number, stderr: string) => cb(Object.assign(new Error("exit"), { code, stdout: "", stderr }));
    switch (key) {
      case "/usr/sbin/sshd -T":
        return ok(["port 22", ...Object.entries(effective()).map(([k, v]) => `${k} ${v}`)].join("\n"));
      case "/usr/sbin/sshd -t":
        return sshdTest.code === 0 ? ok() : bad(sshdTest.code, sshdTest.stderr);
      case "/usr/bin/systemctl reload ssh.service":
        return ok();
      default:
        return bad(127, `unexpected command: ${key}`);
    }
  });
}

const commandsRun = () => execFileMock.mock.calls.map((c) => `${c[0]} ${(c[1] as string[]).join(" ")}`);

function fakeFs() {
  const isOurs = (p: unknown) => String(p).startsWith("/etc/ssh");
  const enoent = (p: unknown) => Object.assign(new Error(`ENOENT: ${p}`), { code: "ENOENT" });
  const real = { readFileSync: fs.readFileSync, existsSync: fs.existsSync, readdirSync: fs.readdirSync };
  vi.spyOn(fs.promises, "mkdir").mockResolvedValue(undefined);
  vi.spyOn(fs, "readFileSync").mockImplementation(((p: any, ...rest: any[]) => {
    if (!isOurs(p)) return (real.readFileSync as any)(p, ...rest);
    if (!files.has(String(p))) throw enoent(p);
    return files.get(String(p));
  }) as any);
  vi.spyOn(fs, "readdirSync").mockImplementation(((p: any, ...rest: any[]) => {
    if (!isOurs(p)) return (real.readdirSync as any)(p, ...rest);
    const prefix = `${String(p)}/`;
    return [...files.keys()].filter((f) => f.startsWith(prefix)).map((f) => f.slice(prefix.length));
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

const remediate = (checkId: string) =>
  handlePmpRemediate({ v: 1, id: "r1", method: "pmp.remediate", params: { checkId } } as any);

const revert = (checkId: string, stateBefore: unknown) =>
  handlePmpRevert({ v: 1, id: "r2", method: "pmp.revert", params: { checkId, params: { stateBefore } } } as any);

const liveFiles = () => [...files.keys()].filter((k) => !k.endsWith(".bak")).sort();

beforeEach(() => {
  vi.restoreAllMocks();
  execFileMock.mockReset();
  files = new Map([[MAIN, UBUNTU_MAIN]]);
  sshdTest = { code: 0, stderr: "" };
  answerCommands();
  fakeFs();
});

// ── Planificador de cambios (puro) ─────────────────────────────────

describe("planSshDropinChanges", () => {
  it("un fix nuevo escribe en el 00-", () => {
    expect(planSshDropinChanges({ primary: "", legacy: "" }, "PasswordAuthentication", "no")).toEqual([
      { file: OURS, oldContent: "", newContent: "PasswordAuthentication no\n" },
    ]);
  });

  it("⭐ migra del 99- SÓLO la directiva del fix; las demás se quedan donde estaban", () => {
    // Mover todo el 99- haría efectivo, en este job, un `PermitRootLogin`
    // que nadie ha pedido ahora.
    const legacy = "PermitRootLogin no\n\nPasswordAuthentication no\n";
    expect(planSshDropinChanges({ primary: "", legacy }, "PasswordAuthentication", "no")).toEqual([
      { file: OURS, oldContent: "", newContent: "PasswordAuthentication no\n" },
      { file: LEGACY, oldContent: legacy, newContent: "PermitRootLogin no\n" },
    ]);
  });

  it("el 99- se borra cuando se queda sin directivas", () => {
    expect(planSshDropinChanges({ primary: "", legacy: "PasswordAuthentication no\n" }, "PasswordAuthentication", "no")).toEqual([
      { file: OURS, oldContent: "", newContent: "PasswordAuthentication no\n" },
      { file: LEGACY, oldContent: "PasswordAuthentication no\n", newContent: null },
    ]);
  });

  it("ya aplicado en el 00- y nada en el 99- → sin cambios (idempotente)", () => {
    expect(planSshDropinChanges({ primary: "PasswordAuthentication no\n", legacy: "PermitRootLogin no\n" }, "PasswordAuthentication", "no")).toEqual([]);
  });

  it("revert (value null) la quita de los DOS ficheros", () => {
    expect(
      planSshDropinChanges({ primary: "PermitRootLogin no\n\nKexAlgorithms x\n", legacy: "PermitRootLogin no\n" }, "PermitRootLogin", null)
    ).toEqual([
      { file: OURS, oldContent: "PermitRootLogin no\n\nKexAlgorithms x\n", newContent: "KexAlgorithms x\n" },
      { file: LEGACY, oldContent: "PermitRootLogin no\n", newContent: null },
    ]);
    expect(planSshDropinChanges({ primary: "", legacy: "" }, "PermitRootLogin", null)).toEqual([]);
  });
});

// ── Quién fija la directiva antes que nosotros (puro) ──────────────

describe("sshdEarlierDefinitions", () => {
  const d = (name: string, content: string) => ({ name, content });

  it("⭐ 50-cloud-init.conf se lee antes que un 99- … y después del 00-", () => {
    const p = sshdEarlierDefinitions(UBUNTU_MAIN, [d("50-cloud-init.conf", "PasswordAuthentication yes\n"), d("00-tracenium-hardening.conf", "PasswordAuthentication no\n")], "PasswordAuthentication");
    expect(p).toEqual({ dropinIncluded: true, earlier: [] });
  });

  it("un drop-in que ordena antes que el nuestro (byte a byte) se señala con fichero y línea", () => {
    const p = sshdEarlierDefinitions(
      UBUNTU_MAIN,
      [
        d("99-other.conf", "PasswordAuthentication yes\n"),
        d("00-aaa.conf", "# local\nPasswordAuthentication=yes\n"),
        d("0-x.conf", "passwordauthentication \"yes\"\n"), // «-» < «0»: va antes que «00-»
        d(".hidden.conf", "PasswordAuthentication yes\n"), // el glob no casa dotfiles
        d("00-a.conf.bak", "PasswordAuthentication yes\n"), // ni lo que no acaba en .conf
      ],
      "PasswordAuthentication"
    );
    expect(p).toEqual({
      dropinIncluded: true,
      earlier: [
        { source: `${DIR}/0-x.conf`, line: 1, value: "yes" },
        { source: `${DIR}/00-aaa.conf`, line: 2, value: "yes" },
      ],
    });
  });

  it("una directiva en sshd_config ANTES del Include gana; después, no", () => {
    const main = "PasswordAuthentication yes\nInclude /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n";
    expect(sshdEarlierDefinitions(main, [], "PasswordAuthentication").earlier).toEqual([{ source: MAIN, line: 1, value: "yes" }]);
    expect(sshdEarlierDefinitions(main, [], "PermitRootLogin").earlier).toEqual([]);
  });

  it("Include relativo (a /etc/ssh) también cuenta", () => {
    expect(sshdEarlierDefinitions("Include sshd_config.d/*.conf\n", [], "PermitRootLogin").dropinIncluded).toBe(true);
  });

  it("sin Include de sshd_config.d (o sólo dentro de un Match) nuestro drop-in no se lee", () => {
    expect(sshdEarlierDefinitions("PermitRootLogin yes\n", [], "PermitRootLogin")).toEqual({
      dropinIncluded: false,
      earlier: [{ source: MAIN, line: 1, value: "yes" }],
    });
    expect(sshdEarlierDefinitions("Match User x\n  Include /etc/ssh/sshd_config.d/*.conf\n", [], "PermitRootLogin").dropinIncluded).toBe(false);
  });

  it("lo que va tras un Match en un drop-in es condicional: no se cuenta", () => {
    const p = sshdEarlierDefinitions(UBUNTU_MAIN, [d("00-aaa.conf", "Match User deploy\n  PasswordAuthentication yes\n")], "PasswordAuthentication");
    expect(p.earlier).toEqual([]);
  });
});

describe("explainSshdOverride", () => {
  it("el culpable va dentro de los primeros 200 caracteres (el agente corta el reason ahí)", () => {
    const msg = explainSshdOverride("KexAlgorithms", "a".repeat(600), {
      dropinIncluded: true,
      earlier: [{ source: `${DIR}/10-crypto.conf`, line: 3, value: "diffie-hellman-group1-sha1" }],
    });
    expect(`post_state_mismatch: ${msg}`.slice(0, 200)).toContain(`${DIR}/10-crypto.conf:3`);
  });
});

// ── pmp.remediate con el equipo simulado ───────────────────────────

describe("handlePmpRemediate — SSH y la precedencia de sshd", () => {
  it("⭐ Ubuntu cloud: el fix gana al 50-cloud-init.conf (antes se quedaba en `yes`)", async () => {
    files.set(CLOUD_INIT, "PasswordAuthentication yes\n");

    const res = await remediate("linux.ssh.password_auth_disabled");

    expect(res.ok).toBe(true);
    expect(res.result).toMatchObject({ exitCode: 0, stderrExcerpt: null, changesApplied: ["PasswordAuthentication=no", "sshd-reloaded"] });
    expect(files.get(OURS)).toBe("PasswordAuthentication no\n");
    expect(files.get(CLOUD_INIT)).toBe("PasswordAuthentication yes\n"); // lo ajeno no se toca
    expect(effective().passwordauthentication).toBe("no");
    // Validar ANTES de recargar; y comprobar el efectivo después.
    expect(commandsRun()).toEqual(["/usr/sbin/sshd -t", "/usr/bin/systemctl reload ssh.service", "/usr/sbin/sshd -T"]);
  });

  it("⭐ el mismo equipo con el drop-in llamado 99- habría perdido (la regla del simulador es la de sshd)", () => {
    files.set(CLOUD_INIT, "PasswordAuthentication yes\n");
    files.set(LEGACY, "PasswordAuthentication no\n");
    expect(effective().passwordauthentication).toBe("yes");
  });

  it("migra desde el 99-: la directiva pasa al 00- y el resto del 99- se queda", async () => {
    files.set(CLOUD_INIT, "PasswordAuthentication yes\n");
    files.set(LEGACY, "PermitRootLogin no\n\nPasswordAuthentication no\n");

    const res = await remediate("linux.ssh.password_auth_disabled");

    expect(res.result).toMatchObject({ exitCode: 0, changesApplied: ["PasswordAuthentication=no", "moved-from-99-dropin", "sshd-reloaded"] });
    expect(files.get(OURS)).toBe("PasswordAuthentication no\n");
    expect(files.get(LEGACY)).toBe("PermitRootLogin no\n");
    expect(commandsRun().filter((c) => c === "/usr/sbin/sshd -t")).toHaveLength(1); // un solo sshd -t para los dos
    expect(effective().passwordauthentication).toBe("no");
  });

  it("si sshd -t rechaza, se restauran LOS DOS ficheros y no se recarga", async () => {
    files.set(LEGACY, "PasswordAuthentication no\n");
    sshdTest = { code: 255, stderr: "/etc/ssh/sshd_config.d/40-x.conf line 2: Bad configuration option" };

    const res = await remediate("linux.ssh.password_auth_disabled");

    expect(res.result).toMatchObject({ exitCode: 1, changesApplied: [] });
    expect(res.result.stderrExcerpt).toMatch(/Bad configuration option/);
    expect(liveFiles()).toEqual([MAIN, LEGACY]);
    expect(files.get(LEGACY)).toBe("PasswordAuthentication no\n");
    expect(commandsRun().some((c) => c.includes("reload"))).toBe(false);
  });

  it("⭐ un drop-in que ordena antes que el 00- manda → exitCode 1 diciendo cuál y en qué línea", async () => {
    files.set(`${DIR}/00-aaa.conf`, "# puesto por el operador\nPasswordAuthentication yes\n");

    const res = await remediate("linux.ssh.password_auth_disabled");

    expect(res.result.exitCode).toBe(1);
    expect(res.result.changesApplied).toEqual(["PasswordAuthentication=no", "sshd-reloaded", "effective-value-overridden"]);
    expect(res.result.stderrExcerpt).toMatch(/^\/etc\/ssh\/sshd_config\.d\/00-aaa\.conf:2 \(yes\) sets PasswordAuthentication before/);
    // Lo nuestro se queda (validado); lo ajeno, intacto.
    expect(files.get(OURS)).toBe("PasswordAuthentication no\n");
    expect(files.get(`${DIR}/00-aaa.conf`)).toBe("# puesto por el operador\nPasswordAuthentication yes\n");
  });

  it("también en el no-op: nuestro fichero ya la lleva pero no gana → exitCode 1 (antes, 0 en silencio)", async () => {
    files.set(OURS, "PasswordAuthentication no\n");
    files.set(MAIN, "PasswordAuthentication yes\n" + UBUNTU_MAIN);

    const res = await remediate("linux.ssh.password_auth_disabled");

    expect(res.result).toMatchObject({ exitCode: 1, changesApplied: ["effective-value-overridden"] });
    expect(res.result.stderrExcerpt).toMatch(/^\/etc\/ssh\/sshd_config:1 \(yes\) sets PasswordAuthentication before/);
    expect(commandsRun()).toEqual(["/usr/sbin/sshd -T"]);
  });

  it("sshd_config sin Include de sshd_config.d → lo dice (el drop-in no se lee nunca)", async () => {
    files.set(MAIN, "PermitRootLogin yes\nUsePAM yes\n");

    const res = await remediate("linux.ssh.root_login_disabled");

    expect(res.result.exitCode).toBe(1);
    expect(res.result.stderrExcerpt).toMatch(/does not Include \/etc\/ssh\/sshd_config\.d\/\*\.conf.*sshd_config:1 \(yes\)/);
  });

  it("KEX: el 00- gana a un drop-in de crypto-policies con SHA-1 y la comprobación es «sin débiles»", async () => {
    files.set(`${DIR}/50-redhat.conf`, `KexAlgorithms ${WEAK_KEX}\n`);

    const res = await remediate("linux.cryptography.weak_ssh_kex_disabled");

    expect(res.result).toMatchObject({ exitCode: 0, changesApplied: [expect.stringMatching(/^KexAlgorithms=/), "sshd-reloaded"] });
    expect(effective().kexalgorithms).not.toMatch(/sha1/);
  });
});

// ── pmp.revert con el 99- de antes ─────────────────────────────────

describe("handlePmpRevert — drop-in viejo", () => {
  const before = (current: string) => ({ directive: "PermitRootLogin", current, expected: "no", sshdEffective: true });

  it("⭐ un fix hecho con el 99- se deshace: la directiva sale del 99- (y se borra si queda vacío)", async () => {
    files.set(LEGACY, "PermitRootLogin no\n");

    const res = await revert("linux.ssh.root_login_disabled", before("prohibit-password"));

    expect(res.result).toMatchObject({ exitCode: 0, changesApplied: ["PermitRootLogin-unset", "legacy-99-dropin-removed", "sshd-reloaded"] });
    expect(liveFiles()).toEqual([MAIN]);
    expect(effective().permitrootlogin).toBe("prohibit-password");
  });

  it("en los dos ficheros → sale de los dos; si quedase en uno, el revert no surtiría efecto", async () => {
    files.set(OURS, "PermitRootLogin no\n\nPasswordAuthentication no\n");
    files.set(LEGACY, "PermitRootLogin no\n");

    const res = await revert("linux.ssh.root_login_disabled", before("prohibit-password"));

    expect(res.result).toMatchObject({ exitCode: 0, changesApplied: ["PermitRootLogin-unset", "legacy-99-dropin-removed", "sshd-reloaded"] });
    expect(files.get(OURS)).toBe("PasswordAuthentication no\n");
    expect(files.has(LEGACY)).toBe(false);
    expect(commandsRun().filter((c) => c === "/usr/sbin/sshd -t")).toHaveLength(1);
  });

  it("revert después de migrar: el 00- se borra y el resto del 99- sigue", async () => {
    files.set(OURS, "PasswordAuthentication no\n");
    files.set(LEGACY, "PermitRootLogin no\n");

    const res = await revert("linux.ssh.password_auth_disabled", {
      directive: "PasswordAuthentication",
      current: "yes",
      expected: "no",
      sshdEffective: true,
    });

    expect(res.result).toMatchObject({ exitCode: 0, changesApplied: ["PasswordAuthentication-unset", "dropin-removed", "sshd-reloaded"] });
    expect(liveFiles()).toEqual([MAIN, LEGACY]);
  });
});
