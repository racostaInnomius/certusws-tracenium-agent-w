// test/privsvc/linux-generic-config.test.ts
//
// `linux.config.set_value`: la remediación genérica de Linux. Equipo
// simulado en memoria (ficheros, /proc/sys, /proc/modules y los comandos),
// para fijar lo que importa: que se escribe sólo en NUESTROS sitios, que
// el estado se lee como lo lee la sonda, que lo guardado no pasa aunque el
// backend lo pida, y que una regla de auditd que no cargaría no se deja
// escrita.

import { describe, it, expect, beforeEach } from "vitest";
import {
  applyGeneric,
  readGenericState,
  parseWrites,
  editConf,
  sysctlBootValue,
  ausyscallMachine,
  CONF_FILES,
  SYSCTL_DROPIN,
  MODPROBE_DROPIN,
  AUDIT_RULES_FILE,
  type GenericDeps,
} from "../../privsvc/linux/src/generic-config";

// ── Equipo simulado ────────────────────────────────────────────────
let files: Map<string, string>;
let dirs: Set<string>;
let calls: string[];
let execImpl: (bin: string, args: string[]) => { stdout: string; stderr: string; code: number | null };

const deps = (): GenericDeps => ({
  readFile: (p) => files.get(p) ?? null,
  writeFile: (p, c) => void files.set(p, c),
  unlink: (p) => void files.delete(p),
  mkdirp: (p) => void dirs.add(p),
  readdir: (p) => [...files.keys()].filter((f) => f.startsWith(p + "/") && !f.slice(p.length + 1).includes("/")).map((f) => f.slice(p.length + 1)),
  isDir: (p) => dirs.has(p),
  fileMode: (p) => (files.has(p) || bins.has(p) ? 0o644 : null),
  copyFile: (s, d) => void files.set(d, files.get(s) ?? ""),
  exec: async (bin, args) => {
    calls.push([bin, ...args].join(" "));
    return execImpl(bin, args);
  },
  machine: () => "x86_64",
  now: () => new Date("2026-09-27T20:00:00Z"),
});
const bins = new Set(["/usr/sbin/ausyscall", "/usr/sbin/augenrules", "/usr/sbin/auditctl", "/usr/bin/systemd-run"]);

function defaultExec(bin: string, args: string[]): { stdout: string; stderr: string; code: number | null } {
  // systemd-run --wait --pipe --collect --quiet -- <bin> <args…>
  if (bin.endsWith("systemd-run")) {
    const i = args.indexOf("--");
    return execImpl(args[i + 1], args.slice(i + 2));
  }
  if (bin.endsWith("sysctl") && args[0] === "-q") {
    const [k, v] = args[2].split("=");
    files.set("/proc/sys/" + k.replace(/\./g, "/"), v + "\n");
    return { stdout: "", stderr: "", code: 0 };
  }
  if (bin.endsWith("modprobe") && args[0] === "-r") {
    files.set("/proc/modules", (files.get("/proc/modules") ?? "").split("\n").filter((l) => !l.startsWith(args[1] + " ")).join("\n"));
    return { stdout: "", stderr: "", code: 0 };
  }
  if (bin.endsWith("ausyscall")) return { stdout: args[1] === "open" && args[0] === "aarch64" ? "" : "90\n", stderr: "", code: 0 };
  if (bin.endsWith("auditctl")) return { stdout: "enabled 1\n", stderr: "", code: 0 };
  return { stdout: "", stderr: "", code: 0 };
}

beforeEach(() => {
  files = new Map([
    ["/proc/sys/net/ipv4/conf/all/accept_redirects", "1\n"],
    ["/proc/sys/net/ipv4/ip_forward", "1\n"],
    ["/proc/modules", "cramfs 16384 0 - Live 0x0\nsquashfs 69632 1 - Live 0x0\n"],
    ["/etc/security/pwquality.conf", "# minlen = 8\nminlen = 8\n"],
    ["/etc/systemd/journald.conf", "[Journal]\n#Storage=auto\n"],
    ["/usr/lib/sysctl.d/50-default.conf", "net.ipv4.conf.all.accept_redirects = 1\n"],
  ]);
  dirs = new Set(["/etc/audit/rules.d", "/etc", "/etc/security"]);
  calls = [];
  execImpl = defaultExec;
});

const w = (...writes: any[]) => ({ writes });

describe("parseWrites — la lista cerrada y las guardas se repiten aquí", () => {
  it("rechaza lo guardado aunque el backend lo pida", () => {
    expect(parseWrites(w({ kind: "sysctl", key: "net.ipv4.ip_forward", value: "0", persist: true }))).toMatchObject({ ok: false, message: expect.stringMatching(/guarded/) });
    expect(parseWrites(w({ kind: "kmod", module: "squashfs", disable: true }))).toMatchObject({ ok: false });
    expect(parseWrites(w({ kind: "conf", file: "/etc/security/faillock.conf", key: "deny", value: "5" }))).toMatchObject({ ok: false });
  });

  it("pero deja deshacer: devolver el reenvío o desbloquear no es lo guardado", () => {
    expect(parseWrites(w({ kind: "sysctl", key: "net.ipv4.ip_forward", value: "1", persist: false })).ok).toBe(true);
    expect(parseWrites(w({ kind: "kmod", module: "squashfs", disable: false })).ok).toBe(true);
  });

  it("fuera de la lista o con forma rara, nada", () => {
    for (const bad of [
      { kind: "kmod", module: "ext4", disable: true },
      { kind: "conf", file: "/etc/shadow", key: "root", value: "x" },
      { kind: "conf", file: "/etc/login.defs", key: "MAIL_DIR", value: "/tmp" },
      { kind: "conf", file: "/etc/login.defs", key: "UMASK", value: "027\nroot ALL" },
      { kind: "audit_rule", line: "-w /etc/passwd -p wa -k x; rm -rf /", present: true },
      { kind: "audit_rule", line: "-w /etc/../root/.ssh -p wa -k tracenium", present: true },
      { kind: "audit_rule", line: "-D", present: true },
      { kind: "sysctl", key: "kernel.core_pattern", value: "|/tmp/evil", persist: true },
      { kind: "shell", cmd: "id" },
    ]) {
      expect(parseWrites(w(bad)).ok, JSON.stringify(bad)).toBe(false);
    }
    expect(parseWrites({ writes: [] }).ok).toBe(false);
  });
});

describe("sysctl", () => {
  const redirects = { kind: "sysctl", key: "net.ipv4.conf.all.accept_redirects", value: "0", persist: true };

  it("persiste en NUESTRO fichero, lo aplica vivo y queda conforme", async () => {
    const r = await applyGeneric(w(redirects), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0, requiresReboot: false } });
    expect(files.get(SYSCTL_DROPIN)).toContain("net.ipv4.conf.all.accept_redirects = 0");
    // Escribir /proc/sys no cabe en el perfil de AppArmor: va por systemd-run.
    expect(calls).toContain("/usr/bin/systemd-run --wait --pipe --collect --quiet -- /usr/sbin/sysctl -q -w net.ipv4.conf.all.accept_redirects=0");
    const s = await readGenericState(w(redirects), deps());
    expect(s).toMatchObject({ ok: true, value: { isCompliant: true } });
    expect((s as any).value.state.writes[0]).toMatchObject({ kind: "sysctl", runtime: "0", ours: "0", boot: "0" });
  });

  it("un fichero posterior que gana en el arranque se dice por su nombre", async () => {
    files.set("/etc/sysctl.d/99-zz-local.conf", "net.ipv4.conf.all.accept_redirects=1\n");
    const r = await applyGeneric(w(redirects), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 1 } });
    expect((r as any).value.stderrExcerpt).toContain("/etc/sysctl.d/99-zz-local.conf sets net.ipv4.conf.all.accept_redirects = 1");
  });

  it("orden de arranque: mismo nombre → /etc gana; glob cuenta", () => {
    files.set("/usr/lib/sysctl.d/99-x.conf", "net.ipv4.conf.all.accept_redirects = 5\n");
    files.set("/etc/sysctl.d/99-x.conf", "net.ipv4.conf.all.accept_redirects = 6\n");
    expect(sysctlBootValue("net.ipv4.conf.all.accept_redirects", deps()).value).toBe("6");
    files.set("/etc/sysctl.d/99-zz.conf", "net/ipv4/conf/*/accept_redirects = 7\n");
    expect(sysctlBootValue("net.ipv4.conf.all.accept_redirects", deps())).toEqual({ value: "7", source: "/etc/sysctl.d/99-zz.conf" });
  });

  it("revert: quita nuestra línea y devuelve el valor vivo que había", async () => {
    await applyGeneric(w(redirects), deps());
    const back = { ...redirects, value: "1", persist: false };
    const r = await applyGeneric(w(back), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(files.get(SYSCTL_DROPIN)).not.toContain("accept_redirects");
    expect(files.get("/proc/sys/net/ipv4/conf/all/accept_redirects")).toBe("1\n");
  });
});

describe("módulos del kernel", () => {
  it("bloquea en nuestro fichero y lo descarga", async () => {
    const r = await applyGeneric(w({ kind: "kmod", module: "cramfs", disable: true }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0, requiresReboot: false } });
    expect(files.get(MODPROBE_DROPIN)).toContain("install cramfs /bin/false\nblacklist cramfs");
    expect(calls).toContain("/usr/bin/systemd-run --wait --pipe --collect --quiet -- /usr/sbin/modprobe -r cramfs");
  });

  it("en uso: queda bloqueado y pide reinicio, no «fallido»", async () => {
    execImpl = (bin, args) => (bin.endsWith("modprobe") ? { stdout: "", stderr: "modprobe: FATAL: Module cramfs is in use.", code: 1 } : defaultExec(bin, args));
    const r = await applyGeneric(w({ kind: "kmod", module: "cramfs", disable: true }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0, requiresReboot: true } });
  });

  it("revert: quita sólo nuestras dos líneas", async () => {
    files.set(MODPROBE_DROPIN, "# x\ninstall hfs /bin/false\nblacklist hfs\ninstall cramfs /bin/false\nblacklist cramfs\n");
    await applyGeneric(w({ kind: "kmod", module: "cramfs", disable: false }), deps());
    expect(files.get(MODPROBE_DROPIN)).toBe("# x\ninstall hfs /bin/false\nblacklist hfs\n");
  });
});

describe("auditd", () => {
  const sudoers = { kind: "audit_rule", line: "-w /etc/sudoers -p wa -k tracenium", present: true };
  const chown = { kind: "audit_rule", line: "-a always,exit -F arch=b64 -S chown,open -k tracenium", present: true };

  it("añade la línea a nuestro fichero y recarga", async () => {
    const r = await applyGeneric(w(sudoers, chown), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(files.get(AUDIT_RULES_FILE)).toContain("-w /etc/sudoers -p wa -k tracenium\n-a always,exit -F arch=b64 -S chown,open -k tracenium");
    expect(calls).toContain("/usr/bin/systemd-run --wait --pipe --collect --quiet -- /usr/sbin/augenrules --load");
    // ausyscall es una tabla: va directo.
    expect(calls).toContain("/usr/sbin/ausyscall x86_64 chown --exact");
  });

  it("sin auditd instalado no se escribe nada", async () => {
    dirs.delete("/etc/audit/rules.d");
    const r = await applyGeneric(w(sudoers), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 2 } });
    expect(files.has(AUDIT_RULES_FILE)).toBe(false);
  });

  it("una syscall que no existe en esta arquitectura se rechaza ANTES de escribir", async () => {
    const d = { ...deps(), machine: () => "aarch64" };
    const r = await applyGeneric(w(chown), d);
    expect(r).toMatchObject({ ok: true, value: { exitCode: 2 } });
    expect((r as any).value.stderrExcerpt).toMatch(/syscall open does not exist for arch=b64/);
    expect(files.has(AUDIT_RULES_FILE)).toBe(false);
    expect(ausyscallMachine("32", "aarch64")).toBeNull();
  });

  it("vigilar una ruta cuyo directorio no existe también (sí vale si existe el padre)", async () => {
    const r = await applyGeneric(w({ kind: "audit_rule", line: "-w /etc/netplan/01-cfg.yaml -p wa -k tracenium", present: true }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 2 } });
    expect((r as any).value.stderrExcerpt).toContain("/etc/netplan does not exist");
    const ok = await applyGeneric(w({ kind: "audit_rule", line: "-w /etc/netplan -p wa -k tracenium", present: true }), deps());
    expect(ok).toMatchObject({ ok: true, value: { exitCode: 0 } });
  });

  it("si augenrules --load falla, el fichero vuelve a como estaba", async () => {
    files.set(AUDIT_RULES_FILE, "## prev\n-w /etc/passwd -p wa -k tracenium\n");
    execImpl = (bin, args) => (bin.endsWith("augenrules") && calls.filter((c) => c.includes("augenrules")).length === 1 ? { stdout: "", stderr: "Error sending add rule data request", code: 1 } : defaultExec(bin, args));
    const r = await applyGeneric(w(sudoers), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 1 } });
    expect(files.get(AUDIT_RULES_FILE)).toBe("## prev\n-w /etc/passwd -p wa -k tracenium\n");
  });

  it("auditd inmutable (-e 2): escrito, pide reinicio, no recarga", async () => {
    execImpl = (bin, args) => (bin.endsWith("auditctl") ? { stdout: "enabled 2\n", stderr: "", code: 0 } : defaultExec(bin, args));
    const r = await applyGeneric(w(sudoers), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0, requiresReboot: true } });
    expect(calls.some((c) => c.includes("augenrules"))).toBe(false);
  });

  it("revert: quita NUESTRA línea, no las del operador", async () => {
    files.set(AUDIT_RULES_FILE, "-w /etc/passwd -p wa -k tracenium\n-w /etc/sudoers -p wa -k tracenium\n");
    files.set("/etc/audit/rules.d/50-operator.rules", "-w /etc/sudoers -p wa -k ops\n");
    await applyGeneric(w({ ...sudoers, present: false }), deps());
    expect(files.get(AUDIT_RULES_FILE)).toBe("-w /etc/passwd -p wa -k tracenium\n");
    expect(files.get("/etc/audit/rules.d/50-operator.rules")).toBe("-w /etc/sudoers -p wa -k ops\n");
  });
});

describe("clave = valor", () => {
  it("systemd: drop-in propio bajo su sección, y reinicia journald", async () => {
    const r = await applyGeneric(w({ kind: "conf", file: "/etc/systemd/journald.conf", key: "Storage", value: "persistent" }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(files.get("/etc/systemd/journald.conf.d/99-tracenium-hardening.conf")).toMatch(/\[Journal\]\nStorage=persistent\n$/);
    expect(files.get("/etc/systemd/journald.conf")).toBe("[Journal]\n#Storage=auto\n");
    expect(calls).toContain("/usr/bin/systemctl restart systemd-journald");
  });

  it("en su sitio: copia de seguridad y la última línea activa cambia", async () => {
    const r = await applyGeneric(w({ kind: "conf", file: "/etc/security/pwquality.conf", key: "minlen", value: "14" }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(files.get("/etc/security/pwquality.conf")).toBe("# minlen = 8\nminlen = 14\n");
    expect(files.get("/etc/security/pwquality.conf.tracenium.20260927-200000.bak")).toBe("# minlen = 8\nminlen = 8\n");
  });

  it("un .d posterior que manda se dice, y el resultado no es «aplicado»", async () => {
    files.set("/etc/security/pwquality.conf.d/50-site.conf", "minlen = 10\n");
    dirs.add("/etc/security/pwquality.conf.d");
    const r = await applyGeneric(w({ kind: "conf", file: "/etc/security/pwquality.conf", key: "minlen", value: "14" }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 1 } });
    expect((r as any).value.stderrExcerpt).toContain("/etc/security/pwquality.conf.d/50-site.conf sets minlen = 10 after ours");
  });

  it("auditd.conf surte efecto al reiniciar auditd: requiresReboot", async () => {
    files.set("/etc/audit/auditd.conf", "log_group = root\n");
    const r = await applyGeneric(w({ kind: "conf", file: "/etc/audit/auditd.conf", key: "log_group", value: "adm" }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0, requiresReboot: true } });
  });

  it("editConf: comenta las anteriores y quita al revertir", () => {
    const p = CONF_FILES["/etc/login.defs"];
    expect(editConf("UMASK 022\nUMASK 077\n", p, "UMASK", "027", false)).toBe("# UMASK 022  # superseded by Tracenium\nUMASK\t027\n");
    expect(editConf("A 1\nUMASK\t027\n", p, "UMASK", null, false)).toBe("A 1\n");
    expect(editConf(null, CONF_FILES["/etc/systemd/coredump.conf"], "Storage", "none", true)).toBe("# Managed by Tracenium — compliance fixes.\n[Coredump]\nStorage=none\n");
  });
});

describe("todo o nada", () => {
  it("un payload con una escritura inválida no toca nada", async () => {
    const r = await applyGeneric(
      w({ kind: "sysctl", key: "net.ipv4.conf.all.accept_redirects", value: "0", persist: true }, { kind: "kmod", module: "squashfs", disable: true }),
      deps()
    );
    expect(r.ok).toBe(false);
    expect(files.has(SYSCTL_DROPIN)).toBe(false);
    expect(calls).toEqual([]);
  });
});

// ── sshd ───────────────────────────────────────────────────────────
// sshd simulado en lo que importa: lee sshd_config hasta su Include y los
// drop-ins en orden, se queda con el PRIMER valor, `-t` rechaza algoritmos
// que no conoce (este OpenSSH no tiene sntrup761: el de Ubuntu 20.04).
describe("sshd — el mismo drop-in 00- que los handlers dedicados", () => {
  const MAIN = "/etc/ssh/sshd_config";
  const DIR = "/etc/ssh/sshd_config.d";
  const OURS = `${DIR}/00-tracenium-hardening.conf`;
  const KNOWN_KEX = new Set(["curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"]);
  const DEFAULTS: Record<string, string> = { maxauthtries: "6", kexalgorithms: "curve25519-sha256,diffie-hellman-group14-sha1", banner: "none", permitrootlogin: "without-password" };

  function effective(extra: string[] = []): Map<string, string> {
    const m = new Map<string, string>();
    const take = (text: string) => {
      for (const l of text.split("\n")) {
        const t = l.trim();
        if (!t || t.startsWith("#")) continue;
        const [k, ...rest] = t.split(/\s+/);
        const key = k.toLowerCase();
        if (key === "include") {
          for (const f of [...files.keys()].filter((f) => f.startsWith(DIR + "/") && f.endsWith(".conf")).sort()) take(files.get(f)!);
          continue;
        }
        if (!m.has(key)) m.set(key, rest.join(" "));
      }
    };
    for (const o of extra) take(o.replace("=", " "));
    take(files.get(MAIN) ?? "");
    for (const [k, v] of Object.entries(DEFAULTS)) if (!m.has(k)) m.set(k, v);
    return m;
  }
  let reloads: string[];
  function sshdExec(bin: string, args: string[]) {
    if (bin === "/usr/sbin/sshd") {
      const extra = args[0] === "-t" && args[1] === "-o" ? [args[2]] : [];
      const m = effective(extra);
      const kex = m.get("kexalgorithms")!.split(",");
      const bad = kex.find((k) => !KNOWN_KEX.has(k));
      if (bad) return { stdout: "", stderr: `Bad SSH2 KexAlgorithms '${bad}'`, code: 255 };
      if ([...files.values()].some((t) => t.includes("BROKEN"))) return { stdout: "", stderr: "line 1: Bad configuration option: BROKEN", code: 255 };
      if (args[0] === "-T") return { stdout: [...m].map(([k, v]) => `${k} ${v}`).join("\n") + "\n", stderr: "", code: 0 };
      return { stdout: "", stderr: "", code: 0 };
    }
    if (bin === "/usr/bin/systemctl" && args[0] === "reload") {
      reloads.push(args[1]);
      return { stdout: "", stderr: "", code: args[1] === "ssh.service" ? 0 : 5 };
    }
    return defaultExec(bin, args);
  }
  beforeEach(() => {
    bins.add("/usr/sbin/sshd");
    reloads = [];
    files.set(MAIN, "Include /etc/ssh/sshd_config.d/*.conf\nUsePAM yes\n");
    files.set("/etc/issue.net", "Authorized use only\n");
    dirs.add(DIR);
    execImpl = sshdExec;
  });

  it("escribe en el 00-, valida con sshd -t, recarga, y el efectivo queda como pide el check", async () => {
    const r = await applyGeneric(w({ kind: "sshd", key: "MaxAuthTries", value: "4" }, { kind: "sshd", key: "Banner", value: "/etc/issue.net" }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(files.get(OURS)).toBe("MaxAuthTries 4\n\nBanner /etc/issue.net\n");
    expect(reloads).toEqual(["ssh.service"]);
    expect(calls.indexOf("/usr/sbin/sshd -t")).toBeLessThan(calls.indexOf("/usr/bin/systemctl reload ssh.service"));
    const s = await readGenericState(w({ kind: "sshd", key: "maxauthtries", value: "4" }), deps());
    expect(s).toMatchObject({ ok: true, value: { isCompliant: true, state: { writes: [{ kind: "sshd", key: "MaxAuthTries", effective: "4", ours: "4" }] } } });
  });

  it("⭐ un algoritmo que este OpenSSH no conoce sale de la lista; los débiles no entran", async () => {
    const r = await applyGeneric(w({ kind: "sshd", key: "KexAlgorithms", value: "sntrup761x25519-sha512@openssh.com,curve25519-sha256,ecdh-sha2-nistp256" }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(files.get(OURS)).toBe("KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256\n");
    expect((r as any).value.changesApplied).toContain("KexAlgorithms: left out sntrup761x25519-sha512@openssh.com (not supported by this OpenSSH)");
  });

  it("⭐ pero si el check lo NECESITA (PQC), no se escribe nada y se dice por qué", async () => {
    const r = await applyGeneric(w({ kind: "sshd", key: "KexAlgorithms", value: "sntrup761x25519-sha512@openssh.com,curve25519-sha256", required: ["sntrup761x25519-sha512@openssh.com"] }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 2, stderrExcerpt: expect.stringMatching(/does not support sntrup761.*upgrade OpenSSH/) } });
    expect(files.has(OURS)).toBe(false);
    expect(reloads).toEqual([]);
  });

  it("otro drop-in anterior gana: se dice cuál y en qué línea, y lo suyo no se toca", async () => {
    files.set(`${DIR}/00-aaa-local.conf`, "# local\nMaxAuthTries 10\n");
    const r = await applyGeneric(w({ kind: "sshd", key: "MaxAuthTries", value: "4" }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 1, stderrExcerpt: expect.stringMatching(/00-aaa-local\.conf:2 \(10\) sets MaxAuthTries before/) } });
    expect(files.get(`${DIR}/00-aaa-local.conf`)).toBe("# local\nMaxAuthTries 10\n");
  });

  it("si sshd -t rechaza el conjunto, nuestros ficheros vuelven a como estaban y no se recarga", async () => {
    files.set(OURS, "X11Forwarding no\n");
    let n = 0;
    execImpl = (bin, args) => (bin === "/usr/sbin/sshd" && args.length === 1 && args[0] === "-t" && ++n === 2 ? { stdout: "", stderr: "boom", code: 255 } : sshdExec(bin, args));
    const r = await applyGeneric(w({ kind: "sshd", key: "MaxAuthTries", value: "4" }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 1, stderrExcerpt: expect.stringMatching(/rejected.*restored/) } });
    expect(files.get(OURS)).toBe("X11Forwarding no\n");
    expect(reloads).toEqual([]);
  });

  it("una configuración que ya está rota no se toca", async () => {
    files.set(`${DIR}/50-cloud-init.conf`, "BROKEN\n");
    const r = await applyGeneric(w({ kind: "sshd", key: "MaxAuthTries", value: "4" }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 2, stderrExcerpt: expect.stringMatching(/already invalid/) } });
    expect(files.has(OURS)).toBe(false);
  });

  it("el 99- de antes se vacía directiva a directiva, como en el handler dedicado", async () => {
    files.set(`${DIR}/99-tracenium-hardening.conf`, "MaxAuthTries 3\nX11Forwarding no\n");
    await applyGeneric(w({ kind: "sshd", key: "MaxAuthTries", value: "4" }), deps());
    expect(files.get(`${DIR}/99-tracenium-hardening.conf`)).toBe("X11Forwarding no\n");
    expect(files.get(OURS)).toBe("MaxAuthTries 4\n");
  });

  it("revert: value null quita la directiva de NUESTRO drop-in (y el fichero si queda vacío)", async () => {
    files.set(OURS, "MaxAuthTries 4\n");
    const r = await applyGeneric(w({ kind: "sshd", key: "MaxAuthTries", value: null }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(files.has(OURS)).toBe(false);
  });

  it("guardas, banner fuera de la lista y valores con forma rara: rechazados", () => {
    for (const bad of [
      { kind: "sshd", key: "PermitRootLogin", value: "no" },
      { kind: "sshd", key: "PasswordAuthentication", value: "NO" },
      { kind: "sshd", key: "DisableForwarding", value: "yes" },
      { kind: "sshd", key: "GSSAPIAuthentication", value: "no" },
      { kind: "sshd", key: "Banner", value: "/etc/shadow" },
      { kind: "sshd", key: "Subsystem", value: "sftp /bin/sh" },
      { kind: "sshd", key: "MaxAuthTries", value: "4\nPermitRootLogin yes" },
      { kind: "sshd", key: "Ciphers", value: "aes128-ctr,aes128 ctr" },
      { kind: "sshd", key: "KexAlgorithms", value: "curve25519-sha256", required: ["sntrup761x25519-sha512@openssh.com"] },
    ]) {
      expect(parseWrites(w(bad)).ok, JSON.stringify(bad)).toBe(false);
    }
    // Deshacer lo guardado sí se deja.
    expect(parseWrites(w({ kind: "sshd", key: "PermitRootLogin", value: "without-password" })).ok).toBe(true);
    expect(parseWrites(w({ kind: "sshd", key: "PermitRootLogin", value: null })).ok).toBe(true);
  });
});

describe("line — una línea de la lista cerrada", () => {
  it("fichero nuestro: se crea con cabecera, idempotente, y el revert lo quita entero", async () => {
    const add = w({ kind: "line", file: "/etc/security/limits.d/60-tracenium.conf", line: "* hard core 0", present: true });
    expect(await applyGeneric(add, deps())).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(files.get("/etc/security/limits.d/60-tracenium.conf")).toBe("# Managed by Tracenium — compliance fixes. Remove a line to hand it back.\n* hard core 0\n");
    const again = await applyGeneric(add, deps());
    expect((again as any).value.changesApplied).toEqual([]);
    expect(await readGenericState(add, deps())).toMatchObject({ ok: true, value: { isCompliant: true, state: { writes: [{ kind: "line", present: true }] } } });
    await applyGeneric(w({ kind: "line", file: "/etc/security/limits.d/60-tracenium.conf", line: "* hard core 0", present: false }), deps());
    expect(files.has("/etc/security/limits.d/60-tracenium.conf")).toBe(false);
  });

  it("fichero del sistema: sólo la línea, al final, con copia; lo comentado del operador se queda", async () => {
    files.set("/etc/security/pwquality.conf", "# enforce_for_root\nminlen = 8\n");
    const r = await applyGeneric(w({ kind: "line", file: "/etc/security/pwquality.conf", line: "enforce_for_root", present: true }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(files.get("/etc/security/pwquality.conf")).toBe("# enforce_for_root\nminlen = 8\nenforce_for_root\n");
    expect(files.get("/etc/security/pwquality.conf.tracenium.20260927-200000.bak")).toBe("# enforce_for_root\nminlen = 8\n");
  });

  it("auditd -c en su fichero 01-, y se recarga", async () => {
    const r = await applyGeneric(w({ kind: "line", file: "/etc/audit/rules.d/01-tracenium-continue.rules", line: "-c", present: true }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(files.get("/etc/audit/rules.d/01-tracenium-continue.rules")).toMatch(/\n-c\n$/);
    expect(calls.some((c) => c.endsWith("augenrules --load"))).toBe(true);
  });

  it("fuera de la lista, o con guarda, no", () => {
    for (const bad of [
      { kind: "line", file: "/etc/security/limits.d/60-tracenium.conf", line: "* hard nofile 1", present: true },
      { kind: "line", file: "/etc/sudoers.d/x", line: "ALL ALL=(ALL) NOPASSWD: ALL", present: true },
      { kind: "line", file: "/etc/security/faillock.conf", line: "even_deny_root", present: true },
      { kind: "line", file: "/etc/apt/apt.conf.d/60tracenium-hardening", line: 'APT::Install-Recommends "false";', present: true },
    ]) {
      expect(parseWrites(w(bad)).ok, JSON.stringify(bad)).toBe(false);
    }
    expect(parseWrites(w({ kind: "line", file: "/etc/security/faillock.conf", line: "even_deny_root", present: false })).ok).toBe(true);
  });

  it("journald: MaxFileSec en nuestro drop-in", async () => {
    dirs.add("/etc/systemd/journald.conf.d");
    const r = await applyGeneric(w({ kind: "conf", file: "/etc/systemd/journald.conf", key: "MaxFileSec", value: "1month" }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(files.get("/etc/systemd/journald.conf.d/99-tracenium-hardening.conf")).toContain("[Journal]\nMaxFileSec=1month\n");
  });
});

// ── Paquetes y unidades ────────────────────────────────────────────
// apt y systemd simulados: dpkg-query dice lo instalado, `apt-get -s` enseña
// lo que haría (ubuntu-standard depende de telnet), systemctl lleva el estado.
describe("pkg y unit — lista cerrada, y apt simulado antes de tocar nada", () => {
  let installed: Set<string>;
  let unitState: Map<string, { enabled: string; active: string }>;
  const DEPENDS_ON: Record<string, string[]> = { telnet: ["ubuntu-standard"] };
  function aptExec(bin: string, args: string[]) {
    if (bin.endsWith("systemd-run")) {
      const i = args.indexOf("--");
      return aptExec(args[i + 1], args.slice(i + 2));
    }
    if (bin === "/usr/bin/dpkg-query") {
      const name = args[args.length - 1];
      return installed.has(name) ? { stdout: "install ok installed\t1.0", stderr: "", code: 0 } : { stdout: "", stderr: `no packages found matching ${name}`, code: 1 };
    }
    if (bin === "/usr/bin/apt-get") {
      const sim = args[0] === "-s";
      const verb = sim ? args[1] : args[0];
      const names = args.filter((a) => /^[a-z][a-z0-9+.-]+$/.test(a) && !["install", "remove"].includes(a));
      if (verb === "remove") {
        const gone = names.filter((n) => installed.has(n)).flatMap((n) => [n, ...(DEPENDS_ON[n] ?? []).filter((d) => installed.has(d))]);
        if (sim) return { stdout: gone.map((g) => `Remv ${g} [1.0]`).join("\n"), stderr: "", code: 0 };
        gone.forEach((g) => installed.delete(g));
        return { stdout: "", stderr: "", code: 0 };
      }
      if (sim) return { stdout: names.map((n) => `Inst ${n} (1.0 Ubuntu)`).join("\n"), stderr: "", code: 0 };
      names.forEach((n) => installed.add(n));
      return { stdout: "", stderr: "", code: 0 };
    }
    if (bin === "/usr/bin/systemctl") {
      if (args[0] === "is-enabled") return { stdout: (unitState.get(args[1])?.enabled ?? "not-found") + "\n", stderr: "", code: 0 };
      if (args[0] === "is-active") return { stdout: (unitState.get(args[1])?.active ?? "inactive") + "\n", stderr: "", code: 3 };
      if (args[0] === "enable" || args[0] === "disable") {
        for (const u of args.filter((a) => a.includes("."))) unitState.set(u, { enabled: args[0] === "enable" ? "enabled" : "disabled", active: args[0] === "enable" ? "active" : "inactive" });
        return { stdout: "", stderr: "", code: 0 };
      }
    }
    return defaultExec(bin, args);
  }
  beforeEach(() => {
    installed = new Set(["telnet", "ubuntu-standard", "ftp", "cups"]);
    unitState = new Map([["cups.socket", { enabled: "enabled", active: "active" }], ["update-notifier-motd.timer", { enabled: "enabled", active: "active" }]]);
    bins.add("/usr/bin/apt-get");
    execImpl = aptExec;
  });

  it("instala sin recomendados, y la relectura es la de la sonda (dpkg-query)", async () => {
    const r = await applyGeneric(w({ kind: "pkg", name: "auditd", installed: true }, { kind: "pkg", name: "audispd-plugins", installed: true }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(calls.some((c) => c.startsWith("/usr/bin/apt-get install -y --no-install-recommends -o DPkg::Lock::Timeout=120") && c.endsWith("auditd audispd-plugins"))).toBe(true);
    expect(installed.has("auditd")).toBe(true);
  });

  it("⭐ quitar telnet se llevaría ubuntu-standard: no se toca nada y se dice", async () => {
    const r = await applyGeneric(w({ kind: "pkg", name: "telnet", installed: false }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 2, stderrExcerpt: expect.stringMatching(/would also remove ubuntu-standard/) } });
    expect(installed.has("telnet")).toBe(true);
    expect(calls.some((c) => c.startsWith("/usr/bin/apt-get remove"))).toBe(false);
  });

  it("quitar ftp, que no arrastra nada, sí", async () => {
    const r = await applyGeneric(w({ kind: "pkg", name: "ftp", installed: false }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(installed.has("ftp")).toBe(false);
  });

  it("unidades por systemd-run, con las que van con ella; el revert las vuelve a encender", async () => {
    const r = await applyGeneric(w({ kind: "unit", unit: "update-notifier-motd.timer", enabled: false }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(calls).toContain("/usr/bin/systemd-run --wait --pipe --collect --quiet -- /usr/bin/systemctl disable --now update-notifier-motd.timer");
    const s = await readGenericState(w({ kind: "unit", unit: "update-notifier-motd.timer", enabled: false }), deps());
    expect(s).toMatchObject({ ok: true, value: { isCompliant: true, state: { writes: [{ kind: "unit", isEnabled: false, isActive: false, state: "disabled" }] } } });
  });

  it("guardas y lista cerrada; el sentido contrario (revert) se deja", () => {
    for (const bad of [
      { kind: "pkg", name: "cups", installed: false },
      { kind: "pkg", name: "gdm3", installed: false },
      { kind: "pkg", name: "openssh-server", installed: false },
      { kind: "pkg", name: "aide", installed: true },
      { kind: "pkg", name: "sudo-ldap", installed: true },
      { kind: "unit", unit: "cups.socket", enabled: false },
      { kind: "unit", unit: "ssh.service", enabled: false },
      { kind: "unit", unit: "auditd", enabled: "yes" },
    ]) {
      expect(parseWrites(w(bad)).ok, JSON.stringify(bad)).toBe(false);
    }
    expect(parseWrites(w({ kind: "unit", unit: "cups.socket", enabled: true })).ok).toBe(true);
    expect(parseWrites(w({ kind: "pkg", name: "auditd", installed: false })).ok).toBe(true);
  });

  it("sin apt (RHEL), no se intenta", async () => {
    bins.delete("/usr/bin/apt-get");
    const r = await applyGeneric(w({ kind: "pkg", name: "auditd", installed: true }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 2, stderrExcerpt: expect.stringMatching(/only apt/) } });
  });
});

describe("perm — quitar bits, root:root, sin seguir enlaces", () => {
  let meta: Map<string, { mode: number; uid: number; gid: number; isDir?: boolean; isLink?: boolean }>;
  const permDeps = (): GenericDeps => ({
    ...deps(),
    stat: (p) => {
      const m = meta.get(p);
      return m ? { mode: m.mode, uid: m.uid, gid: m.gid, isDir: !!m.isDir, isFile: !m.isDir && !m.isLink, isLink: !!m.isLink } : null;
    },
    readdir: (p) => [...meta.keys()].filter((f) => f.startsWith(p + "/") && !f.slice(p.length + 1).includes("/")).map((f) => f.slice(p.length + 1)),
  });
  function permExec(bin: string, args: string[]) {
    if (bin.endsWith("systemd-run")) {
      const i = args.indexOf("--");
      return permExec(args[i + 1], args.slice(i + 2));
    }
    if (bin === "/usr/bin/chmod") { meta.get(args[1])!.mode = parseInt(args[0], 8); return { stdout: "", stderr: "", code: 0 }; }
    if (bin === "/usr/bin/chown") { const [u, g] = args[0].split(":").map(Number); Object.assign(meta.get(args[1])!, { uid: u, gid: g }); return { stdout: "", stderr: "", code: 0 }; }
    return defaultExec(bin, args);
  }
  beforeEach(() => {
    meta = new Map([
      ["/etc/cron.d", { mode: 0o755, uid: 0, gid: 0, isDir: true }],
      ["/etc/crontab", { mode: 0o644, uid: 0, gid: 1000 }],
      ["/etc/ssh/sshd_config.d", { mode: 0o755, uid: 0, gid: 0, isDir: true }],
      ["/etc/ssh/sshd_config.d/50-cloud-init.conf", { mode: 0o644, uid: 0, gid: 0 }],
      ["/etc/ssh/sshd_config.d/00-tracenium-hardening.conf", { mode: 0o600, uid: 0, gid: 0 }],
      ["/usr/share/keyrings", { mode: 0o755, uid: 0, gid: 0, isDir: true }],
      ["/usr/share/keyrings/ubuntu-archive-keyring.gpg", { mode: 0o644, uid: 0, gid: 0 }],
      ["/usr/share/keyrings/vendor.gpg", { mode: 0o600, uid: 0, gid: 0 }],
      ["/usr/share/keyrings/link.gpg", { mode: 0o777, uid: 0, gid: 0, isLink: true }],
    ]);
    execImpl = permExec;
  });

  it("directorio: sólo pierde bits (0755 → 0700) y la relectura lo da por bueno", async () => {
    const r = await applyGeneric(w({ kind: "perm", path: "/etc/cron.d", maxMode: "0700" }), permDeps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(meta.get("/etc/cron.d")!.mode).toBe(0o700);
    expect(calls).toContain("/usr/bin/systemd-run --wait --pipe --collect --quiet -- /usr/bin/chmod 0700 /etc/cron.d");
  });

  it("fichero con grupo ajeno: chown root:root y modo", async () => {
    await applyGeneric(w({ kind: "perm", path: "/etc/crontab", maxMode: "0600" }), permDeps());
    expect(meta.get("/etc/crontab")).toMatchObject({ mode: 0o600, uid: 0, gid: 0 });
  });

  it("⭐ `files`: cada fichero; lo más estricto se queda (0600 no pasa a 0644) y el enlace no se toca", async () => {
    const r = await applyGeneric(w({ kind: "perm", path: "/usr/share/keyrings", maxMode: "0644" }), permDeps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(meta.get("/usr/share/keyrings/vendor.gpg")!.mode).toBe(0o600);
    expect(meta.get("/usr/share/keyrings/link.gpg")!.mode).toBe(0o777);
    expect(calls.some((c) => c.includes("link.gpg"))).toBe(false);
  });

  it("revert: vuelven el modo y el dueño que había", async () => {
    await applyGeneric(w({ kind: "perm", path: "/etc/ssh/sshd_config.d", maxMode: "0600" }), permDeps());
    expect(meta.get("/etc/ssh/sshd_config.d/50-cloud-init.conf")!.mode).toBe(0o600);
    const back = w({ kind: "perm", path: "/etc/ssh/sshd_config.d", maxMode: "0600", restore: [{ file: "/etc/ssh/sshd_config.d/50-cloud-init.conf", mode: "0644", uid: 0, gid: 0 }] });
    expect(await applyGeneric(back, permDeps())).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(meta.get("/etc/ssh/sshd_config.d/50-cloud-init.conf")!.mode).toBe(0o644);
  });

  it("fuera de la lista, un máximo distinto, o un restore fuera de la ruta: rechazado", () => {
    for (const bad of [
      { kind: "perm", path: "/usr/bin/env", maxMode: "0644" },
      { kind: "perm", path: "/etc/shadow", maxMode: "0000" },
      { kind: "perm", path: "/etc/cron.d", maxMode: "0777" },
      { kind: "perm", path: "/etc/cron.d", maxMode: "0700", restore: [{ file: "/etc/passwd", mode: "0666", uid: 0, gid: 0 }] },
      { kind: "perm", path: "/etc/ssh/sshd_config.d", maxMode: "0600", restore: [{ file: "/etc/ssh/sshd_config.d/../../shadow", mode: "0644", uid: 0, gid: 0 }] },
      { kind: "perm", path: "/etc/crontab", maxMode: "0600", restore: [{ file: "/etc/crontab", mode: "4777", uid: 0, gid: 0 }] },
    ]) {
      expect(parseWrites(w(bad)).ok, JSON.stringify(bad)).toBe(false);
    }
  });
});

describe("banner y grub_audit", () => {
  const TEXT = "Authorized users only. All activity may be monitored and reported.";
  beforeEach(() => {
    files.set("/etc/issue", "Ubuntu 24.04.5 LTS \\n \\l\n\n");
    files.set("/etc/os-release", "ID=ubuntu\n");
    files.set("/boot/grub/grub.cfg", "menuentry 'Ubuntu' {\n\tlinux /boot/vmlinuz root=/dev/sda1 ro quiet\n}\n");
    bins.add("/usr/sbin/update-grub");
    bins.add("/usr/sbin/auditd");
    execImpl = (bin, args) => {
      if (bin.endsWith("systemd-run")) {
        const i = args.indexOf("--");
        return execImpl(args[i + 1], args.slice(i + 2));
      }
      if (bin === "/usr/sbin/update-grub") {
        const extra = (files.get("/etc/default/grub.d/99-tracenium-audit.cfg") ?? "").includes("audit=1") ? " audit=1 audit_backlog_limit=8192" : "";
        files.set("/boot/grub/grub.cfg", `menuentry 'Ubuntu' {\n\tlinux /boot/vmlinuz root=/dev/sda1 ro quiet${extra}\n}\n`);
        return { stdout: "", stderr: "", code: 0 };
      }
      return defaultExec(bin, args);
    };
  });

  it("issue: el aviso de CIS, con copia del de antes; el revert lo devuelve tal cual", async () => {
    const r = await applyGeneric(w({ kind: "banner", file: "/etc/issue", text: TEXT }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(files.get("/etc/issue")).toBe(TEXT + "\n");
    expect(files.get("/etc/issue.tracenium.20260927-200000.bak")).toBe("Ubuntu 24.04.5 LTS \\n \\l\n\n");
    await applyGeneric(w({ kind: "banner", file: "/etc/issue", text: TEXT, restore: "Ubuntu 24.04.5 LTS \\n \\l\n\n" }), deps());
    expect(files.get("/etc/issue")).toBe("Ubuntu 24.04.5 LTS \\n \\l\n\n");
  });

  it("grub: drop-in propio + update-grub; requiere reinicio; y la relectura mira grub.cfg", async () => {
    const r = await applyGeneric(w({ kind: "grub_audit", present: true }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 0, requiresReboot: true } });
    expect(files.get("/etc/default/grub.d/99-tracenium-audit.cfg")).toBe('GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX audit=1 audit_backlog_limit=8192"\n');
    expect(calls).toContain("/usr/bin/systemd-run --wait --pipe --collect --quiet -- /usr/sbin/update-grub");
    const back = await applyGeneric(w({ kind: "grub_audit", present: false }), deps());
    expect(back).toMatchObject({ ok: true, value: { exitCode: 0 } });
    expect(files.has("/etc/default/grub.d/99-tracenium-audit.cfg")).toBe(false);
  });

  it("sin auditd no se pone audit=1; sin GRUB de Debian, nada", async () => {
    bins.delete("/usr/sbin/auditd");
    expect(await applyGeneric(w({ kind: "grub_audit", present: true }), deps())).toMatchObject({ ok: true, value: { exitCode: 2, stderrExcerpt: expect.stringMatching(/install it first/) } });
    bins.delete("/usr/sbin/update-grub");
    expect(await applyGeneric(w({ kind: "grub_audit", present: false }), deps())).toMatchObject({ ok: true, value: { exitCode: 2, stderrExcerpt: expect.stringMatching(/does not boot with the Debian\/Ubuntu GRUB/) } });
  });

  it("update-grub que falla: el drop-in vuelve a como estaba", async () => {
    execImpl = (bin, args) => (bin.endsWith("systemd-run") ? { stdout: "", stderr: "grub-mkconfig: error", code: 1 } : defaultExec(bin, args));
    const r = await applyGeneric(w({ kind: "grub_audit", present: true }), deps());
    expect(r).toMatchObject({ ok: true, value: { exitCode: 1, stderrExcerpt: expect.stringMatching(/update-grub failed/) } });
    expect(files.has("/etc/default/grub.d/99-tracenium-audit.cfg")).toBe(false);
  });

  it("sólo el texto estándar, y sólo esos tres ficheros", () => {
    expect(parseWrites(w({ kind: "banner", file: "/etc/issue", text: "Welcome to Ubuntu \\r" })).ok).toBe(false);
    expect(parseWrites(w({ kind: "banner", file: "/etc/passwd", text: TEXT })).ok).toBe(false);
  });
});
