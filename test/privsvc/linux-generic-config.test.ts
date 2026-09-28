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
    const s = readGenericState(w(redirects), deps());
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
