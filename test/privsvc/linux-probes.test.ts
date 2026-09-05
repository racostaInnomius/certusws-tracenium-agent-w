// test/privsvc/linux-probes.test.ts
//
// Fase 2 del cierre de brecha CIS: sondas genéricas de Linux. Lo que se
// fija: la forma de la sonda (kind cerrado, sin shell), los parsers puros
// (mountinfo, key=value, modprobe), y la resolución con deps inyectadas —
// incluido que una sonda rota no tira las demás y que lo ilegible se
// omite en vez de inventarse.

import { describe, expect, it } from "vitest";
import {
  collectLinuxProbes, decodeKey, isBlacklisted, modeOctal, modprobeShowsInstallFalse, nonCommentLines,
  parseKeyValue, parseMountinfo, parseProbe, parseProcModules, probesFromParams, type ProbeDeps,
} from "../../privsvc/linux/src/linux-probes";

describe("parseProbe", () => {
  it("accepts kind.key of known kinds and rejects anything shell-like", () => {
    expect(parseProbe("kmod.cramfs")).toEqual({ kind: "kmod", key: "cramfs" });
    expect(parseProbe("conf./etc/login~defs:PASS_MAX_DAYS")).toEqual({ kind: "conf", key: "/etc/login~defs:PASS_MAX_DAYS" });
    expect(parseProbe("sysctl.net.ipv4.ip_forward")).toEqual({ kind: "sysctl", key: "net.ipv4.ip_forward" });
    expect(parseProbe("cmd.ls")).toBeNull();
    expect(parseProbe("kmod.")).toBeNull();
    expect(parseProbe("file./etc/passwd; id")).toBeNull();
    expect(parseProbe("unit.$(reboot)")).toBeNull();
    expect(decodeKey("autofs~service")).toBe("autofs.service");
    expect(probesFromParams({ linuxProbes: ["kmod.cramfs", 3] })).toEqual(["kmod.cramfs"]);
    expect(probesFromParams({})).toEqual([]);
  });
});

describe("parsers", () => {
  it("mountinfo → path with fstype and merged options", () => {
    const text =
      "24 30 0:22 / /tmp rw,nosuid,nodev,noexec,relatime shared:5 - tmpfs tmpfs rw,size=1G\n" +
      "27 30 8:2 / /home rw,relatime shared:9 - ext4 /dev/sda2 rw\n";
    const m = parseMountinfo(text);
    expect(m.get("/tmp")).toEqual({ fstype: "tmpfs", source: "tmpfs", options: ["rw", "nosuid", "nodev", "noexec", "relatime", "size=1G"] });
    expect(m.get("/home")?.fstype).toBe("ext4");
    expect(m.get("/var")).toBeUndefined();
  });
  it("key=value and key value, comments stripped, last wins, quotes removed", () => {
    const kv = parseKeyValue("# c\nPASS_MAX_DAYS 99999\nPASS_MAX_DAYS   365 # override\nminlen = 14\nStorage=\"persistent\"\n[Journal]\n");
    expect(kv.get("PASS_MAX_DAYS")).toBe("365");
    expect(kv.get("minlen")).toBe("14");
    expect(kv.get("Storage")).toBe("persistent");
  });
  it("modprobe / procmodules / blacklist / lines / mode", () => {
    expect(modprobeShowsInstallFalse("install /bin/false \n")).toBe(true);
    expect(modprobeShowsInstallFalse("insmod /lib/modules/x/cramfs.ko\n")).toBe(false);
    expect(parseProcModules("cramfs 16384 0 - Live 0x0\nxfs 1 0 - Live 0x0\n").has("cramfs")).toBe(true);
    expect(isBlacklisted(["# x\nblacklist cramfs\n"], "cramfs")).toBe(true);
    expect(isBlacklisted(["blacklist usb_storage\n"], "usb-storage")).toBe(true);
    expect(isBlacklisted(["blacklist cramfsx\n"], "cramfs")).toBe(false);
    expect(nonCommentLines("# a\n\npassword requisite pam_pwquality.so\n  # b\nauth x\n")).toEqual(["password requisite pam_pwquality.so", "auth x"]);
    expect(modeOctal(0o100644)).toBe("0644");
    expect(modeOctal(0o40755)).toBe("0755");
  });
});

function fakeDeps(over: Partial<ProbeDeps> = {}): ProbeDeps {
  const files: Record<string, string> = {
    "/proc/modules": "xfs 1 0 - Live 0x0\n",
    "/proc/self/mountinfo": "24 30 0:22 / /tmp rw,nosuid,nodev shared:5 - tmpfs tmpfs rw\n",
    "/etc/modprobe.d/cis.conf": "blacklist cramfs\n",
    "/etc/login.defs": "PASS_MAX_DAYS 365\n",
    "/etc/login.defs.d/10.conf": "PASS_MAX_DAYS 180\n",
    "/etc/pam.d/common-password": "# c\npassword requisite pam_pwquality.so retry=3\n",
    "/proc/sys/net/ipv4/ip_forward": "0\n",
    "/etc/audit/rules.d/50-scope.rules": "# scope\n-w /etc/sudoers -p wa -k scope\n",
    "/etc/audit/rules.d/99-finalize.rules": "-e 2\n",
  };
  const stats: Record<string, { mode: number; uid: number; gid: number; isDir: boolean; isFile: boolean }> = {
    "/etc/passwd": { mode: 0o100644, uid: 0, gid: 0, isDir: false, isFile: true },
    "/etc/ssh/sshd_config.d": { mode: 0o40755, uid: 0, gid: 0, isDir: true, isFile: false },
    "/etc/ssh/sshd_config.d/a.conf": { mode: 0o100600, uid: 0, gid: 0, isDir: false, isFile: true },
    "/etc/ssh/sshd_config.d/b.conf": { mode: 0o100644, uid: 1000, gid: 0, isDir: false, isFile: true },
    "/etc/login.defs.d": { mode: 0o40755, uid: 0, gid: 0, isDir: true, isFile: false },
    "/etc/audit/rules.d": { mode: 0o40750, uid: 0, gid: 0, isDir: true, isFile: false },
    "/etc/audit/rules.d/50-scope.rules": { mode: 0o100640, uid: 0, gid: 0, isDir: false, isFile: true },
    "/etc/audit/rules.d/99-finalize.rules": { mode: 0o100640, uid: 0, gid: 0, isDir: false, isFile: true },
  };
  const dirs: Record<string, string[]> = { "/etc/modprobe.d": ["cis.conf"], "/etc/ssh/sshd_config.d": ["a.conf", "b.conf"], "/etc/login.defs.d": ["10.conf"], "/etc/audit/rules.d": ["99-finalize.rules", "50-scope.rules"] };
  return {
    readFile: (p) => files[p] ?? null,
    exists: (p) => p in files || p in stats || p in dirs,
    stat: (p) => stats[p] ?? null,
    readdir: (p) => dirs[p] ?? [],
    exec: async (bin, args) => {
      if (bin.endsWith("modprobe")) return args[2] === "cramfs" ? { stdout: "install /bin/false \n", stderr: "", code: 0 } : { stdout: "", stderr: "modprobe: FATAL: Module nope not found in directory /lib/modules/x", code: 1 };
      if (bin.endsWith("systemctl")) return { stdout: args[0] === "is-enabled" ? "disabled\n" : "inactive\n", stderr: "", code: 1 };
      if (bin.endsWith("dpkg-query")) return args[2] === "autofs" ? { stdout: "", stderr: "no packages found", code: 1 } : { stdout: "install ok installed\t4.0.1", stderr: "", code: 0 };
      if (bin.endsWith("sshd")) return { stdout: "usepam yes\nmaxauthtries 4\nciphers aes256-gcm@openssh.com,aes128-ctr\n", stderr: "", code: 0 };
      return { stdout: "", stderr: "", code: 1 };
    },
    userName: (uid) => (uid === 0 ? "root" : null),
    groupName: (gid) => (gid === 0 ? "root" : null),
    family: "debian",
    ...over,
  };
}

describe("collectLinuxProbes", () => {
  it("resolves every kind and indexes evidence by the probe key as sent", async () => {
    const r = await collectLinuxProbes(
      ["kmod.cramfs", "kmod.nope", "mount./tmp", "mount./var", "unit.autofs~service", "pkg.autofs", "pkg.apparmor", "file./etc/passwd", "file./nope", "files./etc/ssh/sshd_config~d", "conf./etc/login~defs:PASS_MAX_DAYS", "conf./etc/login~defs:NOPE", "lines./etc/pam~d/common-password", "lines./etc/audit/rules~d", "sysctl.net.ipv4.ip_forward", "sysctl.net.nope", "sshd.usepam", "sshd.maxauthtries", "sshd.nope", "cmd.rm"],
      fakeDeps()
    );
    expect(r.errors).toEqual({});
    expect(r.probes.kmod.cramfs).toEqual({ loaded: false, exists: true, installFalse: true, blacklisted: true });
    expect(r.probes.kmod.nope).toMatchObject({ exists: false, installFalse: false, loaded: false });
    expect(r.probes.mount["/tmp"]).toEqual({ present: true, fstype: "tmpfs", source: "tmpfs", options: ["rw", "nosuid", "nodev"] });
    expect(r.probes.mount["/var"]).toEqual({ present: false });
    expect(r.probes.unit["autofs~service"]).toMatchObject({ enabled: "disabled", active: "inactive", isEnabled: false, isActive: false, exists: true });
    expect(r.probes.pkg.autofs).toEqual({ installed: false, version: null });
    expect(r.probes.pkg.apparmor).toEqual({ installed: true, version: "4.0.1" });
    expect(r.probes.file["/etc/passwd"]).toMatchObject({ exists: true, mode: "0644", owner: "root", group: "root" });
    expect(r.probes.file["/nope"]).toEqual({ exists: false });
    // worstMode es el OR de los modos; un dueño no root cuenta.
    expect(r.probes.files["/etc/ssh/sshd_config~d"]).toMatchObject({ exists: true, count: 2, worstMode: "0644", nonRootOwner: 1, nonRootGroup: 0 });
    // El drop-in .d manda sobre el fichero base.
    expect(r.probes.conf["/etc/login~defs:PASS_MAX_DAYS"]).toBe("180");
    expect(r.probes.conf).not.toHaveProperty("/etc/login~defs:NOPE");
    expect(r.probes.lines["/etc/pam~d/common-password"]).toEqual(["password requisite pam_pwquality.so retry=3"]);
    // Un directorio concatena sus ficheros en orden de nombre.
    expect(r.probes.lines["/etc/audit/rules~d"]).toEqual(["-w /etc/sudoers -p wa -k scope", "-e 2"]);
    expect(r.probes.sshd.usepam).toBe("yes");
    expect(r.probes.sshd.maxauthtries).toBe(4);
    expect(r.probes.sshd).not.toHaveProperty("nope");
    expect(r.probes.sysctl["net.ipv4.ip_forward"]).toBe(0);
    expect(r.probes.sysctl).not.toHaveProperty("net.nope");
    expect(r.probes).not.toHaveProperty("cmd");
  });

  it("a probe that throws lands in errors and the rest still resolve", async () => {
    const deps = fakeDeps({ exec: async (bin) => { if (bin.endsWith("systemctl")) throw new Error("boom"); return { stdout: "", stderr: "", code: 1 }; } });
    const r = await collectLinuxProbes(["unit.x", "file./etc/passwd"], deps);
    expect(r.errors["unit.x"]).toMatch(/boom/);
    expect(r.probes.file["/etc/passwd"]).toMatchObject({ exists: true });
  });
});
