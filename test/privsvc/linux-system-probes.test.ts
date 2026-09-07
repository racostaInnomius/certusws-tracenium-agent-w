// test/privsvc/linux-system-probes.test.ts
//
// Fase 4 del cierre de brecha CIS: colectores dedicados de Ubuntu. Lo que se
// fija: que cada colector resume en campos contables lo que el script de
// CIS lista, que las fuentes son las declaradas (passwd -S y no /etc/shadow,
// find con /home podado) y que el kind sigue siendo cerrado.

import { describe, expect, it } from "vitest";
import { collectLinuxProbes, parseProbe, type ProbeDeps } from "../../privsvc/linux/src/linux-probes";
import {
  bannerIssues, classifyFindOutput, localMountsForScan, parseDconfValue, parseIni, parsePasswdStatus, parseProcNet,
} from "../../privsvc/linux/src/linux-system-probes";

function deps(over: Partial<ProbeDeps> = {}): ProbeDeps {
  const files: Record<string, string> = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\nsvc:x:900:900::/var/svc:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:0::/home/bob:/bin/bash\ntoor:x:0:0::/root:/bin/sh\norphan:x:1002:4242::/home/orphan:/bin/bash\n",
    "/etc/group": "root:x:0:\ndaemon:x:1:\nshadow:x:42:alice\nusers:x:100:\nsvc:x:900:\nalice:x:1000:\nbob:x:1001:\n",
    "/etc/shells": "# valid\n/bin/sh\n/bin/bash\n/usr/sbin/nologin\n",
    "/etc/login.defs": "UID_MIN 1000\n",
    "/etc/profile": "readonly TMOUT=600 ; export TMOUT\n",
    "/root/.bashrc": "umask 022\n",
    "/etc/os-release": 'NAME="Ubuntu"\nID=ubuntu\n',
    "/etc/motd": "Welcome to \\n running Ubuntu \\r\n",
    "/etc/issue": "Authorized use only\n",
    "/etc/issue.net": "Authorized use only\n",
    "/etc/pam.d/sshd": "session optional pam_motd.so motd=/run/motd.dynamic\nsession optional pam_motd.so\n",
    "/proc/self/mountinfo":
      "24 30 0:22 / /proc rw - proc proc rw\n27 30 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n28 30 8:3 / /home rw - ext4 /dev/sda3 rw\n29 30 0:5 / /run rw - tmpfs tmpfs rw\n30 30 8:4 / /var rw - xfs /dev/sda4 rw\n",
    "/proc/net/tcp": " sl local_address rem_address st\n 0: 0100007F:0019 00000000:0000 0A\n 1: 00000000:0016 00000000:0000 0A\n",
    "/proc/net/tcp6": " sl local_address rem_address st\n 0: 00000000000000000000000001000000:0019 00000000000000000000000000000000:0000 0A\n",
    "/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/sda2 audit=1 audit_backlog_limit=8192\n",
    "/boot/grub/grub.cfg": "set superusers=\"root\"\npassword_pbkdf2 root grub.pbkdf2.sha512.10000.X\nmenuentry 'Ubuntu' {\n\tlinux /vmlinuz root=/dev/sda2 audit=1 audit_backlog_limit=8192\n}\nmenuentry 'recovery' {\n\tlinux /vmlinuz root=/dev/sda2 recovery\n}\n",
    "/etc/dconf/db/gdm.d/00-login": "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='Authorized'\n[org/gnome/desktop/session]\nidle-delay=uint32 900\n",
    "/etc/dconf/db/gdm.d/locks/00-login": "/org/gnome/login-screen/banner-message-enable\n",
    "/etc/gdm3/custom.conf": "[daemon]\nWaylandEnable=false\n[xdmcp]\nEnable=true\n[debug]\nEnable=false\n",
    "/etc/audit/rules.d/50-priv.rules": "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged\n",
    "/etc/audit/rules.d/99-finalize.rules": "-e 2\n",
    "/etc/audit/auditd.conf": "log_file = /var/log/audit/audit.log\n",
    "/etc/aide/aide.conf": "/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512\n/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512\n/sbin/ausearch p+i+n+u+g+s+b\n",
    "/proc/100/status": "Name:\tchronyd\nUid:\t123\t123\t123\t123\n",
    "/proc/101/status": "Name:\tchronyd\nUid:\t0\t0\t0\t0\n",
    "/sys/class/net/wlan0/operstate": "up\n",
  };
  const st = (mode: number, uid = 0, gid = 0) => ({ mode, uid, gid, isDir: (mode & 0o170000) === 0o040000, isFile: (mode & 0o170000) === 0o100000 });
  const stats: Record<string, ReturnType<typeof st>> = {
    "/root": st(0o40700), "/home/alice": st(0o40755, 1000, 1000), "/home/bob": st(0o40750, 1001, 0), "/var/svc": st(0o40750, 0, 0),
    "/usr/local/sbin": st(0o40755), "/usr/bin": st(0o40775),
    "/etc/motd": st(0o100644), "/etc/issue.net": st(0o100644),
    "/etc/dconf/db/gdm.d/00-login": st(0o100644), "/etc/dconf/db/gdm.d/locks/00-login": st(0o100644), "/etc/dconf/profile/gdm": st(0o100644),
    "/etc/audit/rules.d": st(0o40750), "/etc/audit/rules.d/50-priv.rules": st(0o100640), "/etc/audit/rules.d/99-finalize.rules": st(0o100644, 0, 1000),
    "/etc/audit/auditd.conf": st(0o100640),
    "/var/log/audit": st(0o40750), "/var/log/audit/audit.log": st(0o100600), "/var/log/audit/audit.log.1": st(0o100640, 0, 4),
    "/usr/sbin/auditctl": st(0o100755), "/usr/sbin/auditd": st(0o100755), "/usr/sbin/ausearch": st(0o100775, 0, 1000), "/usr/sbin/aureport": st(0o100755),
    "/var/log": st(0o40755), "/var/log/syslog": st(0o100640, 0, 4), "/var/log/lastlog": st(0o100664, 0, 43), "/var/log/app.log": st(0o100666, 0, 0), "/var/log/journal": st(0o40755), "/var/log/journal/system.journal": st(0o100640, 0, 190),
    "/etc/ssh/ssh_host_ed25519_key": st(0o100600), "/etc/ssh/ssh_host_ed25519_key.pub": st(0o100644), "/etc/ssh/ssh_host_rsa_key": st(0o100644, 0, 0),
    "/sys/class/net/wlan0/wireless": st(0o40755), "/etc/aide/aide.conf": st(0o100644),
  };
  const dirs: Record<string, string[]> = {
    "/etc/profile.d": [], "/etc/dconf/db": ["gdm.d", "local.d"], "/etc/dconf/db/gdm.d": ["00-login", "locks"], "/etc/dconf/db/gdm.d/locks": ["00-login"], "/etc/dconf/profile": ["gdm"],
    "/etc/audit": ["auditd.conf", "rules.d"], "/etc/audit/rules.d": ["50-priv.rules", "99-finalize.rules"], "/var/log/audit": ["audit.log", "audit.log.1"],
    "/var/log": ["syslog", "lastlog", "app.log", "journal", "audit"], "/var/log/journal": ["system.journal"],
    "/etc/ssh": ["ssh_host_ed25519_key", "ssh_host_ed25519_key.pub", "ssh_host_rsa_key", "sshd_config"], "/proc": ["100", "101", "self"], "/sys/class/net": ["lo", "eth0", "wlan0"],
    "/etc/aide/aide.conf.d": [], "/etc/motd.d": [],
  };
  const users: Record<number, string> = { 0: "root", 1: "daemon", 900: "svc", 1000: "alice", 1001: "bob", 123: "_chrony" };
  const groups: Record<number, string> = { 0: "root", 4: "adm", 42: "shadow", 43: "utmp", 190: "systemd-journal", 1000: "alice", 1001: "bob" };
  return {
    readFile: (p) => files[p] ?? null,
    exists: (p) => p in files || p in stats || p in dirs,
    stat: (p) => stats[p] ?? (p in dirs ? st(0o40755) : null),
    readdir: (p) => dirs[p] ?? [],
    exec: async (bin, args) => {
      if (bin.endsWith("/passwd")) return { stdout: "root P 2024-01-10 0 99999 7 -1\ndaemon L 2024-01-10 0 99999 7 -1\nsvc P 2024-01-10 0 99999 7 90\nalice P 2099-01-01 0 99999 7 30\nbob NP 2024-01-10 0 99999 7 -1\ntoor P 2024-01-10 0 99999 7 -1\norphan P 2024-01-10 0 99999 7 -1\n", stderr: "", code: 0 };
      if (bin.endsWith("/useradd")) return { stdout: "GROUP=100\nINACTIVE=45\n", stderr: "", code: 0 };
      if (bin.endsWith("/bash")) return { stdout: "/usr/local/sbin:/usr/bin::/nope:.", stderr: "", code: 0 };
      if (bin.endsWith("/find")) return { stdout: "f\t666\t0\t0\t/var/tmp/ww.txt\nd\t1777\t0\t0\t/tmp\nd\t777\t0\t0\t/opt/open\nf\t644\t4242\t0\t/opt/orphan\nf\t4755\t0\t0\t/usr/bin/sudo\nf\t2755\t0\t0\t/usr/bin/wall\n", stderr: "find: '/x': Permission denied\n", code: 0 };
      if (bin.endsWith("/auditctl")) return args[0] === "-l" ? { stdout: "-a always,exit -F path=/usr/bin/sudo -F perm=x -k privileged\n", stderr: "", code: 0 } : { stdout: "enabled 2\nfailure 1\n", stderr: "", code: 0 };
      if (bin.endsWith("/sshd")) return { stdout: "banner /etc/issue.net\nkexalgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256\n", stderr: "", code: 0 };
      return { stdout: "", stderr: "", code: 1 };
    },
    userName: (uid) => users[uid] ?? null,
    groupName: (gid) => groups[gid] ?? null,
    family: "debian",
    ...over,
  };
}

describe("parsers", () => {
  it("passwd -S in ISO and US date formats", () => {
    const m = parsePasswdStatus("root P 2024-01-10 0 99999 7 -1\nold L 01/10/2024 0 99999 7 5\n");
    expect(m.get("root")?.status).toBe("P");
    expect(m.get("root")?.changed?.toISOString()).toBe("2024-01-10T00:00:00.000Z");
    expect(m.get("old")?.changed?.toISOString()).toBe("2024-01-10T00:00:00.000Z");
    expect(m.get("old")?.inactive).toBe(5);
  });
  it("ini sections are case-insensitive and comments are dropped", () => {
    const ini = parseIni("[Daemon]\nWaylandEnable=false # x\n[xdmcp]\nEnable=true\n");
    expect(ini.get("daemon")?.get("waylandenable")).toBe("false");
    expect(ini.get("xdmcp")?.get("enable")).toBe("true");
  });
  it("dconf values: bool, typed ints, quoted strings", () => {
    expect(parseDconfValue("true")).toBe(true);
    expect(parseDconfValue("uint32 900")).toBe(900);
    expect(parseDconfValue("'Authorized'")).toBe("Authorized");
    expect(parseDconfValue("5")).toBe(5);
  });
  it("proc/net hex addresses and listen state", () => {
    expect(parseProcNet(" sl local rem st\n 0: 0100007F:0019 00000000:0000 0A\n 1: 0100007F:0019 00000000:0000 01\n", 25, true)).toEqual(["127.0.0.1"]);
    expect(parseProcNet(" sl local rem st\n 0: 00000000000000000000000001000000:0019 0:0 0A\n", 25, true)).toEqual(["0:0:0:0:0:0:0:1"]);
  });
  it("mount selection skips pseudo filesystems and the privacy boundary", () => {
    expect(localMountsForScan("24 30 0:22 / /proc rw - proc proc rw\n27 30 8:2 / / rw - ext4 /dev/sda2 rw\n28 30 8:3 / /home rw - ext4 /dev/sda3 rw\n30 30 8:4 / /var rw - xfs /dev/sda4 rw\n31 30 0:9 / /run/user/1000 rw - tmpfs tmpfs rw\n32 30 7:1 / /snap/core/1 ro - squashfs /dev/loop1 ro\n")).toEqual(["/", "/var"]);
  });
  it("find output classification: sticky dirs are fine, unowned counted, suid listed", () => {
    const r = classifyFindOutput("f\t666\t0\t0\t/a\nd\t1777\t0\t0\t/tmp\nd\t777\t0\t0\t/open\nf\t644\t4242\t0\t/orphan\nf\t4755\t0\t0\t/usr/bin/sudo\n", deps());
    expect(r).toMatchObject({ worldWritableFiles: 1, worldWritableDirs: 1, unowned: 1, ungrouped: 0, suidSgid: ["/usr/bin/sudo"] });
  });
  it("banner issues: escapes and OS id, word-bounded", () => {
    expect(bannerIssues("Kernel \\r on \\m", "ubuntu")).toEqual(["escape sequence"]);
    expect(bannerIssues("Welcome to Ubuntu", "ubuntu")).toEqual(["os name (ubuntu)"]);
    expect(bannerIssues("ubuntuish text", "ubuntu")).toEqual([]);
  });
  it("new kinds are accepted, unknown still rejected", () => {
    expect(parseProbe("users.audit")).toEqual({ kind: "users", key: "audit" });
    expect(parseProbe("dconf.org/gnome/login-screen:banner-message-enable")).toEqual({ kind: "dconf", key: "org/gnome/login-screen:banner-message-enable" });
    expect(parseProbe("cmd.find")).toBeNull();
  });
});

describe("collectLinuxProbes — dedicated collectors", () => {
  it("users.audit summarises passwd/group/shadow-status without reading /etc/shadow", async () => {
    const d = deps();
    const r = await collectLinuxProbes(["users.audit"], d);
    expect(r.errors).toEqual({});
    const u = r.probes.users.audit as any;
    expect(u.uid0).toEqual(["root", "toor"]);
    expect(u.gid0Users).toEqual(["root", "bob", "toor"]);
    expect(u.duplicateUids).toEqual([0]);
    expect(u.groupsMissing).toEqual(["4242"]);
    expect(u.shadowGroupMembers).toEqual(["alice"]);
    expect(u.systemAccountsWithShell).toEqual(["svc", "toor"]);
    expect(u.noLoginShellUnlocked).toEqual([]);
    expect(u.emptyPasswords).toEqual(["bob"]);
    expect(u.rootPasswordStatus).toBe("P");
    expect(u.inactiveDefault).toBe(45);
    expect(u.inactiveOver45).toEqual(["svc"]);
    expect(u.lastChangeInFuture).toEqual(["alice"]);
    expect(u.homeIssues).toEqual([{ user: "svc", issue: "owner:root" }, { user: "alice", issue: "mode:0755" }, { user: "orphan", issue: "missing" }]);
    expect(u.tmout).toMatchObject({ configured: true, value: 600, readonly: true, exported: true });
    expect(u.rootUmaskViolations).toEqual(["/root/.bashrc:022"]);
    expect(u.rootPath.issues).toEqual(["empty entry (::)", "/usr/bin: mode 0775", "/nope: missing", "current directory (.)"]);
  });

  it("fs.scan prunes /home and /root and shares its SUID list with auditd.privileged", async () => {
    const calls: string[][] = [];
    const d = deps({ exec: async (bin, args) => { if (bin.endsWith("/find")) calls.push(args); return deps().exec(bin, args); } });
    const r = await collectLinuxProbes(["fs.scan", "auditd.privileged", "fs.varlog"], d);
    expect(r.errors).toEqual({});
    expect(calls).toHaveLength(1);
    expect(calls[0].slice(0, 3)).toEqual(["/", "/var", "-xdev"]);
    expect(calls[0]).toContain("/home");
    expect(calls[0]).toContain("-prune");
    expect(r.probes.fs.scan).toMatchObject({ mounts: ["/", "/var"], worldWritableFiles: 1, worldWritableDirs: 1, unowned: 1, suidSgid: ["/usr/bin/sudo", "/usr/bin/wall"], denied: 1, timedOut: false });
    expect(r.probes.auditd.privileged).toMatchObject({ binaries: 2, missingOnDisk: 1, missingRunning: 1, sampleMissing: ["/usr/bin/wall"], auditctlAvailable: true });
    // /var/log: syslog 0640 root:adm ok; lastlog 0664 root:utmp ok; app.log 0666 mal; journal 0640 root:systemd-journal ok; audit.log.1 es del default (0640 root:adm ok)
    expect(r.probes.fs.varlog).toMatchObject({ files: 6, violations: 1 });
    expect((r.probes.fs.varlog as any).sample[0]).toMatch(/app\.log: mode 0666/);
  });

  it("dconf, ini, listen, net, grub, banner, proc, sshkeys, aide, auditd.*", async () => {
    const r = await collectLinuxProbes([
      "dconf.org/gnome/login-screen:banner-message-enable", "dconf.org/gnome/desktop/session:idle-delay", "dconf.org/gnome/desktop/screensaver:lock-delay", "dconf.profile",
      "ini./etc/gdm3/custom~conf:xdmcp:Enable", "ini./etc/gdm3/custom~conf:daemon:WaylandEnable", "ini./etc/gdm3/custom~conf:nope:x",
      "listen.25", "listen.22", "listen.99999", "net.wireless", "grub.password", "grub.cmdline",
      "banner./etc/issue", "banner.motd", "banner.pam_motd", "banner.sshd", "proc.chronyd", "proc.nope", "sshkeys.host", "aide.integrity",
      "auditd.immutable", "auditd.logfiles", "auditd.configfiles", "auditd.tools",
    ], deps());
    expect(r.errors).toEqual({});
    expect(r.probes.dconf["org/gnome/login-screen:banner-message-enable"]).toEqual({ present: true, value: true, locked: true });
    expect(r.probes.dconf["org/gnome/desktop/session:idle-delay"]).toEqual({ present: true, value: 900, locked: false });
    expect(r.probes.dconf["org/gnome/desktop/screensaver:lock-delay"]).toEqual({ present: false, value: null, locked: false });
    expect(r.probes.dconf.profile).toEqual({ profiles: ["gdm"], keys: 3, locks: 1 });
    expect(r.probes.ini["/etc/gdm3/custom~conf:xdmcp:Enable"]).toBe("true");
    expect(r.probes.ini["/etc/gdm3/custom~conf:daemon:WaylandEnable"]).toBe("false");
    expect(r.probes.ini).not.toHaveProperty("/etc/gdm3/custom~conf:nope:x");
    expect(r.probes.listen["25"]).toEqual({ listening: true, nonLoopback: false, addrs: ["tcp:127.0.0.1", "tcp:0:0:0:0:0:0:0:1"] });
    expect(r.probes.listen["22"]).toMatchObject({ listening: true, nonLoopback: true });
    expect(r.probes.listen).not.toHaveProperty("99999");
    expect(r.probes.net.wireless).toEqual({ interfaces: ["wlan0"], up: ["wlan0"] });
    expect(r.probes.grub.password).toMatchObject({ exists: true, superusers: true, password: true });
    expect(r.probes.grub.cmdline).toMatchObject({ linuxEntries: 2, entriesWithoutAudit1: 1, entriesWithoutBacklogLimit: 1, currentAudit1: true, currentBacklogLimit: 8192 });
    expect(r.probes.banner["/etc/issue"]).toMatchObject({ exists: true, clean: true, issues: [] });
    expect(r.probes.banner.motd).toMatchObject({ files: 1, violations: 1 });
    expect(r.probes.banner.pam_motd).toMatchObject({ violations: 1, services: [{ service: "sshd", lines: 2, withoutMotdArg: 1, badMotdFiles: [] }] });
    expect(r.probes.banner.sshd).toEqual({ configured: true, path: "/etc/issue.net", exists: true, mode: "0644", owner: "root", group: "root" });
    expect(r.probes.proc.chronyd).toEqual({ running: true, pids: 2, users: ["_chrony", "root"] });
    expect(r.probes.proc.nope).toEqual({ running: false, pids: 0, users: [] });
    expect(r.probes.sshkeys.host).toMatchObject({ private: 2, public: 1, privateViolations: 1, publicViolations: 0 });
    expect(r.probes.aide.integrity).toEqual({ configured: true, toolsCovered: 2, toolsMissing: ["aureport", "ausearch", "autrace", "augenrules"] });
    expect(r.probes.auditd.immutable).toEqual({ onDisk: true, lastEnabledLine: "-e 2", running: 2 });
    expect(r.probes.auditd.logfiles).toMatchObject({ dir: "/var/log/audit", exists: true, dirMode: "0750", files: 2, worstMode: "0640", nonRootOwner: 0, groupNotRootAdm: 0 });
    expect(r.probes.auditd.configfiles).toEqual({ count: 3, worstMode: "0644", nonRootOwner: 0, nonRootGroup: 1 });
    expect(r.probes.auditd.tools).toMatchObject({ present: 4, missing: ["autrace", "augenrules"], worstMode: "0775", nonRootGroup: 1 });
  });
});
