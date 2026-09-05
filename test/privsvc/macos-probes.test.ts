// test/privsvc/macos-probes.test.ts
//
// Fase 3 del cierre de brecha CIS: sondas genéricas de macOS. Parsers puros
// (pmset, launchctl, systemsetup, pwpolicy, authdb, script JXA) y la
// resolución con deps inyectadas: una sola ejecución de osascript para
// todas las preferencias, kinds cerrados, errores aislados.

import { describe, expect, it } from "vitest";
import {
  buildPrefScript, collectMacProbes, parseAuthdb, parseLaunchctlList, parsePmsetCustom, parsePrefOutput, parseProbe,
  parsePwpolicy, parseSystemsetup, type MacProbeDeps,
} from "../../privsvc/macos/src/macos-probes";

describe("parsers", () => {
  it("probe shape: known kinds, spaces allowed in keys, no shell", () => {
    expect(parseProbe("pref.com~apple~assistant~support:Siri Data Sharing Opt-In Status")).toEqual({ kind: "pref", key: "com~apple~assistant~support:Siri Data Sharing Opt-In Status" });
    expect(parseProbe("mac.csrutil")).toEqual({ kind: "mac", key: "csrutil" });
    expect(parseProbe("kmod.cramfs")).toBeNull();
    expect(parseProbe("mac.csrutil; rm")).toBeNull();
  });
  it("pmset custom takes the highest value across sections", () => {
    const out = parsePmsetCustom("Battery Power:\n womp                 0\n powernap             1\nAC Power:\n womp                 0\n powernap             0\n sleep                1\n");
    expect(out.womp).toBe(0);
    expect(out.powernap).toBe(1);
    expect(out.sleep).toBe(1);
  });
  it("launchctl / systemsetup / pwpolicy / authdb", () => {
    expect(parseLaunchctlList("PID\tStatus\tLabel\n123\t0\tcom.apple.timed\n-\t0\tcom.apple.screensharing\n").has("com.apple.timed")).toBe(true);
    expect(parseSystemsetup("Network Time: On\n")).toBe(true);
    expect(parseSystemsetup("Remote Login: Off\n")).toBe(false);
    expect(parseSystemsetup("Network Time Server: time.apple.com\n")).toBe("time.apple.com");
    expect(parseSystemsetup("")).toBeNull();
    const pw = parsePwpolicy('<plist><dict><key>policyAttributeMaximumFailedAuthentications</key><integer>5</integer><key>autoEnableInSeconds</key><integer>900</integer><key>policyAttributePasswordHistoryDepth</key><integer>24</integer><key>policyContent</key><string>policyAttributePassword matches \'^.{15,}$\'</string></dict></plist>');
    expect(pw).toMatchObject({ maxFailedAuthentications: 5, autoEnableInSeconds: 900, historyDepth: 24, minLength: 15 });
    const db = parseAuthdb("<plist><dict><key>shared</key><false/><key>rule</key><array><string>authenticate-session-owner</string></array></dict></plist>");
    expect(db).toEqual({ shared: false, authenticateSessionOwner: true, rule: "authenticate-session-owner" });
  });
  it("pref script serialises suite/key pairs and its output parses", () => {
    const js = buildPrefScript([{ suite: "com.apple.screensaver", key: "idleTime" }]);
    expect(js).toContain('[["com.apple.screensaver","idleTime"]]');
    expect(parsePrefOutput('{"com.apple.screensaver:idleTime":900,"x:y":null}')).toEqual({ "com.apple.screensaver:idleTime": 900, "x:y": null });
    expect(parsePrefOutput("garbage")).toEqual({});
  });
});

function fakeDeps(): MacProbeDeps {
  return {
    readFile: (p) => (p === "/etc/security/audit_control" ? "# c\nflags:lo,aa\nexpire-after:60d\n" : null),
    stat: (p) => (p === "/etc/security/audit_control" ? { mode: 0o100440, uid: 0, gid: 0, isDir: false, isFile: true } : null),
    readdir: () => [],
    exec: async (bin, args) => {
      if (bin.endsWith("osascript")) return { stdout: '{"com.apple.screensaver:idleTime":600,"com.apple.screensaver:askForPassword":1,"com.apple.MCX:nope":null}', stderr: "", code: 0 };
      if (bin.endsWith("pmset")) return { stdout: "AC Power:\n womp 0\n powernap 1\n", stderr: "", code: 0 };
      if (bin.endsWith("launchctl")) return { stdout: "PID\tStatus\tLabel\n1\t0\tcom.apple.timed\n", stderr: "", code: 0 };
      if (bin.endsWith("systemsetup")) return { stdout: args[0] === "-getremotelogin" ? "Remote Login: Off\n" : "Network Time: On\n", stderr: "", code: 0 };
      if (bin.endsWith("csrutil")) return { stdout: args[0] === "authenticated-root" ? "Authenticated Root status: enabled\n" : "System Integrity Protection status: enabled.\n", stderr: "", code: 0 };
      if (bin.endsWith("security")) return { stdout: "<plist><dict><key>shared</key><true/></dict></plist>", stderr: "", code: 0 };
      if (bin.endsWith("sudo")) return { stdout: "Authentication timestamp timeout: 0.0 minutes\nType of authentication timestamp record: tty\nLog when a command is allowed by sudoers\n", stderr: "", code: 0 };
      return { stdout: "", stderr: "", code: 1 };
    },
    userName: (uid) => (uid === 0 ? "root" : null),
    groupName: (gid) => (gid === 0 ? "wheel" : null),
  };
}

describe("collectMacProbes", () => {
  it("resolves every kind; one osascript for all prefs; nulls are omitted", async () => {
    const r = await collectMacProbes(
      ["pref.com~apple~screensaver:idleTime", "pref.com~apple~screensaver:askForPassword", "pref.com~apple~MCX:nope", "pmset.womp", "pmset.powernap", "pmset.nope", "launchctl.com~apple~timed", "launchctl.com~apple~screensharing", "systemsetup.getremotelogin", "systemsetup.getusingnetworktime", "systemsetup.badflag", "mac.csrutil", "mac.ssv", "mac.sudo", "mac.notacmd", "authdb.system~preferences", "file./etc/security/audit_control", "lines./etc/security/audit_control", "kmod.x"],
      fakeDeps()
    );
    expect(r.errors).toEqual({});
    expect(r.probes.pref["com~apple~screensaver:idleTime"]).toBe(600);
    expect(r.probes.pref["com~apple~screensaver:askForPassword"]).toBe(1);
    expect(r.probes.pref).not.toHaveProperty("com~apple~MCX:nope");
    expect(r.probes.pmset).toEqual({ womp: 0, powernap: 1 });
    expect(r.probes.launchctl["com~apple~timed"]).toEqual({ loaded: true });
    expect(r.probes.launchctl["com~apple~screensharing"]).toEqual({ loaded: false });
    expect(r.probes.systemsetup.getremotelogin).toBe(false);
    expect(r.probes.systemsetup.getusingnetworktime).toBe(true);
    expect(r.probes.systemsetup).not.toHaveProperty("badflag");
    expect(r.probes.mac.csrutil).toEqual({ enabled: true });
    expect(r.probes.mac.ssv).toEqual({ enabled: true });
    expect(r.probes.mac.sudo).toMatchObject({ timestampTimeoutMinutes: 0, timestampType: "tty", logsAllowed: true });
    expect(r.probes.mac).not.toHaveProperty("notacmd");
    expect(r.probes.authdb["system~preferences"]).toMatchObject({ shared: true });
    expect(r.probes.file["/etc/security/audit_control"]).toMatchObject({ exists: true, mode: "0440", owner: "root", group: "wheel" });
    expect(r.probes.lines["/etc/security/audit_control"]).toEqual(["flags:lo,aa", "expire-after:60d"]);
    expect(r.probes).not.toHaveProperty("kmod");
  });
});
