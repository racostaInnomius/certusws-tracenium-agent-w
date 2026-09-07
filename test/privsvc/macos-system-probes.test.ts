// test/privsvc/macos-system-probes.test.ts
//
// Fase 5 del cierre de brecha CIS (macOS): preferencias por usuario,
// perfiles de configuración aplanados, volúmenes, world-writable, pistas,
// Time Machine, sueño, banner, Touch ID. Parsers puros + resolución con
// deps inyectadas.

import { describe, expect, it } from "vitest";
import { collectMacProbes, parsePwpolicy, parseProbe, type MacProbeDeps } from "../../privsvc/macos/src/macos-probes";
import {
  flattenProfiles, localUsers, parseDiskutilInfo, parseDiskutilList, parseHints, parseProfilesStatus, parseTimeMachine, parseUserprefKey,
} from "../../privsvc/macos/src/macos-system-probes";

function deps(): MacProbeDeps {
  const st = (mode: number, uid = 0, gid = 0) => ({ mode, uid, gid, isDir: (mode & 0o170000) === 0o040000, isFile: (mode & 0o170000) === 0o100000 });
  const stats: Record<string, ReturnType<typeof st>> = {
    "/Users/alice": st(0o40700, 501, 20), "/Users/bob": st(0o40755, 502, 20), "/Users/Shared": st(0o41777, 0, 0), "/Users/Guest": st(0o40700, 201, 20),
    "/Library/Security/PolicyBanner.txt": st(0o100644), "/Users/Guest/x": st(0o100644),
  };
  const dirs: Record<string, string[]> = { "/Users": ["Shared", "alice", "bob", "Guest", ".localized"], "/Library/Security": ["PolicyBanner.txt", "audit"] };
  const profilesJson = JSON.stringify({ SPConfigurationProfileDataType: [{ _name: "spconfigprofile_section_systemprofiles", _items: [{ _name: "Safari", _items: [{ _name: "com.apple.Safari", AutoOpenSafeDownloads: 0, "WebKitPreferences.storageBlockingPolicy": 1, nested: { ShowOverlayStatusBar: 1 } }] }] }] });
  return {
    readFile: () => null,
    stat: (p) => stats[p] ?? (p in dirs ? st(0o40755) : null),
    readdir: (p) => dirs[p] ?? [],
    exec: async (bin, args) => {
      if (bin.endsWith("/sudo")) {
        const user = args[1]; const key = args[args.length - 1]; const host = args.includes("-currentHost");
        if (bin.endsWith("/sudo") && args[2].endsWith("bioutil")) return { stdout: `User Touch ID configuration:\nTouch ID for unlock: ${user === "alice" ? 1 : 0}\nTouch ID for ApplePay: 0\n`, stderr: "", code: 0 };
        if (key === "PrefKeyServicesEnabled" && host) return user === "alice" ? { stdout: "1\n", stderr: "", code: 0 } : { stdout: "", stderr: "The domain/default pair does not exist", code: 1 };
        if (key === "wvous-bl-corner") return { stdout: user === "bob" ? "6\n" : "2\n", stderr: "", code: 0 };
        if (key === "WBSPrivacyProxyAvailabilityTraffic") return { stdout: "33422564\n", stderr: "", code: 0 };
        return { stdout: "", stderr: "does not exist", code: 1 };
      }
      if (bin.endsWith("/system_profiler")) return { stdout: profilesJson, stderr: "", code: 0 };
      if (bin.endsWith("/defaults")) return args[1]?.includes("TimeMachine") ? { stdout: "{\n    AutoBackup = 1;\n    Destinations = ( { DestinationID = X; LastKnownEncryptionState = NotEncrypted; } );\n}\n", stderr: "", code: 0 } : { stdout: '{\n    "com.apple.Maps" = { Authorized = 1; };\n    "com.example.app" = { Authorized = 1; };\n}\n', stderr: "", code: 0 };
      if (bin.endsWith("/dscl")) return { stdout: ".\n-list /Users hint\nalice mydog\nbob\n_svc x\n", stderr: "", code: 0 };
      if (bin.endsWith("/find")) return args[0].includes("Applications") ? { stdout: "/System/Volumes/Data/Applications/Xcode.app\n/System/Volumes/Data/Applications/Bad.app\n", stderr: "", code: 0 } : { stdout: "", stderr: "", code: 0 };
      if (bin.endsWith("/diskutil")) {
        if (args[0] === "cs") return { stdout: "CoreStorage logical volume groups (1 found)\n+-> Logical Volume Family X\n    Encryption Type: None\n", stderr: "", code: 0 };
        if (args[0] === "list") return args[1] === "internal" ? { stdout: "/dev/disk3 (synthesized):\n   1: APFS Volume Macintosh HD 10 GB disk3s1\n   2: APFS Volume Preboot 1 GB disk3s2\n   3: APFS Volume Data 100 GB disk3s5\n", stderr: "", code: 0 } : { stdout: "/dev/disk4 (external, physical):\n   1: Apple_HFS Backup 1 TB disk4s2\n   2: Microsoft Basic Data STICK 32 GB disk5s1\n", stderr: "", code: 0 };
        const id = args[1];
        return { stdout: `   Volume Name:               ${id === "disk3s2" ? "Preboot" : id === "disk3s5" ? "Data" : id === "disk4s2" ? "Backup" : "Macintosh HD"}\n   FileVault:                 ${id === "disk3s5" ? "No" : "Yes"}\n`, stderr: "", code: 0 };
      }
      if (bin.endsWith("/sysctl")) return { stdout: args[1] === "hw.model" ? "Mac15,6\n" : "Apple M3 Pro\n", stderr: "", code: 0 };
      if (bin.endsWith("/pmset")) return { stdout: "Battery Power:\n sleep                10\n displaysleep         15\n standbydelaylow      600\n hibernatemode        25\n", stderr: "", code: 0 };
      if (bin.endsWith("/bioutil")) return { stdout: "System Touch ID configuration:\nTouch ID timeout (in seconds): 172800\n", stderr: "", code: 0 };
      if (bin.endsWith("/profiles")) return { stdout: "Enrolled via DEP: No\nMDM enrollment: Yes (User Approved)\n", stderr: "", code: 0 };
      if (bin.endsWith("/sqlite3")) return { stdout: "", stderr: "unable to open database", code: 1 };
      return { stdout: "", stderr: "", code: 1 };
    },
    userName: (uid) => ({ 501: "alice", 502: "bob" } as Record<number, string>)[uid] ?? null,
    groupName: () => "staff",
  };
}

describe("parsers", () => {
  it("userpref key modes", () => {
    expect(parseUserprefKey("host:com~apple~Bluetooth:PrefKeyServicesEnabled")).toEqual({ mode: "host", domain: "com.apple.Bluetooth", name: "PrefKeyServicesEnabled" });
    expect(parseUserprefKey("home:Library/Containers/com~apple~Safari/Data/Library/Preferences/com~apple~Safari:WBSPrivacyProxyAvailabilityTraffic")).toMatchObject({ mode: "home", domain: "Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari" });
    expect(parseUserprefKey("~GlobalPreferences:LDMGlobalEnabled")).toEqual({ mode: "plain", domain: ".GlobalPreferences", name: "LDMGlobalEnabled" });
    expect(parseProbe("userpref.host:com~apple~Bluetooth:PrefKeyServicesEnabled")?.kind).toBe("userpref");
    expect(parseProbe("profile.WebKitPreferences~storageBlockingPolicy")?.kind).toBe("profile");
  });
  it("profiles flatten, last wins, nested payloads walked", () => {
    expect(flattenProfiles({ a: [{ _name: "x", _items: [{ K: 1, nested: { J: "v" } }, { K: 2 }] }] })).toEqual({ K: 2, J: "v" });
  });
  it("time machine, hints, diskutil", () => {
    expect(parseTimeMachine("AutoBackup = 1;\nDestinationID = A;\nLastKnownEncryptionState = NotEncrypted;\nDestinationID = B;\nLastKnownEncryptionState = Encrypted;\n")).toEqual({ autoBackup: true, destinations: 2, notEncrypted: 1 });
    expect(parseHints(".\nalice mydog\nbob\n_svc x\n")).toEqual(["alice"]);
    expect(parseDiskutilList("   1: APFS Volume X 1 GB disk3s1\n   2: Apple_HFS Y 1 GB disk4s2\n   3: Microsoft Basic Data Z 1 GB disk5s1\n")).toEqual({ apfs: ["disk3s1"], hfs: ["disk4s2"], fat: ["disk5s1"] });
    expect(parseDiskutilInfo("   Volume Name:  X\n   FileVault:    No\n")).toEqual({ name: "X", encrypted: false });
    expect(parseDiskutilInfo("   Volume Name:  Y\n   Encrypted:    Yes\n")).toEqual({ name: "Y", encrypted: true });
  });
  it("pwpolicy complexity flags", () => {
    const p = parsePwpolicy("<key>policyContent</key><string>policyAttributePassword matches '(.*[^a-zA-Z0-9].*){1,}'</string><key>minimumMixedCaseCharacters</key><integer>1</integer><key>policyContentDescription</key><string>Contain at least one number and one alphabetic character.</string>");
    expect(p).toMatchObject({ requiresAlpha: true, requiresNumeric: true, requiresSpecial: true, requiresMixedCase: true });
    expect(parsePwpolicy("<key>minimumLength</key><integer>15</integer>")).toMatchObject({ requiresAlpha: false, requiresSpecial: false, requiresMixedCase: false });
  });
  it("local users skip Shared, Guest and system uids", () => {
    expect(localUsers(deps()).map((u) => u.name)).toEqual(["alice", "bob"]);
  });
});

describe("collectMacProbes — fase 5", () => {
  it("userpref aggregates per user; profile is one system_profiler; mac.* summaries", async () => {
    const r = await collectMacProbes([
      "userpref.host:com~apple~Bluetooth:PrefKeyServicesEnabled", "userpref.com~apple~dock:wvous-bl-corner", "userpref.home:Library/Containers/com~apple~Safari/Data/Library/Preferences/com~apple~Safari:WBSPrivacyProxyAvailabilityTraffic", "userpref.nope",
      "profile.AutoOpenSafeDownloads", "profile.WebKitPreferences~storageBlockingPolicy", "profile.ShowOverlayStatusBar", "profile.Missing",
      "mac.mdm", "mac.efi", "mac.timemachine", "mac.hints", "mac.homefolders", "mac.wwapps", "mac.wwsystem", "mac.volumes", "mac.policybanner", "mac.sleep", "mac.touchid", "mac.locationclients", "mac.fulldiskaccess",
    ], deps());
    expect(r.errors).toEqual({});
    expect(r.probes.userpref["host:com~apple~Bluetooth:PrefKeyServicesEnabled"]).toMatchObject({ users: 2, present: 1, missing: 1, distinct: ["1"], byUser: { alice: 1 } });
    expect(r.probes.userpref["com~apple~dock:wvous-bl-corner"]).toMatchObject({ distinct: ["2", "6"] });
    expect(r.probes.userpref["home:Library/Containers/com~apple~Safari/Data/Library/Preferences/com~apple~Safari:WBSPrivacyProxyAvailabilityTraffic"]).toMatchObject({ present: 2, distinct: ["33422564"] });
    expect(r.probes.userpref).not.toHaveProperty("nope");
    expect(r.probes.profile.AutoOpenSafeDownloads).toBe(0);
    expect(r.probes.profile["WebKitPreferences~storageBlockingPolicy"]).toBe(1);
    expect(r.probes.profile.ShowOverlayStatusBar).toBe(1);
    expect(r.probes.profile).not.toHaveProperty("Missing");
    expect(r.probes.mac.timemachine).toEqual({ autoBackup: true, destinations: 1, notEncrypted: 1 });
    expect(r.probes.mac.hints).toEqual({ usersWithHint: ["alice"] });
    expect(r.probes.mac.homefolders).toEqual({ checked: 2, insecure: ["bob: 0755"] });
    expect(r.probes.mac.wwapps).toMatchObject({ count: 1, sample: ["/System/Volumes/Data/Applications/Bad.app"], timedOut: false });
    expect(r.probes.mac.wwsystem).toMatchObject({ count: 0 });
    expect(r.probes.mac.volumes).toMatchObject({ internalUnencrypted: 1, externalUnencrypted: 0, externalFat: ["disk5s1"], coreStorageFamilies: 1, coreStorageUnencrypted: 1 });
    expect((r.probes.mac.volumes as any).internal.map((v: any) => v.name)).toEqual(["Macintosh HD", "Data"]);
    expect(r.probes.mac.policybanner).toEqual({ exists: true, files: [{ name: "PolicyBanner.txt", mode: "0644", worldReadable: true }], modeOk: true });
    expect(r.probes.mac.sleep).toMatchObject({ isMacBook: false, appleSilicon: true, battery: { sleep: 10, displaysleep: 15, standbydelaylow: 600, hibernatemode: 25 }, displaySleepLeSleep: false });
    expect(r.probes.mac.touchid).toMatchObject({ timeoutSeconds: 172800, users: 2, byUser: { alice: { unlock: 1, applePay: 0 } } });
    expect(r.probes.mac.locationclients).toMatchObject({ available: true, clients: ["com.apple.Maps", "com.example.app"], count: 2 });
    expect(r.probes.mac.fulldiskaccess).toMatchObject({ available: false });
    expect(r.probes.mac.mdm).toEqual({ available: true, enrolled: true, userApproved: true, enrolledViaDep: false, raw: "Yes (User Approved)" });
    expect(r.probes.mac.efi).toEqual({ appleSilicon: true, t2: null, efiCheck: null, compliant: true });
    expect(parseProfilesStatus("MDM enrollment: No\n")).toMatchObject({ enrolled: false, userApproved: false });
  });
});
