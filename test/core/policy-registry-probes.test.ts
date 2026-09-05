// test/core/policy-registry-probes.test.ts
//
// Las sondas de registro que el control plane inyecta en la policy
// (`compliance.registryProbes`). El agente no decide cuáles leer: lee
// las que le manden. Pero la policy viaja como JSON y se puede editar en
// crudo, así que la lista se ACOTA antes de llegar al PrivSvc, que corre
// como SYSTEM.

import { describe, expect, it } from "vitest";
import { PolicyRuntime, sanitizeRegistryProbes, sanitizeRegistryUserProbes, sanitizeLinuxProbes } from "../../src/core/policy-runtime";

const OK = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10:Start";

describe("sanitizeRegistryProbes", () => {
  it("keeps well-formed HKLM probes verbatim (they are the evidence keys)", () => {
    // La sonda es literalmente la clave con la que el catálogo indexa la
    // evidencia (`registry.<sonda>`): cualquier normalización aquí
    // rompería el cruce con el evaluador.
    expect(sanitizeRegistryProbes([OK])).toEqual([OK]);
    const spaced = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services:fDisableCdm";
    expect(sanitizeRegistryProbes([spaced])).toEqual([spaced]);
  });

  it("only HKLM: SYSTEM's HKCU is not the user's", () => {
    expect(sanitizeRegistryProbes(["HKCU\\Software\\Policies\\Foo:Bar"])).toEqual([]);
    expect(sanitizeRegistryProbes(["HKEY_LOCAL_MACHINE\\Software\\Foo:Bar"])).toEqual([]);
  });

  it("drops malformed shapes instead of guessing", () => {
    expect(
      sanitizeRegistryProbes([
        "HKLM\\Software\\Foo",          // sin nombre de valor
        "HKLM\\Software\\Foo:",         // nombre vacío
        "HKLM\\Software\\Fo*o:Bar",     // comodín en la subclave
        "HKLM\\Software\\Foo:Ba\\r",    // barra en el nombre del valor
        "HKLM\\Software\\Foo:Bar\nX",   // salto de línea
        42,
        null,
        "",
        "   "
      ])
    ).toEqual([]);
  });

  it("dedupes and trims", () => {
    expect(sanitizeRegistryProbes([` ${OK} `, OK, OK])).toEqual([OK]);
  });

  it("caps length per probe and count overall", () => {
    const long = "HKLM\\" + "a".repeat(400) + ":b";
    expect(sanitizeRegistryProbes([long])).toEqual([]);
    const many = Array.from({ length: 2500 }, (_, i) => `HKLM\\Software\\K${i}:V`);
    expect(sanitizeRegistryProbes(many)).toHaveLength(2000);
  });

  it("survives a non-array value", () => {
    expect(sanitizeRegistryProbes(OK)).toEqual([]);
    expect(sanitizeRegistryProbes(undefined)).toEqual([]);
    expect(sanitizeRegistryProbes({ 0: OK })).toEqual([]);
  });
});

describe("policyRuntime.getRegistryProbes", () => {
  function runtimeWith(policy: any): any {
    const rt: any = Object.create(PolicyRuntime.prototype);
    rt.policy = policy;
    return rt;
  }

  it("returns the list the policy carries", () => {
    expect(runtimeWith({ compliance: { registryProbes: [OK] } }).getRegistryProbes()).toEqual([OK]);
  });

  it("is empty when the control plane sent none — the PrivSvc then emits no block", () => {
    expect(runtimeWith({}).getRegistryProbes()).toEqual([]);
    expect(runtimeWith({ compliance: {} }).getRegistryProbes()).toEqual([]);
  });
});

// Fase 1 del cierre de brecha CIS: sondas de registro DE USUARIO. Sin hive
// (el PrivSvc las resuelve bajo cada HKEY_USERS\<SID> cargado).
describe("sanitizeRegistryUserProbes", () => {
  const U = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments:SaveZoneInformation";

  it("keeps relative probes verbatim", () => {
    expect(sanitizeRegistryUserProbes([U, ` ${U} `, U])).toEqual([U]);
  });

  it("rejects anything with a hive, a leading backslash or wildcards", () => {
    expect(
      sanitizeRegistryUserProbes([
        "HKCU\\Software\\Foo:Bar",
        "HKU\\S-1-5-21-1\\Software\\Foo:Bar",
        "\\Software\\Foo:Bar",
        "Software\\Fo*o:Bar",
        "Software\\Foo",
        "Software\\Foo:",
        42,
        null
      ])
    ).toEqual([]);
  });

  it("is read from the policy and empty by default", () => {
    const rt: any = Object.create(PolicyRuntime.prototype);
    rt.policy = { compliance: { registryUserProbes: [U] } };
    expect(rt.getRegistryUserProbes()).toEqual([U]);
    rt.policy = {};
    expect(rt.getRegistryUserProbes()).toEqual([]);
  });
});

// Fase 2 del cierre de brecha CIS: sondas genéricas de Linux. Kind cerrado,
// key sin nada que parezca un comando.
describe("sanitizeLinuxProbes", () => {
  it("keeps kind.key probes of known kinds", () => {
    const ok = ["kmod.cramfs", "mount./tmp", "unit.autofs~service", "pkg.apparmor-utils", "file./etc/passwd", "conf./etc/login~defs:PASS_MAX_DAYS", "lines./etc/pam~d/common-password", "sysctl.net.ipv4.ip_forward", "files./etc/ssh/sshd_config~d"];
    expect(sanitizeLinuxProbes(ok)).toEqual(ok);
  });
  it("rejects unknown kinds, empty keys and anything shell-like", () => {
    expect(sanitizeLinuxProbes(["cmd.ls", "kmod.", "kmod", "file./etc/passwd; rm -rf /", "unit.$(id)", "pkg.a|b", "lines./etc/x`y`", 3, null])).toEqual([]);
  });
  it("is read from the policy and empty by default", () => {
    const rt: any = Object.create(PolicyRuntime.prototype);
    rt.policy = { compliance: { linuxProbes: ["kmod.cramfs"] } };
    expect(rt.getLinuxProbes()).toEqual(["kmod.cramfs"]);
    rt.policy = {};
    expect(rt.getLinuxProbes()).toEqual([]);
  });
});
