import { describe, it, expect } from "vitest";
import { parseAdminGroupMembership } from "../../privsvc/macos/src/security-posture";

// P2-10 — miembros del grupo admin local en macOS. Una lectura fallida es null
// (el check no se evalúa), nunca "no hay administradores".

describe("parseAdminGroupMembership", () => {
  it("lista los miembros de GroupMembership", () => {
    expect(parseAdminGroupMembership("GroupMembership: root javier soporte\n")).toEqual(["root", "javier", "soporte"]);
  });

  it("sin la clave el grupo no tiene miembros extra", () => {
    expect(parseAdminGroupMembership("No such key: GroupMembership")).toEqual([]);
  });

  it("salida ausente o ilegible = no se sabe", () => {
    expect(parseAdminGroupMembership(null)).toBeNull();
    expect(parseAdminGroupMembership("")).toBeNull();
    expect(parseAdminGroupMembership("DS Error: -14136 (eDSRecordNotFound)")).toBeNull();
  });
});
