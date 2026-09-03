// test/privsvc/linux-ufw-ssh-guard.test.ts
//
// `ufw --force enable` sin regla para SSH corta el acceso al equipo. El
// handler asumía que ufw traía OpenSSH permitido de fábrica (falso en
// Ubuntu). Estos tests fijan la secuencia: puerto efectivo de sshd
// permitido ANTES del enable, y nada abierto si no hay sshd.

import { describe, it, expect } from "vitest";
import { planUfwEnable, sshPortsFromSshdT } from "../../privsvc/linux/src/pmp-remediation";

const SSHD_T_DEFAULT = ["port 22", "addressfamily any", "permitrootlogin no"].join("\n");
const SSHD_T_CUSTOM = ["addressfamily any", "port 2222", "port 22022", "permitrootlogin no"].join("\n");

describe("sshPortsFromSshdT", () => {
  it("lee el puerto efectivo, no el 22 por costumbre", () => {
    expect(sshPortsFromSshdT(SSHD_T_CUSTOM)).toEqual([2222, 22022]);
  });
  it("22 cuando sshd -T no dice puerto (o no se pudo leer)", () => {
    expect(sshPortsFromSshdT("")).toEqual([22]);
    expect(sshPortsFromSshdT("addressfamily any")).toEqual([22]);
  });
  it("ignora basura y duplicados", () => {
    expect(sshPortsFromSshdT("port 22\nport 22\nport 0\nport 70000\nports 5")).toEqual([22]);
  });
});

describe("planUfwEnable", () => {
  it("permite SSH y sólo después activa", () => {
    const steps = planUfwEnable({ sshdActive: true, sshdRendered: SSHD_T_DEFAULT });
    expect(steps.map((s) => s.args.join(" "))).toEqual([
      "allow 22/tcp comment Tracenium: keep SSH reachable",
      "--force enable",
    ]);
    expect(steps.at(-1)!.change).toBe("ufw-enabled");
    expect(steps[0].change).toBe("ufw-allow-22/tcp");
  });

  it("un sshd en puerto no estándar abre ESE puerto, no el 22", () => {
    const steps = planUfwEnable({ sshdActive: true, sshdRendered: SSHD_T_CUSTOM });
    expect(steps.map((s) => s.args[1])).toEqual(["2222/tcp", "22022/tcp", "enable"]);
  });

  it("sin sshd no abre nada: sólo el enable", () => {
    const steps = planUfwEnable({ sshdActive: false, sshdRendered: SSHD_T_DEFAULT });
    expect(steps).toEqual([{ bin: "/usr/sbin/ufw", args: ["--force", "enable"], change: "ufw-enabled" }]);
  });

  it("el enable es siempre el último paso", () => {
    for (const input of [
      { sshdActive: true, sshdRendered: SSHD_T_CUSTOM },
      { sshdActive: true, sshdRendered: "" },
      { sshdActive: false, sshdRendered: "" },
    ]) {
      const steps = planUfwEnable(input);
      expect(steps.at(-1)!.args).toEqual(["--force", "enable"]);
      expect(steps.slice(0, -1).every((s) => s.args[0] === "allow")).toBe(true);
    }
  });
});
