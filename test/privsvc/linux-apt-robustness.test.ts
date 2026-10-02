// test/privsvc/linux-apt-robustness.test.ts
//
// Auditoría PMP 1-oct-2026 — cuatro maneras en que una instalación con apt
// dejaba el equipo peor o el job mal contado:
//   1. apt corría en el cgroup del privsvc: reiniciar el servicio (un
//      agent_update) mataba a dpkg a media configuración.
//   2. needrestart reiniciaba el propio agente en mitad de su instalación.
//   3. Un dpkg interrumpido rompía todos los jobs siguientes y nadie lo
//      reparaba.
//   4. El candado de apt ocupado (apt-daily) era un fallo definitivo.

import { describe, expect, it } from "vitest";
import fs from "fs";
import path from "path";
import { aptInstallEnv, dpkgNeedsRepair, scopedInstallCommand } from "../../privsvc/linux/src/patch-management";

const SRC = fs.readFileSync(path.join(__dirname, "../../privsvc/linux/src/patch-management.ts"), "utf8");

describe("scopedInstallCommand", () => {
  it("lanza el gestor de paquetes en un scope propio, fuera del cgroup del privsvc", () => {
    const c = scopedInstallCommand("/usr/bin/apt-get", ["install", "-y", "openssl"], "tracenium-patch-1-2.scope");
    expect(c.bin).toBe("/usr/bin/systemd-run");
    expect(c.args).toEqual([
      "--scope", "--collect", "--quiet", "--slice=system.slice", "--unit=tracenium-patch-1-2.scope",
      "--", "/usr/bin/apt-get", "install", "-y", "openssl",
    ]);
  });

  it("sólo con systemd como PID 1, y si systemd-run no se puede ejecutar, directo", () => {
    expect(SRC).toMatch(/fs\.existsSync\("\/run\/systemd\/system"\)/);
    expect(SRC).toMatch(/if \(!r\.spawnError\) return r;/);
  });
});

describe("aptInstallEnv", () => {
  it("aparca needrestart y fuerza la salida en inglés", () => {
    expect(aptInstallEnv()).toMatchObject({
      DEBIAN_FRONTEND: "noninteractive",
      NEEDRESTART_SUSPEND: "1",
      NEEDRESTART_MODE: "l",
      LANG: "C",
      LC_ALL: "C",
    });
  });
});

describe("dpkgNeedsRepair", () => {
  it("una salida de `dpkg --audit` con paquetes = hay que reparar", () => {
    const audit = "The following packages are only half configured, probably due to problems\nconfiguring them the first time.\n libssl3t64           Secure Sockets Layer toolkit - shared libraries\n";
    expect(dpkgNeedsRepair({ stdout: audit, code: 0 })).toBe(true);
    expect(dpkgNeedsRepair({ stdout: "", code: 0 })).toBe(false);
  });

  it("la reparación va antes de instalar, y apt espera el candado en vez de abortar", () => {
    expect(SRC.indexOf('runCmd("/usr/bin/dpkg", ["--audit"])')).toBeLessThan(SRC.indexOf('runInstall("/usr/bin/apt-get"'));
    expect(SRC).toMatch(/"DPkg::Lock::Timeout=120"/);
  });
});

describe("candado ocupado → reintento, no fallo", () => {
  it("el privsvc responde `busy` y el agente lo convierte en ACK_RETRY (status 1)", () => {
    expect(SRC).toMatch(/status: "busy",\s*\n\s*mode,/);
    const agente = fs.readFileSync(path.join(__dirname, "../../src/transport/grpc-stream.ts"), "utf8");
    expect(agente).toMatch(/if \(rawStatus === "busy"\) \{[\s\S]{0,400}return \{ status: 1, message: `patch_install retry: /);
  });
});
