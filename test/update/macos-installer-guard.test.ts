// test/update/macos-installer-guard.test.ts
//
// 🔴 iMac-de-iMac-2 (T1, macOS 12.7.6), 30-sep: tres `installer` de 1.1.87
// parados en la cola de PackageKit (8 h 40 min, 2 h 42 min y 47 min). Cada
// intento de update lanzaba otro y contestaba `update_started`.

import { describe, it, expect } from "vitest";
import {
  INSTALLER_STALL_SEC,
  decideInstallerGuard,
  formatElapsed,
  ourInstallersIn,
  parseEtime
} from "../../src/update/macos-installer-guard";

// `ps -axo pid=,etime=,command=` tal como salió en el iMac (sin recortar).
const PS_IMAC = [
  "  380 03-20:09:30 /usr/libexec/bootinstalld",
  " 1525 03-20:04:16 /System/Library/PrivateFrameworks/PackageKit.framework/Resources/installd",
  " 3157 03-19:52:09 /System/Library/PrivateFrameworks/PackageKit.framework/Resources/system_installd",
  "61276    08:40:46 /usr/sbin/installer -pkg /Library/Application Support/Tracenium/updates/Tracenium-Agent-1.1.87-x64.pkg -target /",
  "66864    02:42:20 /usr/sbin/installer -pkg /Library/Application Support/Tracenium/updates/Tracenium-Agent-1.1.87-x64.pkg -target /",
  "68552       47:02 /usr/sbin/installer -pkg /Library/Application Support/Tracenium/updates/Tracenium-Agent-1.1.87-x64.pkg -target /",
  // Lo que NO es nuestro, aunque se parezca.
  "70001       00:12 /usr/sbin/installer -pkg /tmp/GoogleChrome.pkg -target /",
  "70002       00:12 /bin/zsh -c grep installer -pkg Tracenium-Agent-1.1.87-x64.pkg",
  ""
].join("\n");

describe("ourInstallersIn", () => {
  it("⭐ encuentra los tres del iMac, con su antigüedad", () => {
    expect(ourInstallersIn(PS_IMAC)).toEqual([
      { pid: 61276, elapsedSec: 8 * 3600 + 40 * 60 + 46 },
      { pid: 66864, elapsedSec: 2 * 3600 + 42 * 60 + 20 },
      { pid: 68552, elapsedSec: 47 * 60 + 2 }
    ]);
  });

  it("no toca installers de otros paquetes ni procesos que sólo mencionan el nombre", () => {
    const pids = ourInstallersIn(PS_IMAC).map((r) => r.pid);
    expect(pids).not.toContain(70001);
    expect(pids).not.toContain(70002);
    expect(pids).not.toContain(1525);
  });
});

describe("parseEtime", () => {
  it("entiende los cuatro formatos de ps", () => {
    expect(parseEtime("00:12")).toBe(12);
    expect(parseEtime("47:02")).toBe(2822);
    expect(parseEtime("08:40:46")).toBe(31246);
    expect(parseEtime("03-20:04:16")).toBe(3 * 86400 + 20 * 3600 + 4 * 60 + 16);
    expect(parseEtime("basura")).toBeNaN();
  });
});

describe("decideInstallerGuard", () => {
  it("sin installers nuestros, se sigue", () => {
    expect(decideInstallerGuard([])).toEqual({ action: "none" });
  });

  it("uno reciente: se espera y se dice cuál", () => {
    expect(decideInstallerGuard([{ pid: 9, elapsedSec: 120 }])).toEqual({ action: "wait", pid: 9, elapsedSec: 120 });
  });

  it("⭐ el caso del iMac: uno pasa del límite → atascado, y se van TODOS (esperan en la misma cola)", () => {
    expect(decideInstallerGuard(ourInstallersIn(PS_IMAC))).toEqual({
      action: "stalled",
      pids: [61276, 66864, 68552],
      oldestSec: 31246
    });
  });

  it("el límite es media hora, y se cuenta desde que llega", () => {
    expect(INSTALLER_STALL_SEC).toBe(1800);
    expect(decideInstallerGuard([{ pid: 1, elapsedSec: 1799 }]).action).toBe("wait");
    expect(decideInstallerGuard([{ pid: 1, elapsedSec: 1800 }]).action).toBe("stalled");
  });
});

describe("formatElapsed", () => {
  it("minutos, u horas y minutos", () => {
    expect(formatElapsed(47 * 60 + 2)).toBe("47 min");
    expect(formatElapsed(31246)).toBe("8 h 40 min");
    expect(formatElapsed(7200)).toBe("2 h");
  });
});
