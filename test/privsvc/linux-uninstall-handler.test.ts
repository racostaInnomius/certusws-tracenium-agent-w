// test/privsvc/linux-uninstall-handler.test.ts
//
// Que la simulación esté CABLEADA, no sólo escrita.
//
// Los intérpretes de la simulación tienen sus propias pruebas
// (linux-uninstall-simulation.test.ts). Pero si `handleSdpUninstall` dejara de
// llamarlos —o los llamara DESPUÉS de ejecutar— aquellas pruebas seguirían en
// verde y `apt-get remove -y` volvería a llevarse los dependientes. Lo que se
// comprueba aquí es el orden y la negativa: con dependientes, el comando real
// NO SE LANZA.

import { beforeEach, describe, expect, it, vi } from "vitest";
import fs from "fs";

const execFileMock = vi.fn();
vi.mock("child_process", () => ({
  execFile: (...args: unknown[]) => execFileMock(...args),
}));

const family = { value: "debian" };
vi.mock("../../privsvc/linux/src/distro", () => ({
  detectFamily: () => ({ id: family.value === "debian" ? "ubuntu" : "rhel", family: family.value }),
}));

vi.mock("../../privsvc/linux/src/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { handleSdpUninstall } from "../../privsvc/linux/src/sdp";

/** Respuestas por comando: la clave es «binario + argumentos». */
function answer(byCommand: Record<string, { stdout?: string; code?: number }>) {
  execFileMock.mockImplementation((cmd: string, args: string[], _opts: unknown, cb: Function) => {
    const key = `${cmd} ${args.join(" ")}`;
    const hit = byCommand[key];
    if (!hit) {
      cb(Object.assign(new Error(`unexpected command: ${key}`), { code: 127, stdout: "", stderr: "" }));
      return;
    }
    if (hit.code && hit.code !== 0) {
      cb(Object.assign(new Error("exit"), { code: hit.code, stdout: hit.stdout ?? "", stderr: "" }), {
        stdout: hit.stdout ?? "",
        stderr: "",
      });
      return;
    }
    cb(null, { stdout: hit.stdout ?? "", stderr: "" });
  });
}

const commandsRun = () => execFileMock.mock.calls.map((c) => `${c[0]} ${(c[1] as string[]).join(" ")}`);

const req = (packageName: string, format = "deb") => ({
  v: 1,
  id: "t1",
  method: "sdp.uninstall",
  params: { format, identity: { packageName }, timeoutSeconds: 120, packageId: 0 },
}) as any;

beforeEach(() => {
  execFileMock.mockReset();
  family.value = "debian";
  vi.restoreAllMocks();
});

describe("handleSdpUninstall — la simulación va ANTES y manda", () => {
  it("⭐ con dependientes NO ejecuta la desinstalación, y dice qué se habría llevado", async () => {
    answer({
      "/usr/bin/apt-get -s remove firefox": {
        stdout: "Remv ubuntu-desktop [1.481]\nRemv firefox [1:1snap1]",
      },
    });

    const res = await handleSdpUninstall(req("firefox"));

    expect(res.ok).toBe(false);
    expect(res.error?.code).toBe("would_remove_dependents");
    expect(res.error?.message).toMatch(/ubuntu-desktop/);
    expect(commandsRun()).toEqual(["/usr/bin/apt-get -s remove firefox"]); // nada más
  });

  it("⭐ sin colaterales simula y DESPUÉS desinstala", async () => {
    answer({
      "/usr/bin/apt-get -s remove htop": { stdout: "Remv htop [3.0.5]" },
      "/usr/bin/apt-get remove -y htop": { stdout: "Removing htop (3.0.5) ..." },
    });

    const res = await handleSdpUninstall(req("htop"));

    expect(res.ok).toBe(true);
    expect(res.result.exitCode).toBe(0);
    expect(commandsRun()).toEqual([
      "/usr/bin/apt-get -s remove htop",
      "/usr/bin/apt-get remove -y htop",
    ]);
  });

  it("no instalado: éxito sin ejecutar nada", async () => {
    answer({
      "/usr/bin/apt-get -s remove htop": { stdout: "Package 'htop' is not installed, so not removed" },
    });

    const res = await handleSdpUninstall(req("htop"));

    expect(res.ok).toBe(true);
    expect(res.result.exitCode).toBe(0);
    expect(commandsRun()).toEqual(["/usr/bin/apt-get -s remove htop"]);
  });

  it("una salida que no se entiende también bloquea", async () => {
    answer({ "/usr/bin/apt-get -s remove htop": { stdout: "E: Could not get lock", code: 100 } });

    const res = await handleSdpUninstall(req("htop"));

    expect(res.error?.code).toBe("uninstall_simulation_unreadable");
    expect(commandsRun()).toHaveLength(1);
  });

  // ⚠️ Desde el inventario, el nombre lo reporta un equipo. Sin shell, un
  // «-s» seguiría siendo una opción de apt.
  it("⭐ un nombre que apt leería como opción no llega a ningún comando", async () => {
    answer({});
    const res = await handleSdpUninstall(req("--purge"));
    expect(res.error?.code).toBe("identity_not_found");
    expect(execFileMock).not.toHaveBeenCalled();
  });

  it("en rpm, las dependencias sin uso se desinstalan y se dicen", async () => {
    family.value = "rhel";
    vi.spyOn(fs, "existsSync").mockImplementation((p) => String(p) === "/usr/bin/dnf");
    answer({
      "/usr/bin/dnf remove --assumeno htop": {
        code: 1, // con --assumeno, 1 es lo normal cuando hay transacción
        stdout: [
          "Removing:",
          " htop        x86_64   3.2.1-1.el9   @epel   458 k",
          "Removing unused dependencies:",
          " hwloc-libs  x86_64   2.4.1-5.el9   @baseos 2.1 M",
          "",
          "Transaction Summary",
        ].join("\n"),
      },
      "/usr/bin/dnf remove -y htop": { stdout: "Complete!" },
    });

    const res = await handleSdpUninstall(req("htop", "rpm"));

    expect(res.ok).toBe(true);
    expect(res.result.stderrExcerpt).toMatch(/also removed 1 unused dependenc\(ies\): hwloc-libs/);
    expect(commandsRun()).toEqual([
      "/usr/bin/dnf remove --assumeno htop",
      "/usr/bin/dnf remove -y htop",
    ]);
  });
});
