// test/plugins/sdp-reboot.test.ts
//
// Reboot semantics for SDP. These are pure functions precisely so the Windows
// exit codes can be exercised from any host — the orchestrator's platform-fit
// check makes an end-to-end Windows install untestable on a macOS/Linux dev box
// or CI runner, and the codes that matter most (3010/1641) are Windows-only.

import { describe, expect, it } from "vitest";
import {
  EXIT_REBOOT_INITIATED,
  EXIT_REBOOT_REQUIRED,
  EXIT_RESTART_REQUIRED,
  EXIT_WU_ALREADY_INSTALLED,
  EXIT_WU_REBOOT_REQUIRED,
  decideReboot,
  formatSuccessExitCodes,
  rebootExitCodesFor,
  shouldSkipPostDetect,
  withRebootExitCodes,
  withSuccessExitCodes,
} from "../../src/plugins/sdp/reboot";

const base = {
  platform: "windows" as const,
  exitCode: 0 as number | undefined,
  packageRequiresReboot: false as unknown,
  mode: "install" as const,
};

describe("decideReboot — exit-code evidence", () => {
  it("treats 3010 as reboot required, not yet started", () => {
    const d = decideReboot({ ...base, exitCode: EXIT_REBOOT_REQUIRED });
    expect(d.rebootRequired).toBe(true);
    expect(d.reason).toBe("exit_reboot_required");
    expect(d.rebootInProgress).toBe(false);
  });

  it("treats 1641 as reboot already under way", () => {
    const d = decideReboot({ ...base, exitCode: EXIT_REBOOT_INITIATED });
    expect(d.rebootRequired).toBe(true);
    expect(d.reason).toBe("exit_reboot_initiated");
    expect(d.rebootInProgress).toBe(true);
  });

  it("reports no reboot for a plain success", () => {
    expect(decideReboot({ ...base, exitCode: 0 })).toEqual({
      rebootRequired: false,
      rebootInProgress: false,
    });
  });

  // The regression this module exists to fix: 3010 is a Windows Installer code.
  // On a .pkg or a .deb it is an arbitrary number the maintainer chose, and
  // reading reboot intent into it invents a meaning the package never assigned.
  it.each(["macos", "linux"] as const)("does not read 3010 as reboot on %s", (platform) => {
    const d = decideReboot({ ...base, platform, exitCode: EXIT_REBOOT_REQUIRED });
    expect(d.rebootRequired).toBe(false);
  });

  it.each(["macos", "linux"] as const)("does not read 1641 as reboot on %s", (platform) => {
    expect(decideReboot({ ...base, platform, exitCode: EXIT_REBOOT_INITIATED }).rebootRequired).toBe(
      false
    );
  });
});

describe("decideReboot — catalog declaration", () => {
  // The whole point of the change: requires_reboot was shipped to the agent on
  // every dispatch and read by nobody.
  it("honours requiresReboot when the exit code carries no reboot meaning", () => {
    const d = decideReboot({ ...base, exitCode: 0, packageRequiresReboot: true });
    expect(d.rebootRequired).toBe(true);
    expect(d.reason).toBe("package_requires_reboot");
    expect(d.rebootInProgress).toBe(false);
  });

  it.each(["windows", "macos", "linux"] as const)(
    "honours requiresReboot on %s — the flag is platform-independent",
    (platform) => {
      const d = decideReboot({ ...base, platform, exitCode: 0, packageRequiresReboot: true });
      expect(d.rebootRequired).toBe(true);
      expect(d.reason).toBe("package_requires_reboot");
    }
  );

  it("still honours requiresReboot when the runner reported no exit code", () => {
    const d = decideReboot({ ...base, exitCode: undefined, packageRequiresReboot: true });
    expect(d.rebootRequired).toBe(true);
    expect(d.reason).toBe("package_requires_reboot");
  });

  // Strict === true. The flag arrives as untyped JSON from the job payload; a
  // truthy-but-wrong value means the sender is confused, and guessing on its
  // behalf would silently mark installs reboot-pending.
  it.each([["true"], [1], ["yes"], [{}]])("ignores a non-boolean %p", (value) => {
    expect(
      decideReboot({ ...base, exitCode: 0, packageRequiresReboot: value }).rebootRequired
    ).toBe(false);
  });

  it("does not apply the flag to an uninstall — it is a claim about installing", () => {
    const d = decideReboot({ ...base, exitCode: 0, packageRequiresReboot: true, mode: "uninstall" });
    expect(d.rebootRequired).toBe(false);
  });

  it("still applies exit-code evidence to an uninstall (msiexec /x returns 3010 too)", () => {
    const d = decideReboot({
      ...base,
      exitCode: EXIT_REBOOT_REQUIRED,
      packageRequiresReboot: false,
      mode: "uninstall",
    });
    expect(d.rebootRequired).toBe(true);
    expect(d.reason).toBe("exit_reboot_required");
  });

  it("applies the flag to a reinstall", () => {
    const d = decideReboot({ ...base, exitCode: 0, packageRequiresReboot: true, mode: "reinstall" });
    expect(d.rebootRequired).toBe(true);
  });
});

describe("decideReboot — precedence", () => {
  // Observed beats declared: the exit code describes THIS run, the flag is a
  // claim someone typed. The reason field has to say which one spoke.
  it("prefers the exit code over the catalog flag", () => {
    const d = decideReboot({
      ...base,
      exitCode: EXIT_REBOOT_INITIATED,
      packageRequiresReboot: true,
    });
    expect(d.reason).toBe("exit_reboot_initiated");
    expect(d.rebootInProgress).toBe(true);
  });
});

describe("withRebootExitCodes", () => {
  it("adds every Windows reboot code to an operator list that omits them", () => {
    // 3011 y 2359301 se sumaron con `msu`, pero NO se gatean por formato: son
    // códigos de Windows y un EXE que envuelve el motor de servicing puede
    // devolverlos igual, exactamente por lo que 3010 no se gatea en `msi`.
    expect(withRebootExitCodes([0], "windows")).toEqual([0, 3010, 1641, 3011, 2359301]);
  });

  // The catalog default is [0, 3010], so in practice the widening usually adds
  // only 1641 — the code that made a successful reboot-initiating install read
  // as a permanent failure.
  it("adds only what is missing, without duplicating", () => {
    expect(withRebootExitCodes([0, 3010], "windows")).toEqual([0, 3010, 1641, 3011, 2359301]);
  });

  it("leaves a list that already covers all of them untouched", () => {
    // Identidad referencial, no sólo igualdad: el valor tiene que seguir siendo
    // comparable con lo que guarda el catálogo.
    const input = [0, 1641, 3010, 3011, 2359301];
    expect(withRebootExitCodes(input, "windows")).toBe(input);
  });

  it.each(["macos", "linux"] as const)("does not widen on %s", (platform) => {
    const input = [0, 3010];
    expect(withRebootExitCodes(input, platform)).toBe(input);
  });

  it("preserves the operator's other codes", () => {
    expect(withRebootExitCodes([0, 1605, 3010], "windows")).toEqual([
      0, 1605, 3010, 1641, 3011, 2359301,
    ]);
  });
});

describe("rebootExitCodesFor", () => {
  it("covers Windows only", () => {
    expect(rebootExitCodesFor("windows")).toEqual([3010, 1641, 3011, 2359301]);
    expect(rebootExitCodesFor("macos")).toEqual([]);
    expect(rebootExitCodesFor("linux")).toEqual([]);
  });
});

describe("shouldSkipPostDetect", () => {
  // Probing a machine that is tearing down services would grade a shutdown
  // artifact as post_detect_mismatch and turn a success into a permanent
  // failure. A 3010 machine is still up, so the silent-no-op check stays.
  it("skips only when the reboot has already started", () => {
    expect(
      shouldSkipPostDetect(decideReboot({ ...base, exitCode: EXIT_REBOOT_INITIATED }))
    ).toBe(true);
    expect(
      shouldSkipPostDetect(decideReboot({ ...base, exitCode: EXIT_REBOOT_REQUIRED }))
    ).toBe(false);
    expect(shouldSkipPostDetect(decideReboot({ ...base, exitCode: 0 }))).toBe(false);
    expect(
      shouldSkipPostDetect(
        decideReboot({ ...base, exitCode: 0, packageRequiresReboot: true })
      )
    ).toBe(false);
  });
});


// ── Los éxitos propios del FORMATO ───────────────────────────────────────────
//
// El caso: KB5129237 en T111. Un `.msu` puede salir con 2359302 —«ya estaba
// instalado»— que es un ÉXITO documentado y no estaba mapeado en ninguno de los
// dos repos. Fuera del conjunto esperado, sdp/index.ts lo grada `failed` con
// ackStatus 2, que el orquestador NO reintenta: el parche quedaría marcado como
// fallido para siempre sobre un equipo que lo tiene puesto.

describe("formatSuccessExitCodes", () => {
  it("añade «ya instalado» sólo para msu", () => {
    expect(formatSuccessExitCodes("msu")).toEqual([EXIT_WU_ALREADY_INSTALLED]);
  });

  it.each(["msi", "exe", "deb", "rpm", "pkg", "dmg", "tar.gz", "unknown"])(
    "no añade nada para %s",
    (format) => {
      expect(formatSuccessExitCodes(format)).toEqual([]);
    }
  );

  // ⚠️ LA SEPARACIÓN QUE IMPORTA. 2359302 no habla de reinicios. Si estuviera en
  // rebootExitCodesFor, `decideReboot` marcaría un «ya estaba» como
  // reboot_required — y un reinicio pendiente que nadie necesita es una ventana
  // de mantenimiento gastada y un servicio caído sin motivo.
  it("«ya instalado» NO es un código de reinicio", () => {
    expect(rebootExitCodesFor("windows")).not.toContain(EXIT_WU_ALREADY_INSTALLED);
    const d = decideReboot({ ...base, exitCode: EXIT_WU_ALREADY_INSTALLED });
    expect(d.rebootRequired).toBe(false);
    expect(d.rebootInProgress).toBe(false);
  });

  // Y al revés: los dos que sí hablan de reinicio lo marcan, sin darlo por
  // iniciado (la máquina sigue en pie, así que el post-detect sigue corriendo).
  it.each([EXIT_RESTART_REQUIRED, EXIT_WU_REBOOT_REQUIRED])(
    "%i pide reinicio sin haberlo empezado",
    (code) => {
      const d = decideReboot({ ...base, exitCode: code });
      expect(d.rebootRequired).toBe(true);
      expect(d.rebootInProgress).toBe(false);
      expect(shouldSkipPostDetect(d)).toBe(false);
    }
  );
});

describe("withSuccessExitCodes", () => {
  it("mete 2359302 en el conjunto esperado de un msu", () => {
    expect(withSuccessExitCodes([0, 3010], "msu")).toEqual([0, 3010, EXIT_WU_ALREADY_INSTALLED]);
  });

  it("devuelve la entrada INTACTA cuando no hay nada que añadir", () => {
    const input = [0, 3010];
    expect(withSuccessExitCodes(input, "msi")).toBe(input);
    const ya = [0, EXIT_WU_ALREADY_INSTALLED];
    expect(withSuccessExitCodes(ya, "msu")).toBe(ya);
  });

  // La composición real del orquestador: primero los de reinicio de la
  // plataforma, después los del formato. Es la que decide si un parche instalado
  // se cierra como hecho o como fallido.
  it("compuesta con withRebootExitCodes cubre los cuatro éxitos de un msu", () => {
    const expected = withSuccessExitCodes(withRebootExitCodes([0, 3010], "windows"), "msu");
    for (const code of [0, 3010, 1641, 3011, 2359301, 2359302]) {
      expect(expected).toContain(code);
    }
    // Y no cuela un fallo de verdad.
    expect(expected).not.toContain(1603);
    expect(expected).not.toContain(0x800f081e);
  });

  it("en macOS y Linux un msu no ensancha nada de reinicios", () => {
    // `msu` no existe fuera de Windows, pero si llegara, el ensanche de formato
    // no debe inventar códigos de reinicio que esa plataforma no tiene.
    expect(withSuccessExitCodes(withRebootExitCodes([0], "macos"), "msu")).toEqual([
      0,
      EXIT_WU_ALREADY_INSTALLED,
    ]);
  });
});
