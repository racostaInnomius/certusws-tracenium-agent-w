// test/privsvc/linux-uninstall-simulation.test.ts
//
// La simulación que va antes de cada desinstalación en Linux.
//
// ⚠️ `apt-get remove -y` y `dnf remove -y` se llevan sin preguntar todo lo que
// depende del paquete. Desde que se puede desinstalar desde el INVENTARIO
// (ADR-0019), el operador puede señalar cualquier fila; si la vista previa dice
// «un paquete» y en el equipo se van doce, la vista previa mintió en una
// operación sin deshacer. Estas pruebas fijan qué se deja pasar y qué no.
//
// Las salidas son las que imprimen los gestores con LANG=C.

import { describe, expect, it } from "vitest";
import {
  dependentsMessage,
  isPackageName,
  judgeAptSimulation,
  judgeDnfSimulation,
} from "../../privsvc/linux/src/uninstall-simulation";

const APT_HEADER = [
  "NOTE: This is only a simulation!",
  "      apt-get needs root privileges for real execution.",
  "      Keep also in mind that locking is deactivated,",
  "      so don't depend on the relevance to the real current situation!",
  "Reading package lists...",
  "Building dependency tree...",
  "Reading state information...",
].join("\n");

describe("judgeAptSimulation", () => {
  it("deja pasar un paquete que sólo se lleva a sí mismo", () => {
    const out = [
      APT_HEADER,
      "The following packages will be REMOVED:",
      "  htop",
      "0 upgraded, 0 newly installed, 1 to remove and 3 not upgraded.",
      "Remv htop [3.0.5-7build2]",
    ].join("\n");
    expect(judgeAptSimulation("htop", out, 0)).toEqual({
      ok: true,
      kind: "proceed",
      unusedDependencies: [],
    });
  });

  // ⭐ El caso clásico: quitar firefox en Ubuntu se lleva el metapaquete del
  // escritorio. Con `-y` no lo ve nadie.
  it("⭐ rechaza si se llevaría paquetes que dependen del objetivo, y dice cuáles", () => {
    const out = [
      APT_HEADER,
      "The following packages will be REMOVED:",
      "  firefox ubuntu-desktop ubuntu-desktop-minimal",
      "0 upgraded, 0 newly installed, 3 to remove and 0 not upgraded.",
      "Remv ubuntu-desktop [1.481.1]",
      "Remv ubuntu-desktop-minimal [1.481.1]",
      "Remv firefox [1:1snap1-0ubuntu2]",
    ].join("\n");
    expect(judgeAptSimulation("firefox", out, 0)).toEqual({
      ok: false,
      code: "would_remove_dependents",
      dependents: ["ubuntu-desktop", "ubuntu-desktop-minimal"],
    });
  });

  it("la arquitectura no convierte al propio paquete en un dependiente", () => {
    const out = [APT_HEADER, "Remv libfoo1:amd64 [1.2-3]"].join("\n");
    expect(judgeAptSimulation("libfoo1", out, 0)).toMatchObject({ ok: true, kind: "proceed" });
    expect(judgeAptSimulation("libfoo1:amd64", out, 0)).toMatchObject({ ok: true, kind: "proceed" });
  });

  it("un purge también cuenta", () => {
    const out = [APT_HEADER, "Purg htop [3.0.5-7build2]", "Purg htop-extra [1.0]"].join("\n");
    expect(judgeAptSimulation("htop", out, 0)).toMatchObject({
      ok: false,
      dependents: ["htop-extra"],
    });
  });

  it("no instalado es «nada que hacer», no un error", () => {
    const out = [APT_HEADER, "Package 'htop' is not installed, so not removed", "0 upgraded, 0 newly installed, 0 to remove"].join("\n");
    expect(judgeAptSimulation("htop", out, 0)).toEqual({ ok: true, kind: "not_installed" });
  });

  it("un nombre que apt no conoce tampoco es un error", () => {
    expect(judgeAptSimulation("nope", "E: Unable to locate package nope", 100)).toEqual({
      ok: true,
      kind: "not_installed",
    });
  });

  // ⚠️ Lo que no se entiende, se rechaza: con otro idioma, otra versión, o un
  // apt roto, no sabemos qué se llevaría.
  it("⭐ rechaza una salida que no lista el objetivo", () => {
    const out = [APT_HEADER, "Se eliminarán los siguientes paquetes:", "  htop"].join("\n");
    expect(judgeAptSimulation("htop", out, 0)).toMatchObject({
      ok: false,
      code: "uninstall_simulation_unreadable",
    });
  });

  // Un nombre virtual: se pide «editor» y apt quitaría el paquete que lo
  // provee. No es un dependiente — es que el pedido no es un paquete.
  it("rechaza si apt quitaría otra cosa y no el paquete pedido", () => {
    const out = [APT_HEADER, "Remv vim [2:9.1.0016-1ubuntu7]"].join("\n");
    expect(judgeAptSimulation("editor", out, 0)).toMatchObject({
      ok: false,
      code: "uninstall_simulation_unreadable",
    });
  });

  it("rechaza si apt falló por otra razón", () => {
    expect(judgeAptSimulation("htop", "E: Could not get lock /var/lib/dpkg/lock", 100)).toMatchObject({
      ok: false,
      code: "uninstall_simulation_unreadable",
    });
  });
});

const DNF4_TABLE_HEAD = [
  "Dependencies resolved.",
  "================================================================================",
  " Package             Architecture  Version                 Repository      Size",
  "================================================================================",
].join("\n");
const DNF4_TAIL = [
  "",
  "Transaction Summary",
  "================================================================================",
  "Remove  1 Package",
  "",
  "Freed space: 458 k",
  "Operation aborted.",
].join("\n");

describe("judgeDnfSimulation", () => {
  it("deja pasar un paquete que sólo se lleva a sí mismo", () => {
    const out = [
      DNF4_TABLE_HEAD,
      "Removing:",
      " htop                x86_64        3.2.1-1.el9             @epel          458 k",
      DNF4_TAIL,
    ].join("\n");
    expect(judgeDnfSimulation("htop", out)).toEqual({
      ok: true,
      kind: "proceed",
      unusedDependencies: [],
    });
  });

  it("⭐ rechaza los paquetes dependientes", () => {
    const out = [
      DNF4_TABLE_HEAD,
      "Removing:",
      " python3-libs        x86_64        3.9.18-1.el9            @baseos         32 M",
      "Removing dependent packages:",
      " python3             x86_64        3.9.18-1.el9            @baseos         25 k",
      " dnf                 noarch        4.14.0-9.el9            @baseos        476 k",
      DNF4_TAIL,
    ].join("\n");
    expect(judgeDnfSimulation("python3-libs", out)).toEqual({
      ok: false,
      code: "would_remove_dependents",
      dependents: ["python3", "dnf"],
    });
  });

  it("yum de RHEL 7 llama a la misma sección de otra forma", () => {
    const out = [
      "Dependencies Resolved",
      "Removing:",
      " httpd       x86_64     2.4.6-99.el7     @updates     9.4 M",
      "Removing for dependencies:",
      " mod_ssl     x86_64     1:2.4.6-99.el7   @updates     224 k",
      "",
      "Transaction Summary",
      "Remove  1 Package (+1 Dependent package)",
    ].join("\n");
    expect(judgeDnfSimulation("httpd", out)).toMatchObject({
      ok: false,
      dependents: ["mod_ssl"],
    });
  });

  // Las dependencias que quedan sin uso son la limpieza normal de dnf: se
  // instalaron COMO dependencia del objetivo y ya nadie las necesita.
  it("deja pasar las dependencias que quedan sin uso, pero las devuelve para decirlas", () => {
    const out = [
      DNF4_TABLE_HEAD,
      "Removing:",
      " htop                x86_64        3.2.1-1.el9             @epel          458 k",
      "Removing unused dependencies:",
      " hwloc-libs          x86_64        2.4.1-5.el9             @baseos        2.1 M",
      DNF4_TAIL,
    ].join("\n");
    expect(judgeDnfSimulation("htop", out)).toEqual({
      ok: true,
      kind: "proceed",
      unusedDependencies: ["hwloc-libs"],
    });
  });

  // ⚠️ Un nombre que es un «provides»: se pidió uno y dnf quitaría otro.
  it("⭐ rechaza si bajo «Removing:» aparece otro paquete que el pedido", () => {
    const out = [
      DNF4_TABLE_HEAD,
      "Removing:",
      " vim-enhanced        x86_64        2:8.2.2637-20.el9       @appstream     4.0 M",
      DNF4_TAIL,
    ].join("\n");
    expect(judgeDnfSimulation("vim", out)).toMatchObject({
      ok: false,
      code: "uninstall_simulation_unreadable",
    });
  });

  it("el mismo nombre en dos arquitecturas es el mismo paquete", () => {
    const out = [
      DNF4_TABLE_HEAD,
      "Removing:",
      " libfoo              x86_64        1.0-1.el9               @appstream      10 k",
      " libfoo              i686          1.0-1.el9               @appstream      10 k",
      DNF4_TAIL,
    ].join("\n");
    expect(judgeDnfSimulation("libfoo", out)).toMatchObject({ ok: true, kind: "proceed" });
  });

  // Un nombre largo se parte: la continuación va muy sangrada y su primera
  // palabra es la arquitectura. Contarla daría un «dependiente» llamado x86_64.
  it("una fila partida en dos líneas no inventa un paquete llamado x86_64", () => {
    const out = [
      DNF4_TABLE_HEAD,
      "Removing:",
      " google-chrome-stable-with-a-very-long-name",
      "                     x86_64        129.0.6668.58-1         @google-chrome 356 M",
      DNF4_TAIL,
    ].join("\n");
    expect(judgeDnfSimulation("google-chrome-stable-with-a-very-long-name", out)).toMatchObject({
      ok: true,
      kind: "proceed",
    });
  });

  it("dnf5 tiene otra cabecera de resumen y se lee igual", () => {
    const out = [
      "Package            Arch   Version        Repository      Size",
      "Removing:",
      " htop              x86_64 3.3.0-3.fc40   updates      470.0 KiB",
      "Removing dependent packages:",
      " htop-plugins      x86_64 1.0-1.fc40     updates        1.0 KiB",
      "",
      "Transaction Summary:",
      " Removing:         2 packages",
      "Operation aborted by the user.",
    ].join("\n");
    expect(judgeDnfSimulation("htop", out)).toEqual({
      ok: false,
      code: "would_remove_dependents",
      dependents: ["htop-plugins"],
    });
  });

  it("no instalado es «nada que hacer»", () => {
    expect(
      judgeDnfSimulation("nope", "No match for argument: nope\nNo packages marked for removal.\nDependencies resolved.\nNothing to do.\nComplete!")
    ).toEqual({ ok: true, kind: "not_installed" });
    expect(judgeDnfSimulation("nope", "No packages to remove for argument: nope\nNothing to do.")).toEqual({
      ok: true,
      kind: "not_installed",
    });
  });

  it("⭐ rechaza una salida sin tabla (timeout, error, otro idioma)", () => {
    expect(judgeDnfSimulation("htop", "")).toMatchObject({ ok: false, code: "uninstall_simulation_unreadable" });
    expect(judgeDnfSimulation("htop", "Error: Failed to download metadata for repo 'epel'")).toMatchObject({
      ok: false,
      code: "uninstall_simulation_unreadable",
    });
  });
});

describe("isPackageName", () => {
  it("acepta nombres reales de dpkg y rpm", () => {
    for (const n of ["htop", "libstdc++6", "python3.11", "google-chrome-stable", "libfoo1:amd64", "perl_Foo", "g++"]) {
      expect(isPackageName(n)).toBe(true);
    }
  });

  // ⚠️ Sin shell de por medio, un nombre que empiece por «-» sigue siendo una
  // OPCIÓN para apt o dnf.
  it("⭐ rechaza lo que el gestor leería como una opción", () => {
    for (const n of ["-s", "--purge", "-y", "--allow-remove-essential"]) {
      expect(isPackageName(n)).toBe(false);
    }
  });

  it("rechaza espacios, rutas y vacío", () => {
    for (const n of ["", "htop firefox", "/usr/bin/htop", "htop;rm", "htop*"]) {
      expect(isPackageName(n)).toBe(false);
    }
  });
});

describe("dependentsMessage", () => {
  it("dice qué se habría llevado y que no se tocó nada", () => {
    const m = dependentsMessage("firefox", ["ubuntu-desktop", "ubuntu-desktop-minimal"]);
    expect(m).toMatch(/ubuntu-desktop, ubuntu-desktop-minimal/);
    expect(m).toMatch(/Nothing was uninstalled/);
  });

  it("recorta una lista larga sin esconder cuántos son", () => {
    const deps = Array.from({ length: 14 }, (_, i) => `pkg${i}`);
    const m = dependentsMessage("libc", deps);
    expect(m).toMatch(/14 other package/);
    expect(m).toMatch(/and 4 more/);
    expect(m).not.toMatch(/pkg10/);
  });
});
