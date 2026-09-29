// test/privsvc/linux-apt-upgradable-parse.test.ts
//
// Las actualizaciones pendientes según `apt list --upgradable`.
//
// EL CASO DE CAMPO (T118, job a6b4c204, 28-sep-2026)
//
// Un `patch_install` de Linux se cerró como `completed` en 1,15 segundos sin
// instalar nada, sobre `usuariohl-HP-14` (Ubuntu 26.04) que tenía 23 parches
// pendientes. El job decía «hecho»; Patch Management decía «Not applied · 1 of 1».
// Mentía el job.
//
// La cadena tenía TRES eslabones, y los tres se fijan aquí:
//
//   1. El nombre del paquete se recuperaba parseando `title`, que es un texto de
//      PRESENTACIÓN escrito de dos formas según si se conocía la versión vieja.
//   2. Esa versión vieja no se conocía NUNCA en ese equipo, porque `runCmd` no
//      fijaba el locale: apt en español imprime `[actualizable desde: …]` y la
//      expresión en inglés no casaba.
//   3. Los únicos títulos que SÍ tenían dos puntos eran los de versiones con
//      epoch (`1:50.2.2`), y para esos el parseo extraía «nautilus 1» como
//      nombre de paquete — basura que iba directa a apt-get.

import { describe, it, expect } from "vitest";
import { parseAptUpgradable } from "../../privsvc/linux/src/patch-management";

// Salida real de un equipo en INGLÉS (la forma que el parser siempre esperó).
const EN = `Listing... Done
openssl/jammy-security 3.0.2-0ubuntu1.21 amd64 [upgradable from: 3.0.2-0ubuntu1.18]
libssl3/jammy-security 3.0.2-0ubuntu1.21 amd64 [upgradable from: 3.0.2-0ubuntu1.18]
`;

// Salida real de `usuariohl-HP-14`, en ESPAÑOL. Es la que rompía todo.
const ES = `Listando... Hecho
rust-coreutils/resolute-updates 0.10.0-1ubuntu2~26.04.1 amd64 [actualizable desde: 0.9.0-1]
nautilus/resolute-updates 1:50.2.2-0ubuntu0.2 amd64 [actualizable desde: 1:50.2.1-0ubuntu1]
`;

describe("parseAptUpgradable — el nombre del paquete es un DATO", () => {
  it("lo lleva aparte del título, en inglés", () => {
    const items = parseAptUpgradable(EN);
    expect(items.map(i => i.packageName)).toEqual(["openssl", "libssl3"]);
  });

  // ⚠️ LA PROPIEDAD QUE IMPORTA. El nombre tiene que ser correcto AUNQUE el
  // idioma del equipo nos impida leer la versión instalada. Antes se deducía del
  // título, así que perder la versión vieja se llevaba por delante el nombre.
  it("sigue siendo correcto cuando el locale se escapa y no hay versión vieja", () => {
    const items = parseAptUpgradable(ES);
    expect(items.map(i => i.packageName)).toEqual(["rust-coreutils", "nautilus"]);
  });

  // ⚠️ EL CASO QUE PRODUCÍA BASURA. Con epoch, el título es «nautilus 1:50.2.2…»
  // y el viejo `/^([^:]+):/` extraía «nautilus 1» — un nombre que no existe, que
  // se le pasaba a apt-get tal cual.
  it("una versión con epoch no contamina el nombre", () => {
    const [item] = parseAptUpgradable(
      "nautilus/resolute-updates 1:50.2.2-0ubuntu0.2 amd64 [actualizable desde: 1:50.2.1]\n"
    );
    expect(item.packageName).toBe("nautilus");
    expect(item.packageName).not.toBe("nautilus 1");
    // Y el título sí lleva dos puntos, que es lo que engañaba al parseo viejo.
    expect(item.title).toContain(":");
  });

  it("el identificador sigue siendo pkg-version, como lo guarda el catálogo", () => {
    const [item] = parseAptUpgradable(ES);
    expect(item.hotFixId).toBe("rust-coreutils-0.10.0-1ubuntu2~26.04.1");
  });
});

describe("parseAptUpgradable — el resto no se rompe", () => {
  it("marca seguridad por el pocket", () => {
    const items = parseAptUpgradable(EN);
    expect(items.every(i => i.type === "security")).toBe(true);
    expect(items.every(i => i.severity === "important")).toBe(true);
  });

  it("un pocket de updates no es seguridad", () => {
    const [item] = parseAptUpgradable(
      "nautilus/resolute-updates 1:50.2.2 amd64 [upgradable from: 1:50.2.1]\n"
    );
    expect(item.type).toBe("update");
  });

  it("marca reinicio en kernel y libc", () => {
    const items = parseAptUpgradable(
      "linux-image-generic/jammy 5.15.0-92 amd64 [upgradable from: 5.15.0-91]\n" +
        "libc6/jammy 2.35-0ubuntu3.6 amd64 [upgradable from: 2.35-0ubuntu3.5]\n" +
        "openssl/jammy 3.0.2 amd64 [upgradable from: 3.0.1]\n"
    );
    expect(items.map(i => i.rebootRequired)).toEqual([true, true, false]);
  });

  it("dos pockets en la misma línea no rompen el nombre", () => {
    // Es la forma real de T118: `resolute-updates,resolute-security`.
    const [item] = parseAptUpgradable(
      "libcurl4t64/resolute-updates,resolute-security 8.18.0-1ubuntu2.7 amd64 [upgradable from: 8.18.0-1ubuntu2.6]\n"
    );
    expect(item.packageName).toBe("libcurl4t64");
    expect(item.type).toBe("security");
  });

  it("ignora la cabecera y las líneas que no casan", () => {
    expect(parseAptUpgradable("Listing... Done\n\nbasura sin forma\n")).toEqual([]);
    expect(parseAptUpgradable("")).toEqual([]);
  });

  // El título con flecha sólo aparece cuando SÍ se leyó la versión instalada: es
  // la señal que `scanApt` usa para avisar de que el formato o el locale cambió.
  it("el título lleva la flecha sólo cuando se pudo leer la versión vieja", () => {
    expect(parseAptUpgradable(EN)[0].title).toContain(" → ");
    expect(parseAptUpgradable(ES)[0].title).not.toContain(" → ");
  });
});
