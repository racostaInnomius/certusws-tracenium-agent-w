// Quién publica un paquete de Linux.
//
// Los colectores mandaban el nombre del GESTOR en el campo del fabricante, y
// el efecto medido en el tenant 1 fue que "Unknown" encabezaba el ranking de
// publishers con 950 de 1671 filas — el 57%. Lo que se fija aquí es que la
// ausencia se envíe como ausencia y que un Maintainer real sobreviva.

import { describe, it, expect } from "vitest";
import { parsePackagePublisher, publisherFromPackageFields } from "../../src/domain/package-publisher";

describe("parsePackagePublisher", () => {
  it("se queda con el nombre y tira el correo", () => {
    // La forma real de un Maintainer de dpkg.
    expect(parsePackagePublisher("Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>")).toBe(
      "Ubuntu Developers"
    );
    expect(parsePackagePublisher("Debian Apache Maintainers <debian-apache@lists.debian.org>")).toBe(
      "Debian Apache Maintainers"
    );
  });

  it("⚠️ el correo se tira porque FRAGMENTA el ranking", () => {
    // El mismo equipo publica bajo varias direcciones; con el correo dentro,
    // cada una seria un fabricante distinto en la grafica.
    const a = parsePackagePublisher("Ubuntu Developers <ubuntu-devel@lists.ubuntu.com>");
    const b = parsePackagePublisher("Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>");
    expect(a).toBe(b);
  });

  it("también quita una dirección suelta sin ángulos", () => {
    expect(parsePackagePublisher("Someone Real someone@example.org")).toBe("Someone Real");
  });

  it("⚠️ rechaza el nombre del gestor de paquetes", () => {
    // Éste es el valor que se estaba enviando, y el que puso "Unknown" en la
    // cima del ranking de un tenant entero.
    for (const v of ["dpkg", "rpm", "snap", "flatpak", "homebrew", "pkgutil", "DPKG", " rpm "]) {
      expect(parsePackagePublisher(v)).toBeUndefined();
    }
  });

  it("rechaza los rellenos que no dicen nada", () => {
    for (const v of ["", "  ", "unknown", "Unknown", "n/a", "none", "null", "-", "x"]) {
      expect(parsePackagePublisher(v)).toBeUndefined();
    }
  });

  it("⚠️ devuelve undefined y NUNCA la palabra 'Unknown'", () => {
    // Mandar "Unknown" desde el agente seria fabricar un dato: el backend ya
    // sabe agrupar la ausencia, y solo el backend sabe como llamarla.
    expect(parsePackagePublisher(null)).toBeUndefined();
    expect(parsePackagePublisher(undefined)).toBeUndefined();
    expect(parsePackagePublisher(42)).toBeUndefined();
    // rpm imprime "(none)" cuando el paquete no declara Vendor.
    expect(parsePackagePublisher("(none)")).toBeUndefined();
  });

  it("acota un Maintainer larguisimo", () => {
    // Algunos traen parrafos, y esto viaja en cada snapshot por cada paquete.
    const largo = parsePackagePublisher("A".repeat(400));
    expect(largo).toHaveLength(120);
  });

  it("limpia la coma que queda al sacar el correo de una lista", () => {
    expect(parsePackagePublisher("Team One <a@b.c>, ")).toBe("Team One");
  });
});

describe("publisherFromPackageFields", () => {
  it("el Vendor de rpm gana sobre el Maintainer", () => {
    // Vendor describe a quien CONSTRUYO el paquete; Maintainer a quien lo
    // cuida. Para un inventario de software importa el primero.
    expect(
      publisherFromPackageFields({ vendor: "Red Hat, Inc.", maintainer: "Alguien <a@b.c>" })
    ).toBe("Red Hat, Inc.");
  });

  it("cae al Maintainer cuando no hay Vendor utilizable", () => {
    expect(publisherFromPackageFields({ vendor: "(none)", maintainer: "Ubuntu Developers <a@b.c>" }))
      .toBe("Ubuntu Developers");
    expect(publisherFromPackageFields({ vendor: "", maintainer: "Ubuntu Developers <a@b.c>" }))
      .toBe("Ubuntu Developers");
  });

  it("sin ninguno de los dos, ausencia", () => {
    expect(publisherFromPackageFields({})).toBeUndefined();
    expect(publisherFromPackageFields({ vendor: "rpm", maintainer: "dpkg" })).toBeUndefined();
  });
});
