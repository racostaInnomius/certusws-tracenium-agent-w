// test/transport/catalog-item-mapping.test.ts
//
// La proyección proto → tray del catálogo self-service.
//
// ⚠️ EXISTE PORQUE UNA PROYECCIÓN ES DONDE UN CAMPO SE PIERDE SIN RUIDO. El
// proto lo lleva, el backend lo manda, el mapa se olvida de copiarlo y el tray
// enseña lo de siempre: nada falla, no hay excepción, y el síntoma es «la
// función que pediste no aparece». `installedVersion` es justo eso — sin él,
// el botón vuelve a ofrecer «Install» sobre un paquete ya instalado, y en un
// MSI ya puesto `msiexec /i` no reinstala: entra en mantenimiento y sale 1603.

import { describe, it, expect } from "vitest";
import { mapCatalogItem } from "../../src/transport/grpc-stream";

describe("mapCatalogItem", () => {
  it("lleva installedVersion hasta el tray", () => {
    const out = mapCatalogItem({
      packageId: "8",
      name: "Google Chrome",
      vendor: "Google LLC",
      version: "152.0.7977.83",
      installedVersion: "152.0.7977.82"
    });
    expect(out.installedVersion).toBe("152.0.7977.82");
  });

  it("colapsa a undefined lo que el servidor no sabe", () => {
    // "" es lo que manda un backend que no lo sabe, y también lo que produce
    // proto3 en un backend anterior al campo. Los dos significan «no lo
    // enseñes»: si se colara "" como cadena, el tray pintaría «Installed · v».
    expect(mapCatalogItem({ packageId: "8", installedVersion: "" }).installedVersion).toBeUndefined();
    expect(mapCatalogItem({ packageId: "8" }).installedVersion).toBeUndefined();
  });

  it("no pierde el resto de campos por el camino", () => {
    const out = mapCatalogItem({
      packageId: "9",
      name: "Microsoft Edge",
      vendor: "Microsoft Corporation",
      version: "152.0.4191.66",
      description: "Silently installs Microsoft Edge",
      requiresReboot: true
    });
    expect(out).toEqual({
      packageId: "9",
      name: "Microsoft Edge",
      vendor: "Microsoft Corporation",
      version: "152.0.4191.66",
      description: "Silently installs Microsoft Edge",
      requiresReboot: true,
      installedVersion: undefined
    });
  });

  it("aguanta un ítem vacío sin reventar el catálogo entero", () => {
    // Un ítem malformado no puede tumbar la lista: el handler mapea todos de
    // una pasada y una excepción aquí dejaría al tray sin catálogo.
    const out = mapCatalogItem({});
    expect(out.packageId).toBe("");
    expect(out.requiresReboot).toBe(false);
  });
});
