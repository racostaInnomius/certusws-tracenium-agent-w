// test/plugins/printers-windows.test.ts
//
// Lo que privsvc manda desde un servidor de impresión, convertido a Printer.
// Los valores imitan una cola real de T111 (MSIG-WSUS\CasticoPrintroom).

import { describe, it, expect } from "vitest";
import { collectWindowsPrinters } from "../../src/plugins/amp/providers/printers-windows";

function ctxWith(result: unknown) {
  return {
    enrollment: { tenantId: "t", deviceId: "d" },
    logger: { warn: () => {} },
    priv: { call: async () => ({ ok: true, result }) }
  } as any;
}

describe("collectWindowsPrinters — campos del servidor de impresión", () => {
  it("lleva shareName y la dirección del puerto", async () => {
    const r = await collectWindowsPrinters(ctxWith({
      machineScope: "collected",
      userScope: "collected",
      items: [{
        name: "Castico Printroom", driverName: "HP Universal Printing PCL 6", portName: "HP-Castico",
        shared: true, shareName: "CasticoPrintroom", hostAddress: "10.20.11.39", printerStatus: "Normal"
      }]
    }));
    expect(r.printers[0]).toMatchObject({
      shareName: "CasticoPrintroom",
      hostAddress: "10.20.11.39",
      isShared: true,
      // El puerto se llama "HP-Castico", pero tiene dirección TCP/IP: es de red.
      isNetwork: true
    });
  });

  it("un privsvc anterior sin esos campos deja null, no undefined ni cadena vacía", async () => {
    const r = await collectWindowsPrinters(ctxWith({
      machineScope: "collected", userScope: "collected",
      items: [{ name: "USB HP", portName: "USB001", shareName: "  ", printerStatus: "Normal" }]
    }));
    expect(r.printers[0].shareName).toBeNull();
    expect(r.printers[0].hostAddress).toBeNull();
    expect(r.printers[0].isNetwork).toBe(false);
  });
});
