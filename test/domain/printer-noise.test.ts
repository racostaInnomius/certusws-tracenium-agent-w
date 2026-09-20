// Qué colas no salen del equipo.
//
// ⚠️ Lo que se filtra aquí no llega nunca al backend: un falso positivo borra
// una impresora real sin rastro. Los casos son las formas REALES de
// `device_printers` en T111 (2026-09-15).

import { describe, it, expect } from "vitest";
import { printerNoiseKind } from "../../src/domain/printer";

const cola = (name: string, driver: string | null, port: string | null, hostAddress: string | null = null) =>
  ({ name, driver, port, hostAddress });

describe("printerNoiseKind — sesión RDP", () => {
  it("las redirigidas por Escritorio remoto no son del equipo", () => {
    expect(printerNoiseKind(cola("HPBD65A6 (HP Officejet Pro 8600) (redirected 3)", "Remote Desktop Easy Print", "TS008"))).toBe("session");
    expect(printerNoiseKind(cola("Fax (redirected 12)", "Remote Desktop Easy Print", "TS005"))).toBe("session");
    expect(printerNoiseKind(cola("Algo", null, "TS014"))).toBe("session");
  });
});

describe("printerNoiseKind — virtuales, sólo por puerto", () => {
  it.each([
    ["Microsoft Print to PDF", "Microsoft Print To PDF", "PORTPROMPT:"],
    ["Microsoft XPS Document Writer", "Microsoft XPS Document Writer v4", "PORTPROMPT:"],
    ["OneNote (Desktop)", "Send to Microsoft OneNote 16 Driver", "nul:"],
    ["ABS PDF Driver v400", "Amyuni Document Converter 450", "NUL:"],
    ["Fax", "Microsoft Shared Fax Driver", "SHRFAX:"],
    ["Adobe PDF", "Adobe PDF Converter", "Documents\\*.pdf"],
    ["LogMeIn Resolve Printer", "Microsoft Print To PDF", "C:\\Program Files (x86)\\GoTo Resolve Unattended\\1\\remoteprint\\print.pdf"],
    ["HP Universal Fax Driver", "HP Universal Fax Driver", "HPUFD_Fax_Port"],
    ["Fax - HP OfficeJet Pro 6960", "HPOJ6960_Fax_Driver", "HPOJ6960_Fax_Port"],
    ["Nitro PDF Creator", "Nitro PDF Driver 14", "Nitro PDF 14 Port:"],
    ["AnyDesk Printer", "AnyDesk v4 Printer Driver", "AD_Port"],
    ["TSPrint PDF", "TSPrintDRV", "TSPRINTPort:"],
    ["PDF", "CUPS-PDF", "cups-pdf:/"],
    // Control remoto: imprime al equipo de quien está conectado, no en papel.
    ["RustDesk Printer", "RustDesk v4 Printer Driver", "RustDesk Printer"],
  ])("%s", (name, driver, port) => {
    expect(printerNoiseKind(cola(name, driver, port))).toBe("virtual");
  });

  it("⚠️ el nombre o el driver no bastan: con puerto de red, se envía", () => {
    expect(printerNoiseKind(cola("Fax Contabilidad", "HP LaserJet Pro MFP Fax", "IP_10.100.17.72"))).toBeNull();
    expect(printerNoiseKind(cola("Adobe PDF", "Adobe PDF Converter", "10.0.0.5"))).toBeNull();
  });

  it("⚠️ una cola con dirección medida o UNC nunca es virtual", () => {
    expect(printerNoiseKind(cola("Rara", null, "nul:", "10.100.19.79"))).toBeNull();
    expect(printerNoiseKind(cola("\\\\MSIG-WSUS\\Printroom", null, "\\\\MSIG-WSUS"))).toBeNull();
  });

  it("⚠️ WSD, USB y colas TCP/IP viajan: la pestaña decide si cuentan", () => {
    expect(printerNoiseKind(cola("RICOH MP C3504", "Microsoft IPP Class Driver", "WSD-60d0600f-f10d-4d2c-9a1b-000000000000"))).toBeNull();
    expect(printerNoiseKind(cola("AccountSpecialist3", "HP LaserJet Pro M428f-M429f PCL-6 (V4)", "IP4_60d0600f-f10d-4d2c-9a1b-000000000000_10.100.17.84"))).toBeNull();
    expect(printerNoiseKind(cola("ZDesigner ZT410-203dpi ZPL", "ZDesigner ZT410-203dpi ZPL", "USB001"))).toBeNull();
    expect(printerNoiseKind(cola("009", "MKR7MI01", "MI7_MON02"))).toBeNull();
  });
});
