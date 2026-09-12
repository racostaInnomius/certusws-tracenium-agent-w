// ¿Es de red esta cola de impresión?
//
// ⚠️ Este fichero existe por un fallo medido en producción el 2026-09-11: las
// PRIMERAS 14 impresoras que Windows consiguió reportar —todas conexiones de
// red de usuario, `\\MSIG-WSUS\CasticoPrintroom` y compañía— llegaron
// etiquetadas como LOCALES las 14. No había caso para UNC y caían al valor
// conservador.
//
// Era inocuo mientras Windows sólo mandaba colas de máquina (`IP_10.0.0.5`,
// `USB001`); dejó de serlo en cuanto el colector empezó a leer HKEY_USERS, donde
// el puerto ES el servidor. Un fallo latente que sólo se activó al arreglar
// OTRA cosa.

import { describe, it, expect } from "vitest";
import { isNetworkPort } from "../../src/domain/printer";

describe("isNetworkPort — UNC", () => {
  it("⚠️ una cola UNC es de red", () => {
    // Los valores REALES que llegaron de T111.
    expect(isNetworkPort("\\\\MSIG-WSUS.mountainside-investment.com")).toBe(true);
    expect(isNetworkPort("\\\\10.20.11.39")).toBe(true);
    expect(isNetworkPort("\\\\SRV\\CasticoPrintroom")).toBe(true);
  });

  it("no se deja engañar por espacios", () => {
    expect(isNetworkPort("  \\\\SRV\\Cola  ")).toBe(true);
  });
});

describe("isNetworkPort — lo que ya funcionaba sigue igual", () => {
  it("los puertos de red de Windows", () => {
    // `TCP/IP_…` en minúsculas empieza por `tcp/`: es de red, y el nombre
    // clásico del puerto de Windows entra por ahí.
    expect(isNetworkPort("TCP/IP_10.0.0.5")).toBe(true);
    expect(isNetworkPort("tcp/10.0.0.5")).toBe(true);
    expect(isNetworkPort("WSD-abc")).toBe(true);
    expect(isNetworkPort("10.0.0.5")).toBe(true);
  });

  it("los URI de CUPS", () => {
    for (const p of ["ipp://x", "ipps://x", "socket://x", "lpd://x", "smb://x", "dnssd://x"]) {
      expect(isNetworkPort(p), p).toBe(true);
    }
  });

  it("⚠️ lo local sigue siendo local", () => {
    // Un USB marcado como de red confunde más que al revés: por eso el valor
    // por defecto es conservador y la lista de denegación se respeta.
    for (const p of ["USB001", "LPT1:", "COM3:", "PORTPROMPT:", "FILE:", "nul:"]) {
      expect(isNetworkPort(p), p).toBe(false);
    }
  });

  it("ausente no es de red", () => {
    expect(isNetworkPort(null)).toBe(false);
    expect(isNetworkPort(undefined)).toBe(false);
    expect(isNetworkPort("")).toBe(false);
    expect(isNetworkPort("   ")).toBe(false);
  });
});
