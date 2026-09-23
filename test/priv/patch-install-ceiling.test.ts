// test/priv/patch-install-ceiling.test.ts
//
// EL INVARIANTE, leído del código de verdad y no de un comentario:
//
//     plazo del job  >  presupuesto del cliente  >  techo del handler
//
// Si el cliente no sobrevive al handler, un handler que agota su techo nunca
// entrega su diagnóstico —el cliente ya se rindió— y el fallo sale como un
// timeout pelado sin resultado. Pasó en producción el 11-ago-2026 con un
// patch_install de macOS: privsvc, cliente y job valían los tres 3600 s, así
// que expiraron juntos y el job acabó sin `result_json` ninguno. El bloque de
// comentarios de privsvc-client-windows.ts lleva la cuenta: siete apariciones.
//
// Un comentario no lo sostiene. Esto lee la constante del C# y la compara con
// el presupuesto que el cliente usa de verdad, así que bajar uno sin mirar el
// otro rompe el test en vez de romper un parcheo.

import { describe, expect, it } from "vitest";
import fs from "fs";
import path from "path";
import { getTimeoutForMethod, laneForMethod } from "../../src/priv/privsvc-client-windows";

const repoRoot = path.join(__dirname, "..", "..");
const PATCH_CS = path.join(repoRoot, "privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/PatchManagement.cs");

/** `private const int InstallTimeoutMs = 60 * 60_000;` → milisegundos. */
function ceilingFromCSharp(nombre: string): number {
  const cs = fs.readFileSync(PATCH_CS, "utf8");
  const m = new RegExp(`const\\s+int\\s+${nombre}\\s*=\\s*([^;]+);`).exec(cs);
  if (!m) throw new Error(`no se encontró ${nombre} en PatchManagement.cs`);
  // La expresión es aritmética simple con separadores de miles de C#.
  const expr = m[1].replace(/_/g, "").trim();
  if (!/^[\d\s*+]+$/.test(expr)) throw new Error(`expresión no reconocida para ${nombre}: ${expr}`);
  return Number(new Function(`return (${expr})`)());
}

describe("patch.install — el invariante de presupuestos", () => {
  it("⭐ el cliente SOBREVIVE al techo del handler", () => {
    const handler = ceilingFromCSharp("InstallTimeoutMs");
    expect(getTimeoutForMethod("patch.install")).toBeGreaterThan(handler);
  });

  it("⭐ y el escaneo, igual", () => {
    const handler = ceilingFromCSharp("ScanTimeoutMs");
    expect(getTimeoutForMethod("patch.scan")).toBeGreaterThan(handler);
  });

  it("⚠️ el techo de instalación no vuelve a subir sin datos que lo pidan", () => {
    // Ninguna instalación correcta de la flota pasó de 48,3 min (mediana 0,9;
    // p90 34). 60 min deja un 25% de margen sobre la peor real; 90 no compraba
    // nada y costaba media hora de carril serial y media hora de no saber.
    const handler = ceilingFromCSharp("InstallTimeoutMs");
    expect(handler).toBe(60 * 60_000);
  });

  it("una instalación va por el carril LENTO: no puede dejar sin latidos al stream", () => {
    expect(laneForMethod("patch.install")).toBe("slow");
  });
});
