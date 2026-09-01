// test/transport/cdp-job-routing.test.ts
//
// ⚠️ ESTE FICHERO EXISTE POR UN FALLO QUE LLEGÓ A PRODUCCIÓN.
//
// Las fases 2 y 3 de ADR-0011 se desplegaron en 1.1.56 y 1.1.57 con los
// handlers del PrivSvc dentro del bundle — comprobado leyéndolo en un
// host real— y aun así estaban MUERTAS: el job runner del agent-core no
// conocía `cdp_csr_generate` ni `cdp_cert_install`, así que respondía
// `runJob rejected: unsupported jobType` y las llamadas IPC no ocurrían
// nunca.
//
// Lo más incómodo: el backend tiene su propia lista (`isSupportedJobType`)
// y le escribí un test citando el precedente de los seis tipos del
// gateway... mientras la lista del AGENTE, que es otra, quedaba sin
// tocar. Ninguna suite lo vio. Se descubrió ejercitando el flujo de
// verdad contra un equipo real.
//
// Por eso esto se prueba leyendo el FUENTE del despachador y no montando
// el stream: lo que hay que garantizar es que el `case` exista y llame a
// lo que debe. Es una comprobación débil —cubre «se dejó de enrutar», no
// «se enruta bien»— y se prefiere débil-y-presente a fuerte-y-ausente.

import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";

const fuente = fs.readFileSync(
  path.join(__dirname, "../../src/transport/grpc-stream.ts"),
  "utf8"
);

/** El bloque `switch (jobType)` del despachador, y solo ese. */
const despachador = fuente.slice(fuente.indexOf("switch (jobType)"));

describe("enrutado de jobs de CDP en el agente", () => {
  it.each([
    ["cdp_csr_generate", "cdp.csr.generate"],
    ["cdp_cert_install", "cdp.cert.install"],
    // El que ya estaba, como control: si este cayera, el test estaría
    // midiendo otra cosa.
    ["cdp_anchor_distrust", "cdp.anchor.distrust"]
  ])("%s está enrutado y llama a %s en el PrivSvc", (jobType, metodoIpc) => {
    expect(despachador).toContain(`case "${jobType}"`);
    const bloque = despachador.slice(despachador.indexOf(`case "${jobType}"`));
    // El método IPC tiene que aparecer ANTES del siguiente `case`, o
    // estaríamos leyendo el handler de otro job.
    const finBloque = bloque.indexOf("\n    case ", 10);
    expect(bloque.slice(0, finBloque > 0 ? finBloque : undefined)).toContain(metodoIpc);
  });

  it("⭐ los dos nuevos devuelven su resultado por el envelope de facts", () => {
    // El ACK solo transporta `status` y `message`. Un job que tiene que
    // DEVOLVER algo —el CSR, o el `installed` que dispara el rescan de
    // verificación— necesita el otro camino, que es el único que el
    // control plane sabe leer.
    for (const jobType of ["cdp_csr_generate", "cdp_cert_install"]) {
      const bloque = despachador.slice(despachador.indexOf(`case "${jobType}"`));
      const finBloque = bloque.indexOf("\n    case ", 10);
      const cuerpo = bloque.slice(0, finBloque > 0 ? finBloque : undefined);
      expect(cuerpo).toContain("collectFactsSnapshot");
      expect(cuerpo).toContain('jobStatus: "completed"');
    }
  });

  it("el CSR viaja de verdad, no solo un acuse", () => {
    const bloque = despachador.slice(despachador.indexOf('case "cdp_csr_generate"'));
    expect(bloque.slice(0, bloque.indexOf("\n    case ", 10))).toContain("csrPem");
  });

  it("la instalación reporta `installed`, que es lo que dispara el rescan", () => {
    const bloque = despachador.slice(despachador.indexOf('case "cdp_cert_install"'));
    expect(bloque.slice(0, bloque.indexOf("\n    case ", 10))).toContain("installed");
  });
});

describe("transporte del resultado estructurado", () => {
  it("collectFactsSnapshot acepta el resultado de un job y lo funde en el payload", () => {
    expect(fuente).toContain("jobResult?: { jobId: string; jobStatus:");
    // ⚠️ JUNTO a los facts, no en vez de ellos: el backend valida
    // `schemaVersion` y `namespaces` antes de mirar el `jobId`, así que
    // un envelope que solo llevara el resultado se rechazaría como
    // payload inválido.
    expect(fuente).toContain("...(facts as any)");
  });
});
