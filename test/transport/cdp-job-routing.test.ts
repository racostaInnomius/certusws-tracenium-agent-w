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
    ["cdp_key_list", "cdp.key.list"],
    ["cdp_key_destroy", "cdp.key.destroy"],
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
    for (const jobType of ["cdp_csr_generate", "cdp_cert_install", "cdp_key_list", "cdp_key_destroy"]) {
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

  it("⭐ TODO método IPC de CDP del PrivSvc es alcanzable desde agent-core", () => {
    // Esta es la comprobación que habría evitado el fallo entero: un
    // método que existe en el PrivSvc y que nadie llama es código
    // privilegiado inalcanzable. Se lee el router de macOS como censo —
    // los tres PrivSvc se mantienen paralelos a propósito.
    //
    // ⚠️ Se busca en TODO `src/`, no solo en el despachador de jobs.
    // Antes solo miraba ahí, y eso codificaba una suposición que dejó de
    // ser cierta con `cdp.anchor.state`: que la única forma de llegar a
    // un método privilegiado es un job del control plane. Ese método lo
    // pide el ciclo de facts. Estrechar el censo al despachador habría
    // obligado a elegir entre romper el test o no escribir la llamada —
    // y la versión ancha comprueba lo que de verdad importa, que es que
    // ALGUIEN lo invoque.
    const routerMac = fs.readFileSync(
      path.join(__dirname, "../../privsvc/macos/src/router.ts"),
      "utf8"
    );
    const metodos = [...routerMac.matchAll(/case "(cdp\.[a-z.]+)"/g)].map((m) => m[1]);
    expect(metodos.length).toBeGreaterThanOrEqual(6);

    const src = path.join(__dirname, "../../src");
    const fuentes: string[] = [];
    const recorrer = (dir: string) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) recorrer(p);
        else if (e.name.endsWith(".ts")) fuentes.push(fs.readFileSync(p, "utf8"));
      }
    };
    recorrer(src);
    const todo = fuentes.join("\n");

    for (const metodo of metodos) {
      expect(
        todo.includes(`"${metodo}"`),
        `el PrivSvc expone ${metodo} y agent-core no lo llama desde ningún sitio: es código privilegiado inalcanzable`
      ).toBe(true);
    }
  });

  it("⭐ el estado del pin se pide fuera del despachador de jobs, a propósito", () => {
    // Si `cdp.anchor.state` acabara siendo un job, la telemetría del pin
    // dependería de que el control plane la pidiera — y el control plane
    // es justo el adversario del que la fase 0 desconfía. Tiene que
    // salir sola, con el inventario.
    expect(despachador).not.toContain("cdp.anchor.state");
    const plugin = fs.readFileSync(
      path.join(__dirname, "../../src/plugins/cdp/index.ts"),
      "utf8"
    );
    expect(plugin).toContain('"cdp.anchor.state"');
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
