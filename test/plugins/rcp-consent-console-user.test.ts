// test/plugins/rcp-consent-console-user.test.ts
//
// ⚠️ ¿La respuesta la dio quien está delante del equipo?
//
// AgentCore corre como SYSTEM y busca la respuesta del consentimiento en
// TODOS los perfiles del equipo, porque no sabe de antemano quién está en
// consola. Eso significaba que una respuesta escrita desde una sesión de
// RDP abierta en paralelo —u otro usuario en cambio rápido— valía
// exactamente igual que la de la persona sentada delante.
//
// El consentimiento de ADR-0012 es el de esa persona: es SU pantalla.
//
// ── Las dos decisiones que fija este fichero ─────────────────────────
//
// 1. Se compara por NOMBRE y no por ruta de perfil. El directorio de perfil
//    no es el usuario en Windows —se queda con el que tuviera la cuenta al
//    crearse— y comparar por ahí rechazaría a gente legítima, que es peor
//    que no comparar.
//
// 2. "No se sabe" NO es "se rechaza". Una bandeja anterior a este campo no
//    manda quién respondió, y el usuario de consola no siempre se resuelve.
//    Rechazar ahí dejaría sin consentir a toda la flota sin actualizar, y
//    una puerta que deja fuera a quien tiene derecho a pasar se acaba
//    desactivando por directiva — con lo que no protege de nada.

import { describe, it, expect } from "vitest";
import { matchesConsoleUser } from "../../src/plugins/rcp/consent-prompter-tray";

describe("quién respondió", () => {
  it("acepta cuando coincide con el usuario de consola", () => {
    const r = matchesConsoleUser("javier", "javier");
    expect(r.verified).toBe(true);
  });

  it("⚠️ NO da por verificada la respuesta de otro usuario del equipo", () => {
    // El caso real: alguien conectado por RDP aprueba en nombre de quien
    // está sentado delante.
    const r = matchesConsoleUser("otro", "javier");
    expect(r.verified).toBe(false);
  });

  it("⚠️ y lo dice con su propio motivo, no con el de 'no se pudo saber'", () => {
    // Los tres motivos se contaban como uno solo (`consola_desconocida`),
    // así que la ÚNICA señal de abuso de las tres quedaba enterrada bajo el
    // ruido de las bandejas viejas y de las lecturas fallidas: la ventana de
    // observación no medía lo que dice medir, y con ella se iba a decidir
    // cuándo pasar a rechazar.
    const r = matchesConsoleUser("intruso", "javier");
    expect(r.verified).toBe(false);
    if (!r.verified) {
      expect(r.why).toBe("otro_usuario");
      // Los dos nombres, normalizados: sin ellos el registro dice que hubo
      // un desajuste pero no entre quiénes.
      expect(r.respondio).toBe("intruso");
      expect(r.consola).toBe("javier");
    }
  });

  it("el desajuste se detecta con dominio y con UPN por medio", () => {
    // `CONTOSO\\intruso` contra `javier` sigue siendo otra persona: la
    // normalización que hace pasar a los legítimos no puede colar a nadie.
    const r = matchesConsoleUser("CONTOSO\\intruso", "javier@contoso.com");
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.why).toBe("otro_usuario");
  });

  it("el dominio no cuenta: es la misma persona", () => {
    // `CONTOSO\\javier` en consola y `javier` en la bandeja son el mismo
    // usuario. Comparar la cadena entera rechazaría a todo un dominio.
    expect(matchesConsoleUser("javier", "CONTOSO\\javier").verified).toBe(true);
    expect(matchesConsoleUser("CONTOSO\\javier", "javier").verified).toBe(true);
  });

  it("ni las mayúsculas, ni un UPN", () => {
    expect(matchesConsoleUser("Javier", "javier").verified).toBe(true);
    expect(matchesConsoleUser("javier@contoso.com", "javier").verified).toBe(true);
  });
});

describe("cuando no se puede saber", () => {
  it("⚠️ una bandeja vieja no bloquea el consentimiento", () => {
    // No manda `respondedBy`. Si esto rechazara, media flota se quedaría sin
    // poder consentir hasta actualizar la bandeja — y entonces alguien
    // apagaría el consentimiento entero.
    const r = matchesConsoleUser(undefined, "javier");
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.why).toBe("tray_sin_identidad");
  });

  it("⚠️ un usuario de consola irresoluble tampoco bloquea", () => {
    // En Linux la resolución falla en equipos donde todo lo que sale por
    // `exec` vuelve vacío. Es un fallo de lectura, no una señal de abuso.
    const r = matchesConsoleUser("javier", null);
    expect(r.verified).toBe(false);
    if (!r.verified) expect(r.why).toBe("consola_desconocida");
  });

  it("⚠️ los dos motivos de 'no se sabe' no se confunden con el desajuste", () => {
    // Cada uno se arregla de una forma distinta: uno actualizando la flota,
    // otro arreglando la resolución del usuario, y el tercero hablando con
    // alguien. Un solo motivo para los tres no permite ninguna de las tres.
    const vieja = matchesConsoleUser(undefined, "javier");
    const irresoluble = matchesConsoleUser("javier", null);
    const otro = matchesConsoleUser("intruso", "javier");

    const motivos = [vieja, irresoluble, otro].map((r) =>
      r.verified ? "verificado" : r.why
    );
    expect(new Set(motivos).size).toBe(3);
  });

  it("una cadena vacía cuenta como no saber, no como coincidir", () => {
    // `"" === ""` sería el peor de los verdaderos: dos ausencias que se
    // confirman entre sí.
    expect(matchesConsoleUser("", "").verified).toBe(false);
    expect(matchesConsoleUser("   ", "javier").verified).toBe(false);
  });
});
