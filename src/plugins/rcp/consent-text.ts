// src/plugins/rcp/consent-text.ts
//
// El texto de los avisos de consentimiento (ADR-0012).
//
// ── Por qué vive aparte, y en un módulo probado ──────────────────────
//
//   Esto no es presentación. Es la única información que tiene una persona
//   para decidir si deja que otra vea —o use— su equipo. Si el texto dice
//   menos de lo que va a pasar, el "sí" que da no vale: consintió otra cosa.
//
//   Al estar centralizado, las tres plataformas dicen lo MISMO. Tres diálogos
//   nativos con tres redacciones distintas es como se acaba teniendo una que
//   menciona la grabación y dos que no.
//
// ── Las dos puertas dicen cosas distintas a propósito ────────────────
//
//   "Va a ver tu pantalla" y "va a poder usar tu equipo" no son la misma
//   frase. Enseñar la primera cuando ocurre la segunda sería obtener el
//   permiso por una descripción falsa, que es peor que no pedirlo: deja el
//   registro de auditoría diciendo que la persona aceptó algo que nunca le
//   explicaron.

export type ConsentKind = "view" | "control";

export type ConsentTextArgs = {
  kind: ConsentKind;
  /** Nombre del operador. Vacío ⇒ "A remote operator". */
  operator?: string | null;
  /** Si el tenant tiene la grabación activa (ADR-0012, decisión 2). */
  recording?: boolean;
};

/**
 * Texto del diálogo, en líneas ya partidas.
 *
 * Se parte aquí y no en cada plataforma porque el helper de X11 no envuelve
 * texto —Xlib sin métricas decentes corta peor de lo que puede elegir quien
 * redacta— y así las tres plataformas reciben exactamente los mismos saltos.
 */
export function consentLines(args: ConsentTextArgs): string[] {
  const who = args.operator?.trim() || "A remote operator";
  const lines: string[] = [];

  if (args.kind === "view") {
    lines.push(`${who} is requesting to VIEW your screen.`);
    lines.push("They will see everything on your display,");
    lines.push("including any windows you have open.");
  } else {
    lines.push(`${who} is requesting to CONTROL this computer.`);
    // Decirlo explícitamente evita que alguien conceda el control creyendo
    // que es el primer permiso otra vez.
    lines.push("They can already see your screen.");
    lines.push("This also lets them use your mouse and keyboard.");
  }

  if (args.recording) {
    // ⚠️ No es un detalle de redacción: grabar a alguien sin avisarle es
    // ilegal en varias jurisdicciones y, en todas, la vía rápida a perder la
    // confianza de un cliente. Si la grabación está activa, el diálogo LO
    // DICE.
    lines.push("This session is being recorded.");
  }

  return lines;
}

export function consentTitle(kind: ConsentKind): string {
  return kind === "view" ? "Screen sharing request" : "Remote control request";
}

/** Etiquetas de los botones. */
export function consentButtons(kind: ConsentKind): { allow: string; deny: string } {
  return {
    // Etiquetas que dicen QUÉ se concede, no "Sí"/"No". Alguien que llegue al
    // diálogo a mitad de otra cosa lee el botón antes que el texto.
    allow: kind === "view" ? "Allow viewing" : "Allow control",
    deny: "Don't allow"
  };
}

/** Mapea la capacidad del seam de consentimiento a la puerta que representa. */
export function kindForCapability(capability: string): ConsentKind {
  return capability === "rcp.screen.control" ? "control" : "view";
}
