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

  // La procedencia va en el CUERPO, no solo en el título: no todas las
  // plataformas enseñan el título con la misma prominencia —el MessageBox de
  // Windows lo pone en la barra, el NSAlert de macOS lo destaca— y la línea
  // que no se puede perder es esta. Va al final, junto a la grabación, porque
  // lo primero que la persona necesita saber es qué le están pidiendo.
  lines.push(`Requested through ${PRODUCT_NAME}, your IT management software.`);

  if (args.recording) {
    // ⚠️ No es un detalle de redacción: grabar a alguien sin avisarle es
    // ilegal en varias jurisdicciones y, en todas, la vía rápida a perder la
    // confianza de un cliente. Si la grabación está activa, el diálogo LO
    // DICE.
    lines.push("This session is being recorded.");
  }

  return lines;
}

/**
 * Título del diálogo. SIEMPRE lleva el nombre del producto.
 *
 * ⚠️ No es marca, es seguridad. Un aviso que aparece de la nada diciendo que
 * alguien quiere controlar tu equipo, sin decir QUÉ software lo muestra, es
 * indistinguible de un intento de estafa — y la reacción sana ante eso es
 * pulsar cualquier cosa para que desaparezca.
 *
 * Nombrar el producto hace dos cosas a la vez: permite creer el aviso legítimo
 * (esta empresa instaló Tracenium, tiene sentido) y permite RECHAZAR el que no
 * lo sea (yo no tengo eso instalado). Sin el nombre, la persona no puede hacer
 * ninguna de las dos, y un consentimiento que no se puede evaluar no es un
 * consentimiento.
 *
 * Lo encontró el usuario probando el diálogo real: aceptó sin saber qué se lo
 * estaba pidiendo.
 */
export function consentTitle(kind: ConsentKind): string {
  return kind === "view"
    ? `${PRODUCT_NAME} — Screen sharing request`
    : `${PRODUCT_NAME} — Remote control request`;
}

/** El nombre que la persona ve, y con el que puede verificar el aviso. */
export const PRODUCT_NAME = "Tracenium";

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
