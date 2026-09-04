// Quién publica un paquete de Linux.
//
// ⚠️ Existe porque los colectores de Linux escribían el nombre del GESTOR DE
// PAQUETES en el campo del fabricante: `publisher: "dpkg"`, `"rpm"`, `"snap"`,
// `"flatpak"`. Medido en el tenant 1: 950 de 1671 filas de inventario acababan
// bajo el fabricante "Unknown" —el 57%— y 99 de ellas llevaban literalmente
// "dpkg" como fabricante crudo. El backend hacía bien en rechazarlo, pero la
// consecuencia visible era que el ranking de publishers estaba encabezado por
// "Unknown" en un tenant entero.
//
// El mismo error ya se había corregido para `pkgutil` en macOS —el comentario
// vive en macos.ts y dice exactamente esto— y se dejó Linux intacto.
//
// Hay dos casos distintos y se resuelven distinto:
//
//   - dpkg y rpm SÍ tienen fabricante en su metadata (Maintainer y Vendor).
//     Se lee y se manda.
//   - homebrew, snap y flatpak NO tienen el concepto. Ahí la respuesta correcta
//     es la ausencia, no el nombre del gestor: `undefined` deja que el backend
//     lo agrupe como desconocido, que es la verdad.

/**
 * Nombres que NO son fabricantes.
 *
 * ⚠️ La lista incluye los gestores de paquetes porque es exactamente el valor
 * que se estaba enviando. Si un `Maintainer` real dijera "dpkg" —no ocurre—
 * perder ese dato es mucho menos dañino que volver a encabezar el ranking con
 * el nombre de una herramienta.
 */
const NOT_A_PUBLISHER = new Set([
  "dpkg",
  "rpm",
  "snap",
  "flatpak",
  "homebrew",
  "brew",
  "pkgutil",
  "apt",
  "dnf",
  "yum",
  "unknown",
  "n/a",
  "na",
  "null",
  "none",
  "empty",
  "-",
  // ⚠️ rpm imprime esto literalmente cuando el paquete no declara Vendor. Sin
  // la entrada, "(none)" se convertia en un fabricante mas del ranking — y en
  // publisherFromPackageFields le ganaba al Maintainer real, porque el Vendor
  // tiene prioridad. Un test lo dejo escrito antes de que lo notara.
  "(none)",
  "(null)",
]);

/**
 * Limpia el campo Maintainer de dpkg o Vendor de rpm.
 *
 * `Maintainer` viene como "Ubuntu Developers <ubuntu-devel-discuss@lists.
 * ubuntu.com>": el correo no aporta nada a un ranking de fabricantes y además
 * lo fragmenta, porque el mismo equipo publica bajo varias direcciones. Se
 * queda la parte legible.
 *
 * Devuelve `undefined` —no una cadena vacía ni "Unknown"— cuando no hay nada
 * utilizable: es el colector diciendo "no sé", y el backend ya sabe agrupar
 * eso. Mandar la palabra "Unknown" desde aquí sería fabricar un dato.
 */
export function parsePackagePublisher(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;

  // Fuera el correo, esté al final o en medio.
  let value = raw.replace(/<[^>]*>/g, " ");
  // Y una dirección suelta sin ángulos, que también aparece.
  value = value.replace(/\S+@\S+\.\S+/g, " ");
  value = value.replace(/\s+/g, " ").trim();
  // Comas y punto y coma finales quedan al quitar el correo de una lista.
  value = value.replace(/[,;]+$/, "").trim();

  if (!value) return undefined;
  if (NOT_A_PUBLISHER.has(value.toLowerCase())) return undefined;
  // Un valor de un solo carácter no identifica a nadie.
  if (value.length < 2) return undefined;

  // Tope defensivo: algunos Maintainer traen párrafos enteros y esto viaja en
  // cada snapshot de inventario, por cada paquete.
  return value.length > 120 ? value.slice(0, 120).trim() : value;
}

/**
 * El fabricante de un paquete a partir de su fila cruda.
 *
 * Se separa de parsePackagePublisher para que el colector no tenga que saber
 * qué columna trae el dato en cada gestor.
 */
export function publisherFromPackageFields(fields: {
  maintainer?: unknown;
  vendor?: unknown;
}): string | undefined {
  // El Vendor de rpm es más específico que el Maintainer cuando ambos existen:
  // describe a quien construyó el paquete, no a quien lo mantiene.
  return parsePackagePublisher(fields.vendor) ?? parsePackagePublisher(fields.maintainer);
}
