// src/domain/install-date.ts
//
// La fecha en que se instaló la versión ACTUAL de una app, como "YYYY-MM-DD".
//
// ── Por qué sólo el día ──────────────────────────────────────────────────
//
// La fuente más común —el `InstallDate` del registro de Windows— sólo trae el
// día. Mezclar días con instantes obliga al backend a inventar una hora, y una
// medianoche UTC inventada se lee como el día ANTERIOR en cualquier zona al
// oeste de Greenwich (todo México). Así que todas las fuentes se reducen a lo
// que la peor puede decir: la fecha de calendario del propio equipo.
//
// ── Qué significa ────────────────────────────────────────────────────────
//
// En casi todas las fuentes, una actualización reescribe la fecha: MSI al
// reinstalar, rpm y dpkg al actualizar, el bundle de macOS al reemplazarse. Es
// "desde cuándo está ESTA versión", no "desde cuándo está el producto".
//
// ── Lo que no se acepta ──────────────────────────────────────────────────
//
// Nada que haya que adivinar. `03/04/2024` puede ser 3 de abril o 4 de marzo, y
// los instaladores de Windows escriben lo que quieren en `InstallDate`; una
// fecha dudosa es peor que ninguna porque se lee como un hecho. Tampoco fechas
// imposibles (antes de 1990, o en el futuro): un reloj mal puesto o un campo
// basura no son una fecha de instalación.

const ISO_DAY = /^(\d{4})-(\d{2})-(\d{2})$/;
const MIN_YEAR = 1990;

function pad(n: number): string {
  return String(n).padStart(2, "0");
}

/** ¿Es un "YYYY-MM-DD" válido y plausible? */
export function isInstalledOn(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const m = ISO_DAY.exec(value);
  if (!m) return false;
  return plausibleDay(Number(m[1]), Number(m[2]), Number(m[3]));
}

function plausibleDay(y: number, mo: number, d: number): boolean {
  if (y < MIN_YEAR || mo < 1 || mo > 12 || d < 1 || d > 31) return false;
  // 2024-02-31 pasa el patrón; el Date lo corre a marzo y así se detecta.
  const dt = new Date(y, mo - 1, d);
  if (dt.getFullYear() !== y || dt.getMonth() !== mo - 1 || dt.getDate() !== d) return false;
  // Un día de margen: el reloj del equipo y el del instalador no tienen por
  // qué coincidir al segundo.
  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  return dt.getTime() <= tomorrow.getTime();
}

/** La fecha de calendario LOCAL de un instante, o undefined si no es válido. */
export function installedOnFromDate(value: Date | null | undefined): string | undefined {
  if (!(value instanceof Date)) return undefined;
  const t = value.getTime();
  // birthtime = 0 es lo que devuelven los sistemas de ficheros que no la
  // guardan; el patrón de plausibilidad ya lo tira (1970), pero se dice aquí.
  if (!Number.isFinite(t) || t <= 0) return undefined;
  const out = `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`;
  return isInstalledOn(out) ? out : undefined;
}

/** Segundos desde epoch (rpm %{INSTALLTIME}, pkgutil install-time). */
export function installedOnFromEpochSeconds(value: unknown): string | undefined {
  const n = typeof value === "number" ? value : typeof value === "string" && /^\d+$/.test(value.trim()) ? Number(value.trim()) : NaN;
  if (!Number.isFinite(n) || n <= 0) return undefined;
  return installedOnFromDate(new Date(n * 1000));
}

/**
 * El `InstallDate` de una clave Uninstall, tal como lo devuelve el registro.
 *
 *   "20240315"    → 2024-03-15   (lo que escribe Windows Installer)
 *   "2024-03-15"  → 2024-03-15   (algunos instaladores EXE)
 *   1710460800    → 2024-03-15   (DWORD con epoch, raro pero existe)
 *   "15/03/2024"  → undefined    (día/mes ambiguo: no se adivina)
 */
export function installedOnFromWindowsRegistry(raw: unknown): string | undefined {
  if (typeof raw === "number") return installedOnFromEpochSeconds(raw);
  if (typeof raw !== "string") return undefined;
  const s = raw.trim();

  const compact = /^(\d{4})(\d{2})(\d{2})$/.exec(s);
  if (compact) {
    const [, y, m, d] = compact;
    const out = `${y}-${m}-${d}`;
    return isInstalledOn(out) ? out : undefined;
  }

  const iso = /^(\d{4}-\d{2}-\d{2})(?:[T ].*)?$/.exec(s);
  if (iso) return isInstalledOn(iso[1]) ? iso[1] : undefined;

  // Epoch en texto (9-10 dígitos). Ocho dígitos ya se trataron como yyyyMMdd.
  if (/^\d{9,10}$/.test(s)) return installedOnFromEpochSeconds(s);

  return undefined;
}
