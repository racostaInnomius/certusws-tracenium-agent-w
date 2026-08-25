using System.Reflection;

namespace Tracenium.AgentTray;

/// <summary>
/// Colores y assets de marca del tray, para que Windows y macOS se vean igual.
///
/// Los dos trays se venían tocando por separado y habían derivado: en macOS los
/// títulos de sección usaban el color de acento del sistema y aquí el azul de
/// Windows, así que ninguna de las dos ventanas era de Tracenium. Tener los
/// valores en un solo sitio es lo que evita que vuelvan a separarse.
/// </summary>
internal static class BrandAssets
{
    /// <summary>
    /// Teal de marca para títulos de sección, en su variante para fondo claro.
    ///
    /// El tono de la paleta es #5A9F9F, pero sobre blanco da 2.82:1 de
    /// contraste — por debajo del 3.0 que WCAG pide incluso para texto grande
    /// en negrita. #3C7C7C es el mismo tono oscurecido y llega a 4.45:1.
    ///
    /// Es exactamente el valor que usa el popover de macOS en apariencia clara.
    /// macOS además alterna al #5A9F9F en modo oscuro; aquí no hace falta,
    /// porque el contenido de esta ventana es blanco fijo.
    /// </summary>
    public static readonly Color SectionTeal = Color.FromArgb(60, 124, 124);

    /// <summary>Cian de la paleta (#8FFDFF) — el acento del logo.</summary>
    public static readonly Color AccentCyan = Color.FromArgb(143, 253, 255);

    /// <summary>Gris claro del texto sobre la banda oscura del header.</summary>
    public static readonly Color HeaderText = Color.FromArgb(219, 224, 230);

    /// <summary>Fondo de la banda del header.</summary>
    public static readonly Color HeaderBackground = Color.FromArgb(34, 40, 49);

    /// <summary>Eslogan de producto, partido para poder pintar el "&amp;" en cian.</summary>
    public const string SloganLeft = "Endpoint Intelligence ";
    public const string SloganAccent = "&";
    public const string SloganRight = " Compliance Platform";

    // Mismo mecanismo que TrayIconLoader: MSBuild combina el default namespace
    // con el NOMBRE del archivo (no su ruta) para el logical name del recurso.
    private const string LogoResourceName = "Tracenium.AgentTray.tracenium_logo_color.png";

    /// <summary>
    /// Logo a color del header, o null si el recurso no viajó.
    ///
    /// Devuelve null en vez de lanzar: un asset que no se embebe es un fallo de
    /// empaquetado silencioso, y el header sabe colapsar su hueco. Que el tray
    /// no arranque por un PNG sería mucho peor que verlo sin logo.
    /// </summary>
    public static Image? LoadLogoOrNull()
    {
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            using var stream = assembly.GetManifestResourceStream(LogoResourceName);
            if (stream is null)
            {
                return null;
            }
            // Image.FromStream exige que el stream siga vivo mientras se use la
            // imagen, así que se copia a memoria y se devuelve una copia propia.
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            ms.Position = 0;
            return Image.FromStream(ms);
        }
        catch
        {
            return null;
        }
    }
}
