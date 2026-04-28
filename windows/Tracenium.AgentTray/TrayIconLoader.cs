using System.Reflection;

namespace Tracenium.AgentTray;

internal static class TrayIconLoader
{
    // Logical name del recurso embebido. Debe coincidir con
    // <EmbeddedResource Include="tracenium.ico"/> en el csproj —
    // MSBuild combina default namespace ("Tracenium.AgentTray") con
    // el nombre del archivo (no el path) para producir el resource
    // name. La validación post-build VerifyTrayIconEmbedded garantiza
    // que esta constante y el resource embebido se mantengan en sync.
    private const string ResourceName = "Tracenium.AgentTray.tracenium.ico";

    public static Icon LoadOrFallback()
    {
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            using var stream = assembly.GetManifestResourceStream(ResourceName);
            if (stream is null)
            {
                return SystemIcons.Application;
            }

            // Con un .ico embedded resource podemos cargar el Icon
            // directamente desde el stream — el constructor parsea el
            // formato ICO multi-resolución de Windows y nos devuelve
            // el Icon listo para asignar a NotifyIcon.Icon. Comparado
            // con el patrón anterior (PNG → Bitmap → GetHicon → Clone
            // + DestroyIcon manual), esto es un orden de magnitud más
            // simple y no fuga handles si algo falla a mitad.
            return new Icon(stream);
        }
        catch
        {
            // Cualquier excepción (resource missing, ICO corrupto,
            // OOM, etc.) → fallback al icon genérico de Windows. El
            // tray sigue funcionando, solo con apariencia degradada,
            // y el usuario aún puede acceder al status form.
            return SystemIcons.Application;
        }
    }
}
