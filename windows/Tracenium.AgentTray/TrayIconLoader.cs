using System.Reflection;
using System.Runtime.InteropServices;

namespace Tracenium.AgentTray;

internal static class TrayIconLoader
{
    private const string ResourceName = "Tracenium.AgentTray.Resources.Tracenium_tryicon.png";

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

            using var bitmap = new Bitmap(stream);
            using var resized = new Bitmap(bitmap, new Size(32, 32));
            var handle = resized.GetHicon();
            try
            {
                using var icon = Icon.FromHandle(handle);
                return (Icon)icon.Clone();
            }
            finally
            {
                DestroyIcon(handle);
            }
        }
        catch
        {
            return SystemIcons.Application;
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr hIcon);
}
