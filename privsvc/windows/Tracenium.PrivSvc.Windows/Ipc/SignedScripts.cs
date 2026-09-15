// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/SignedScripts.cs
//
// La firma de los .ps1 que privsvc ejecuta como SYSTEM con `-File`
// (Scripts\asp-ad-collector.ps1 de ADR-0022, Scripts\ad-printers.ps1 de
// ADR-0023). Vivía dentro de AspCollector; con un segundo script se extrae en vez
// de copiarla.
//
// ⚠️ Si el propio PrivSvc está firmado —cualquier build de release—, el script
// TIENE que pasar WinVerifyTrust o no se ejecuta: un .ps1 sustituido en Program
// Files correría como SYSTEM. En un build de desarrollo sin firmar se ejecuta y
// queda en el log. El resultado se cachea por ruta + tamaño + fecha: un fichero
// cambiado vuelve a verificarse.

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class SignedScripts
{
    private static readonly object Lock = new();
    private static readonly Dictionary<string, (string Key, bool Trusted, string Reason)> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static bool? _selfSigned;

    public static (bool Trusted, string Reason) Verify(string scriptPath, string logTag)
    {
        var info = new FileInfo(scriptPath);
        var key = $"{info.Length}|{info.LastWriteTimeUtc.Ticks}";
        lock (Lock)
        {
            _selfSigned ??= SelfIsSigned();
            if (_selfSigned == false)
            {
                IpcLog.Write($"[{logTag}] privsvc is unsigned (dev build) — script signature not enforced");
                return (true, "dev_build_unsigned");
            }
            if (Cache.TryGetValue(info.FullName, out var cached) && cached.Key == key) return (cached.Trusted, cached.Reason);
            var (trusted, reason) = Sdp.WinVerifyTrustFile(scriptPath);
            Cache[info.FullName] = (key, trusted, reason);
            return (trusted, reason);
        }
    }

    private static bool SelfIsSigned()
    {
        var self = Environment.ProcessPath;
        if (string.IsNullOrEmpty(self) || !File.Exists(self)) return false;
        return Sdp.WinVerifyTrustFile(self).trusted;
    }
}
