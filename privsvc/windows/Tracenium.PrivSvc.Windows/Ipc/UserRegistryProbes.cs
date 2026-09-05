// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/UserRegistryProbes.cs
//
// Lee sondas de registro en HKEY_USERS\<SID> de cada perfil cargado y las
// agrega (ver UserRegistryProbeShape.cs para el contrato). Sin juzgar: el
// veredicto es del control plane.
//
// Sólo perfiles S-1-5-21-* con sesión: los hives de un usuario sin
// sesión no están cargados y cargarlos (`reg load` de NTUSER.DAT) los
// bloquearía para el propio usuario al iniciar sesión. Que un equipo sin
// nadie conectado no pueda afirmar nada es la verdad, y así se reporta.

using Microsoft.Win32;

namespace Tracenium.PrivSvc.Windows.Ipc;

public sealed class UserRegistryProbeResult
{
    public Dictionary<string, Dictionary<string, object?>> PerHive { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> Errors { get; } = new(StringComparer.Ordinal);
    public int Hives => PerHive.Count;
}

public static class UserRegistryProbes
{
    public static UserRegistryProbeResult Read(IEnumerable<string> probes)
    {
        var result = new UserRegistryProbeResult();
        var parsed = new List<(string Probe, string SubKey, string ValueName)>();
        foreach (var probe in probes)
        {
            var p = UserRegistryProbeShape.Parse(probe);
            if (p is null) continue;
            parsed.Add((probe, p.Value.SubKey, p.Value.ValueName));
        }

        using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
        foreach (var hiveName in users.GetSubKeyNames())
        {
            if (!UserRegistryProbeShape.IsUserProfileHive(hiveName)) continue;
            var dict = new Dictionary<string, object?>(StringComparer.Ordinal);
            result.PerHive[hiveName] = dict;
            foreach (var (probe, subKey, valueName) in parsed)
            {
                try
                {
                    using var key = users.OpenSubKey(hiveName + "\\" + subKey, writable: false);
                    var raw = key?.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    if (raw is null) continue; // ausente → omitida en este hive
                    dict[probe] = RegistryProbeShape.Normalize(raw);
                }
                catch (Exception ex)
                {
                    result.Errors[hiveName + ":" + probe] = ex.GetType().Name;
                }
            }
        }
        return result;
    }
}
