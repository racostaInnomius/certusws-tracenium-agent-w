// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/RegistryProbes.cs
//
// Lee una lista de valores del registro y los devuelve tal cual, sin
// juzgarlos. El veredicto es del control plane. La parte sin Windows
// (parseo, normalización, extracción de params) vive en
// RegistryProbeShape.cs para poder probarse.
//
// ── Por qué existe ───────────────────────────────────────────────────
//
// De los 512 controles de CIS Windows 11 v5.1.0, 347 se reducen a "esta
// clave del registro vale esto" — CIS lo escribe literalmente en la
// sección Audit de cada uno: `HKLM\...\mrxsmb10:Start`, REG_DWORD, 4. Un
// colector por control habría sido 347 colectores. Éste es uno: el
// control plane le dice qué claves leer (vienen en la policy, bajo
// `compliance.registryProbes`), y él las lee.
//
// Eso también decide quién cambia cuando CIS publica una versión nueva:
// el backend re-siembra el catálogo y la policy lleva las claves nuevas.
// El agente no se toca — y no tocarlo importa, porque se auto-actualiza
// y llegar a toda la flota tarda días.
//
// ── Por qué NO usa PowerShell ────────────────────────────────────────
//
// El resto de este servicio lanza PowerShell con `-EncodedCommand`. Con
// 352 claves el comando codificado supera el límite de 32K de la línea
// de comandos de Windows, y serían 352 accesos dentro de un proceso con
// un presupuesto de 15 s que Get-MpComputerStatus ya agota a veces.
// `Microsoft.Win32.Registry` es una llamada en proceso, sin límite de
// tamaño y del orden de microsegundos por clave.
//
// ── Ausente = OMITIDO, nunca null ni cero ────────────────────────────
//
// CIS distingue "vale 4" de "la clave no existe" — 27 controles dicen
// "4, o que la clave no exista" (un servicio que nunca se instaló cumple).
// El evaluador del backend expresa eso con `onMissing: "pass"`, que sólo
// dispara cuando el path NO está en la evidencia. Si aquí una clave
// ausente se reportara como null, `resolvePath` la encontraría
// (found=true, value=null), `onMissing` no dispararía y el control
// FALLARÍA en un equipo que cumple. Por eso una clave ausente
// sencillamente no aparece en `Values`.
//
// Una clave que no se pudo leer (acceso denegado, hive corrupto) tampoco
// aparece en `Values` — no se sabe qué vale — pero sí en `Errors`, para
// que se pueda diagnosticar. Como SYSTEM lee cualquier clave de directiva
// bajo HKLM, en la práctica `Errors` debería quedar vacío siempre; si no
// lo está, es un hallazgo.
//
// ── Vista de 64 bits, explícita ──────────────────────────────────────
//
// Las claves de directiva viven en el hive de 64 bits; un proceso de 32
// bits sin la vista explícita sería redirigido a WOW6432Node y leería
// otra cosa sin ningún error. El servicio se compila x64 hoy, pero nada
// garantiza que siga así.

using Microsoft.Win32;

namespace Tracenium.PrivSvc.Windows.Ipc;

public sealed class RegistryProbeResult
{
    /// <summary>Sonda → valor. Indexado por la sonda TAL CUAL llegó: ésa es
    /// la clave que el catálogo usa en el path del evaluador.</summary>
    public Dictionary<string, object?> Values { get; } = new(StringComparer.Ordinal);
    /// <summary>Sonda → motivo. Sólo las que no se pudieron leer.</summary>
    public Dictionary<string, string> Errors { get; } = new(StringComparer.Ordinal);
}

public static class RegistryProbes
{
    public static RegistryProbeResult Read(IEnumerable<string> probes)
    {
        var result = new RegistryProbeResult();
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

        foreach (var probe in probes)
        {
            var parsed = RegistryProbeShape.Parse(probe);
            if (parsed is null) continue; // malformada: ni se lee ni se reporta
            var (subKey, valueName) = parsed.Value;

            try
            {
                using var key = hklm.OpenSubKey(subKey, writable: false);
                var raw = key?.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                // Sin subclave, o sin el valor: ausente → omitido. Ver cabecera.
                if (raw is null) continue;
                result.Values[probe] = RegistryProbeShape.Normalize(raw);
            }
            catch (Exception ex)
            {
                result.Errors[probe] = ex.GetType().Name;
            }
        }
        return result;
    }
}
