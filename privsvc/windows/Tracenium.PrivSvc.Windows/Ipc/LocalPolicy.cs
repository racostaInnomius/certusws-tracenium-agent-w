// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/LocalPolicy.cs
//
// Escribir un valor de HKLM como POLÍTICA DE GRUPO LOCAL y dejar que lo
// aplique Windows. Lo usa la remediación genérica sólo cuando la escritura
// directa vuelve `write_blocked` (ver RegistryWriteBlockedException): un
// filtro del kernel deniega el valor, pero el cliente de directivas sí puede
// escribirlo. El formato de los ficheros, puro y probado, está en
// LocalPolicyShape.cs.
//
// Decidido con el usuario (1-oct-2026): sólo como respaldo de un bloqueo, y
// también en equipos de dominio. ⚠️ En dominio la política local es la de
// MENOS prioridad: si una GPO del dominio configura el mismo ajuste, gana
// ella, y la comprobación posterior lo dirá.

using System.Diagnostics;
using System.Text;

namespace Tracenium.PrivSvc.Windows.Ipc;

internal static class LocalPolicy
{
    private static string Root => Path.Combine(Environment.SystemDirectory, "GroupPolicy");
    private static string MachinePol => Path.Combine(Root, "Machine", "Registry.pol");
    private static string GptIni => Path.Combine(Root, "gpt.ini");

    /// <summary>Un único escritor de Registry.pol/gpt.ini dentro del PrivSvc.</summary>
    private static readonly object Gate = new();

    private const int GpupdateTimeoutMs = 120_000;

    /// <summary>
    /// Deja la entrada en la política local y aplica. NO comprueba el
    /// resultado: lo hace el llamante leyendo el registro, que es lo único
    /// que dice si de verdad quedó.
    /// </summary>
    public static void ApplyMachineEntry(PolEntry entry)
    {
        lock (Gate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(MachinePol)!);

            // Leer y entender ANTES de escribir nada: un fichero que no se
            // entiende lanza aquí y no se toca.
            var existing = File.Exists(MachinePol) ? File.ReadAllBytes(MachinePol) : null;
            var entries = LocalPolicyShape.Upsert(LocalPolicyShape.Parse(existing), entry);
            WriteAtomically(MachinePol, LocalPolicyShape.Serialize(entries));

            var ini = File.Exists(GptIni) ? File.ReadAllText(GptIni, Encoding.ASCII) : null;
            WriteAtomically(GptIni, Encoding.ASCII.GetBytes(LocalPolicyShape.UpdateGptIni(ini)));
        }
        RunGpupdate();
    }

    private static void WriteAtomically(string path, byte[] bytes)
    {
        var tmp = path + ".tracenium-tmp";
        File.WriteAllBytes(tmp, bytes);
        File.Move(tmp, path, overwrite: true);
    }

    private static void RunGpupdate()
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "gpupdate.exe"), "/target:computer /force")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            // gpupdate puede preguntar si reiniciar: con la entrada cerrada
            // la respuesta es «no», en vez de quedarse esperando.
            RedirectStandardInput = true,
        };
        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("gpupdate did not start");
        proc.StandardInput.Close();
        var stdout = proc.StandardOutput.ReadToEndAsync();
        var stderr = proc.StandardError.ReadToEndAsync();
        if (!proc.WaitForExit(GpupdateTimeoutMs))
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("gpupdate did not finish in 120 s");
        }
        if (proc.ExitCode != 0)
        {
            var text = (stderr.Result + " " + stdout.Result).Trim();
            throw new InvalidOperationException($"gpupdate exit {proc.ExitCode}: {(text.Length > 80 ? text[..80] : text)}");
        }
    }
}
