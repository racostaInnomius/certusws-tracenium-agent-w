// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CryptoCertStage.cs
//
// ADR-0015 punto 10 — el bundle de CA llega en su PROPIO mensaje IPC.
//
// ⚠️ ESTE FICHERO NO EXISTÍA, Y NINGÚN WINDOWS NUEVO PODÍA ENROLARSE.
//
// El mensaje se partió en dos PRECISAMENTE por Windows: el IPC es JSON
// delimitado por saltos de línea, un mensaje es UNA línea, y este pipe
// corta a 64 KB (NamedPipeServer). Con certificados catalyst, hoja y
// cadena juntas miden ~33 KB: no revienta hoy, pero se come la mitad del
// margen. macOS y Linux recibieron `crypto.cert.stage` el 2026-09-06
// (981dbcf); este router no, y respondía `not_supported`. El agente lo
// llama sin condiciones al enrolar, así que reintentaba cada 30 s para
// siempre. Los equipos ya enrolados no lo notaron: la renovación manda el
// bundle en su propio mensaje de install y no pasa por aquí. Visto en
// campo el 2026-09-11, al instalar una VM nueva.
//
// Es la sexta vez que aparece el mismo patrón: un contrato IPC que se
// actualiza en dos plataformas de tres. Por eso hay un censo en
// `test/privsvc/cert-install-split.test.ts` que deriva los métodos del
// enrolamiento del propio agente y exige que los tres routers los conozcan.
//
// Semántica idéntica a macOS/Linux: el bundle se deja EN ESPERA, no se
// instala. Instalar la cadena sin la hoja dejaría al equipo confiando en
// una CA nueva sin certificado con que hablarle. El compromiso sigue
// siendo uno solo, `crypto.cert.install`, que lee de aquí cuando su
// mensaje no trae el bundle y lo descarta al terminar bien.

using System.Text;
using System.Text.Json;
#if WINDOWS
using System.Security.AccessControl;
using System.Security.Principal;
#endif

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CryptoCertStage
{
    /// <summary>
    /// Sólo para los tests, que corren fuera de Windows y no pueden
    /// escribir en ProgramData.
    /// </summary>
    internal static string? DirectoryForTests { get; set; }

    private const string FileName = "ca-bundle.staged.pem";

    private static string StageDir() =>
        DirectoryForTests ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Tracenium", "PrivSvc", "staging");

    internal static string StagedPath() => Path.Combine(StageDir(), FileName);

    public static Task<PrivSvcResponse> HandleStage(PrivSvcRequest req)
    {
        try
        {
            var p = req.Params ?? new Dictionary<string, object>();
            var bundle = GetString(p, "caBundlePem");

            if (string.IsNullOrWhiteSpace(bundle) ||
                !bundle.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal))
            {
                return Task.FromResult(
                    PrivSvcResponse.Fail(req.Id, "invalid_ca_bundle", "caBundlePem is required"));
            }

            var normal = bundle.Replace("\r\n", "\n").Trim() + "\n";

            var dir = StageDir();
            Directory.CreateDirectory(dir);
            HardenDirectory(dir);

            // Escritura atómica: un install que leyera a medio escribir
            // confiaría en una cadena truncada.
            var path = StagedPath();
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, normal, new UTF8Encoding(false));
            File.Move(tmp, path, overwrite: true);

            return Task.FromResult(
                PrivSvcResponse.Success(req.Id, new { staged = true, bytes = normal.Length }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(
                PrivSvcResponse.Fail(req.Id, "cert_stage_failed", ex.Message));
        }
    }

    /// <summary>
    /// El bundle en espera, o null. Un fichero que no contenga un
    /// certificado se ignora en vez de usarse: lo que se instala de aquí
    /// acaba en el almacén Root de la máquina.
    /// </summary>
    public static string? ReadStaged()
    {
        try
        {
            var path = StagedPath();
            if (!File.Exists(path)) return null;
            var pem = File.ReadAllText(path);
            return pem.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal) ? pem : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Se descarta tras instalar, para que un enrolamiento posterior no
    /// herede sin saberlo la cadena de uno anterior.
    /// </summary>
    public static void DiscardStaged()
    {
        try { File.Delete(StagedPath()); } catch { }
    }

    /// <summary>
    /// ⚠️ El contenido acaba en el almacén Root de la máquina, instalado
    /// por SYSTEM. ProgramData concede escritura a Users por herencia: sin
    /// romperla, un usuario sin privilegios podría dejar aquí su propio
    /// bundle y conseguir que SYSTEM plantara su CA como raíz de
    /// confianza. Mismo endurecimiento que AltKeyStore y CredentialStore.
    /// </summary>
    private static void HardenDirectory(string dir)
    {
#if WINDOWS
        try
        {
            var info = new DirectoryInfo(dir);
            var sec = info.GetAccessControl();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                sec.RemoveAccessRule(rule);

            foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            {
                sec.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(sid, null),
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            }
            info.SetAccessControl(sec);
        }
        catch
        {
            // Un fallo endureciendo no puede impedir el enrolamiento. El
            // fichero se reescribe entero en cada `stage`, y el install
            // prefiere siempre el bundle de su propio mensaje.
        }
#endif
    }

    private static string? GetString(Dictionary<string, object> p, string key)
    {
        if (!p.TryGetValue(key, out var val) || val == null) return null;
        if (val is string s) return s;
        if (val is JsonElement je)
        {
            if (je.ValueKind == JsonValueKind.String) return je.GetString();
            return je.ToString();
        }
        return val.ToString();
    }
}
