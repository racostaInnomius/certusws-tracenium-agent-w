// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AltKeyStore.cs
//
// ADR-0015 punto 11 — la clave alternativa ML-DSA-65 en Windows.
//
// ── LA ASIMETRÍA, ACEPTADA POR ESCRITO EN EL ADR ──────────────────────
//
// La clave CLÁSICA vive en CNG, no exportable: el proceso la usa y nunca
// ve sus bytes. Ésta no puede: **ML-DSA en CNG sólo existe desde Windows
// 11 25H2 y Server 2025, y la flota tiene 12 Server 2022 que no lo
// tendrán nunca.** Así que la alternativa es software, en un fichero,
// envuelta con DPAPI de máquina.
//
// Eso significa que la mitad post-cuántica está MENOS PROTEGIDA que la
// clásica en Windows, y conviene decirlo sin adornos: quien consiga
// SYSTEM en el equipo puede desenvolverla, mientras que la clásica se le
// resistiría. El ADR asume ese coste explícitamente; la alternativa era
// esperar a que Server 2022 saliera de la flota, que es esperar años.
//
// Lo que NO cambia por esto: un atacante con SYSTEM ya podía FIRMAR con
// la clave clásica aunque no pudiera extraerla. La diferencia práctica
// es la exfiltración, no el uso.
//
// ── POR QUÉ DPAPI DE MÁQUINA Y NO DE USUARIO ──────────────────────────
//
// El servicio corre como SYSTEM y el equipo no tiene sesión de usuario
// cuando arranca. Con ámbito de usuario, la clave sería indescifrable
// tras un reinicio — la identidad del equipo perdida sin que nadie lo
// pida. Mismo criterio que la credencial del Gateway (ADR-0001), y misma
// implementación: ver CredentialStore.cs.
//
// ⚠️ ESTE FICHERO NO SE PUEDE PROBAR FUERA DE WINDOWS. DPAPI es Win32, y
// por eso queda aparte de MlDsaAlt/HybridCsr/CatalystReader, que sí se
// prueban en el proyecto `net8.0`. Lo que aquí no cubre ningún test es el
// ciclo envolver/desenvolver: hay que verlo en un equipo real.

using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class AltKeyStore
{
    /// <summary>Nombre del fichero envuelto. Uno por equipo, como la identidad.</summary>
    private const string FileName = "client-alt-key.bin";

    /// <summary>
    /// %ProgramData%\Tracenium\PrivSvc — endurecido a SYSTEM y
    /// Administradores.
    ///
    /// ⚠️ ProgramData concede lectura a Users por herencia, que es
    /// exactamente lo que un directorio con material de clave no puede
    /// tener. Se rompe la herencia igual que en CredentialStore.
    /// </summary>
    public static string StoreDir()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Tracenium", "PrivSvc");
        Directory.CreateDirectory(dir);
        HardenDirectory(dir);
        return dir;
    }

    private static void HardenDirectory(string dir)
    {
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
            // Un fallo endureciendo no puede dejar el servicio inservible;
            // la protección DPAPI de máquina se sostiene por su cuenta.
        }
    }

    private static string KeyPath() => Path.Combine(StoreDir(), FileName);

    /// <summary>¿Hay ya una clave alternativa en este equipo?</summary>
    public static bool Exists() => File.Exists(KeyPath());

    /// <summary>
    /// Carga la clave alternativa, generándola si no existe.
    ///
    /// ⚠️ <paramref name="reuse"/> importa igual que en la clásica: en una
    /// renovación se conserva —cambiarla obligaría a reemitir por un
    /// motivo que no existe, y dejaría certificados vivos nombrando una
    /// clave que el equipo ya no tiene— y en un alta desde cero se genera.
    ///
    /// La SPKI se DERIVA siempre de la privada en vez de guardarse aparte:
    /// dos ficheros que pueden discrepar producirían un CSR que declara
    /// una clave y firma la prueba de posesión con otra, y el backend lo
    /// rechazaría con un mensaje que no señala a la causa.
    /// </summary>
    public static MlDsaKeyPairDer LoadOrCreate(bool reuse, out bool created)
    {
        var path = KeyPath();

        if (reuse && File.Exists(path))
        {
            try
            {
                var pkcs8 = ProtectedData.Unprotect(
                    File.ReadAllBytes(path), null, DataProtectionScope.LocalMachine);
                created = false;
                return new MlDsaKeyPairDer(MlDsaAlt.SpkiFromPkcs8(pkcs8), pkcs8);
            }
            catch (Exception ex)
            {
                // ⚠️ NO se regenera en silencio. Una clave que no se puede
                // desenvolver significa una de dos cosas —el fichero se
                // corrompió, o el equipo ya no es el que la envolvió— y
                // las dos merecen un log antes de sustituir material de
                // identidad. Se sigue adelante generando, porque quedarse
                // sin poder enrolar sería peor, pero queda dicho.
                try
                {
                    Console.WriteLine(
                        $"[PrivSvc][Crypto] clave alternativa ilegible, se regenera: {ex.Message}");
                }
                catch { }
            }
        }

        var kp = MlDsaAlt.GenerateKeyPair();
        var envuelta = ProtectedData.Protect(kp.Pkcs8Der, null, DataProtectionScope.LocalMachine);
        File.WriteAllBytes(path, envuelta);
        created = true;
        return kp;
    }

    /// <summary>Borra la clave alternativa. Para el desmantelado del equipo.</summary>
    public static bool Destroy()
    {
        try
        {
            var path = KeyPath();
            if (!File.Exists(path)) return false;
            File.Delete(path);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
