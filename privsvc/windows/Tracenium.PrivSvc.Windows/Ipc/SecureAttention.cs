using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// Ctrl+Alt+Supr remoto — la «secuencia de atención segura» (SAS).
///
/// ── Por qué hace falta ──────────────────────────────────────────────
///
/// TNS-OPER-SNOC04 (29-sep-2026): con la pantalla de inicio de sesión ya a la
/// vista, Windows pedía «Presiona Ctrl+Alt+Supr para desbloquear» y el operador
/// no tenía forma de hacerlo. Desde un Mac esa combinación no existe, y desde
/// un PC con Windows la intercepta el sistema del OPERADOR antes de que llegue
/// al navegador. Es un callejón sin salida en cualquier plataforma.
///
/// ── Por qué no va por SendInput ─────────────────────────────────────
///
/// Windows no deja sintetizar Ctrl+Alt+Supr con SendInput: es justo la
/// garantía que da la SAS, que sólo la genera el teclado de verdad o quien el
/// sistema autorice. El camino soportado es `SendSAS` de sas.dll, llamado
/// desde un servicio que corre como SYSTEM. Este PrivSvc lo es — y por eso se
/// hace aquí y no en el helper de sesión.
///
/// ── La directiva que lo permite ─────────────────────────────────────
///
/// Aun siendo SYSTEM, `SendSAS` NO HACE NADA —en silencio: la función no
/// devuelve nada— si la directiva «Disable or enable software Secure Attention
/// Sequence» no autoriza a los servicios. Por defecto no lo hace.
///
/// ⭐ Decisión del usuario (29-sep-2026, tras toparse con ella en campo): si
/// la directiva NO está configurada, PrivSvc la pone a 1 (servicios). Si
/// alguien la fijó explícitamente —casi siempre una GPO— no se pisa: se
/// explica con el nombre exacto. La decisión pura y sus pruebas están en
/// SignInScreenShape.DecideSasPolicy.
/// </summary>
public static class SecureAttention
{
    private const string PolicyKey =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string PolicyValue = "SoftwareSASGeneration";

    [DllImport("sas.dll", SetLastError = false)]
    private static extern void SendSAS([MarshalAs(UnmanagedType.Bool)] bool asUser);

    public static PrivSvcResponse Send(PrivSvcRequest req)
    {
        // ⚠️ SÓLO en un servidor. Decisión del usuario, 29-sep-2026: «un
        // windows endpoint requiere usuario logueado, el botón no se ocupa».
        // Y no es sólo que sobre: en un equipo con alguien dentro, la SAS abre
        // «Bloquear / Cambiar de usuario / Cerrar sesión» encima de la sesión
        // de OTRA persona.
        //
        // El agente ya lo filtra por la clasificación del portal; esto es la
        // misma salvaguarda técnica que la pantalla de login
        // (SessionScreenCapture): un error clasificando no puede encenderlo en
        // el portátil de nadie.
        var sku = SessionScreenCapture.WindowsProductType();
        if (!SessionScreenCapture.IsServerProductType(sku))
        {
            return PrivSvcResponse.Fail(req.Id, "sas_not_server",
                $"Ctrl+Alt+Del is only sent to servers. Windows reports ProductType='{sku ?? "(unreadable)"}'; " +
                "only 'ServerNT' or 'LanmanNT' qualify.");
        }

        int? policy = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(PolicyKey);
            if (key?.GetValue(PolicyValue) is int v) policy = v;
        }
        catch (Exception ex)
        {
            // Sin poder leerla no sabemos si SendSAS surtirá efecto; decirlo
            // con el motivo es mejor que llamar a ciegas y callar.
            return PrivSvcResponse.Fail(req.Id, "sas_policy_unreadable",
                $"Could not read {PolicyValue} to check whether Ctrl+Alt+Del can be sent: {ex.Message}");
        }

        var configuredByUs = false;
        switch (SignInScreenShape.DecideSasPolicy(policy))
        {
            case SasPolicyAction.RefuseExplicit:
                // Alguien la fijó a propósito —casi siempre una GPO, que la
                // reescribiría en el siguiente refresco—. No se pelea.
                return PrivSvcResponse.Fail(req.Id, "sas_not_allowed",
                    $"Windows on this device is explicitly configured not to let services send " +
                    $"Ctrl+Alt+Del ({PolicyValue} = {policy}), usually by Group Policy. " +
                    "Tracenium does not override an explicit setting. Set the policy " +
                    "'Disable or enable software Secure Attention Sequence' (Computer Configuration > " +
                    "Administrative Templates > Windows Components > Windows Logon Options) to " +
                    "'Services' or 'Services and Ease of Access applications'.");

            case SasPolicyAction.ConfigureThenSend:
                // ⭐ Decisión del usuario, 29-sep-2026: en un servidor
                // clasificado, si nadie la ha configurado, la ponemos. Autoriza
                // a SERVICIOS, que ya corren como SYSTEM — la protección de la
                // SAS es contra programas de usuario, y ésos siguen fuera.
                try
                {
                    using var key = Registry.LocalMachine.CreateSubKey(PolicyKey, writable: true);
                    key.SetValue(PolicyValue, 1, RegistryValueKind.DWord);
                    configuredByUs = true;
                    IpcLog.Write($@"[sas] HKLM\{PolicyKey}\{PolicyValue} no estaba configurada; puesta a 1 para permitir Ctrl+Alt+Supr remoto");
                }
                catch (Exception ex)
                {
                    return PrivSvcResponse.Fail(req.Id, "sas_policy_write_failed",
                        $"{PolicyValue} is not configured and Tracenium could not set it: {ex.Message}. " +
                        $@"Set HKLM\{PolicyKey}\{PolicyValue} = 1 to allow Ctrl+Alt+Del.");
                }
                break;
        }

        try
        {
            // asUser:false — la llamada viene de un servicio, no de una sesión.
            SendSAS(false);
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "sas_failed", ex.Message);
        }

        // ⚠️ `SendSAS` no devuelve nada. «Enviado» es lo más que se puede
        // afirmar; el efecto se ve en el siguiente fotograma.
        return PrivSvcResponse.Success(req.Id, new Dictionary<string, object?>
        {
            ["sent"] = true,
            ["policy"] = configuredByUs ? 1 : policy,
            // Queda constancia de que la directiva la cambiamos nosotros: el
            // agente lo registra, y es lo primero que hay que poder contestar
            // si el cliente pregunta quién tocó su configuración.
            ["policyConfiguredByTracenium"] = configuredByUs
        });
    }
}
