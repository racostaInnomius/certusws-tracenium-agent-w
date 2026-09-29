namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>
/// Qué significa el código con el que sale DISM al añadir un paquete (.msu).
///
/// POR QUÉ ESTO ES UN MÓDULO Y NO UN `switch` DENTRO DE Sdp.cs
///
/// Porque la mitad de estos códigos son SÉMANTICA que no se puede deducir
/// leyendo el número, y porque la clasificación tiene que poder corregirse con
/// lo que se vea en campo sin tocar el camino de ejecución. Un `.msu` mal
/// clasificado se marca como FALLIDO habiéndose instalado, o como instalado sin
/// haberlo hecho, y las dos cosas son peores que no haberlo intentado.
///
/// ⚠️ DISM Y NO wusa. `wusa.exe` lanza el trabajo y vuelve: es asíncrono, y el
/// código que devuelve no siempre es el del resultado real de la instalación.
/// `dism /Online /Add-Package` es sincrónico y su código SÍ describe lo que pasó.
/// El precio es que los códigos son otros —los de CBS, no los de Windows
/// Update— y por eso `2359302` (WU_S_ALREADY_INSTALLED), que es el que toda la
/// documentación de wusa menciona, NO aparece en esta tabla como caso esperado
/// de DISM. Se incluye igualmente, porque un operador puede poner `wusa` a mano
/// en silentInstallArgs y entonces sí llegaría.
///
/// ⚠️ LO QUE ESTA TABLA NO SABE, Y LO DICE. `0x800F081E`
/// (CBS_E_NOT_APPLICABLE) mete en el mismo número dos hechos muy distintos:
/// «ya está instalado» y «este paquete no es para este sistema». El primero es
/// un éxito y el segundo un fallo permanente, y DISM no los separa. Así que NO
/// se adivina: se clasifica como <see cref="MsuOutcome.NotApplicable"/>, que el
/// orquestador debe resolver mirando si la revisión del sistema subió. Esa
/// comprobación existe desde que el inventario reporta el UBR.
/// </summary>
public enum MsuOutcome
{
    /// <summary>Instalado y terminado. La máquina sigue en pie.</summary>
    Success,

    /// <summary>Instalado; hace falta reiniciar para completarlo. La máquina no se mueve sola.</summary>
    RebootRequired,

    /// <summary>Instalado Y el reinicio YA empezó. Todo lo que venga detrás compite con el apagado.</summary>
    RebootInitiated,

    /// <summary>
    /// El paquete ya estaba. Es un éxito: el estado deseado se cumple.
    /// Sólo se usa con los códigos que dicen ESO y nada más.
    /// </summary>
    AlreadyInstalled,

    /// <summary>
    /// «No aplica» — ambiguo por construcción: puede ser «ya estaba» o «no es
    /// para este sistema». Ni éxito ni fallo hasta que algo más lo resuelva.
    /// </summary>
    NotApplicable,

    /// <summary>Fallo. Reintentar no cambiaría el resultado.</summary>
    Failed,
}

public static class MsuExitCodes
{
    /// <summary>ERROR_SUCCESS_REBOOT_REQUIRED. Instalado; falta reiniciar.</summary>
    public const int RebootRequired = 3010;

    /// <summary>ERROR_SUCCESS_REBOOT_INITIATED. Instalado; ya se está reiniciando.</summary>
    public const int RebootInitiated = 1641;

    /// <summary>
    /// ERROR_SUCCESS_RESTART_REQUIRED de DISM. Es 3011 y significa lo mismo que
    /// 3010 para lo que nos importa: está puesto y falta un reinicio. Se
    /// distingue en la documentación de CBS, no en la decisión que tomamos.
    /// </summary>
    public const int RestartRequired = 3011;

    /// <summary>
    /// WU_S_ALREADY_INSTALLED (0x00240006). Código de Windows Update, no de
    /// DISM: sólo llega si alguien instala con `wusa` a mano. Dice exactamente
    /// «ya estaba», sin ambigüedad, así que es un éxito.
    /// </summary>
    public const int WuAlreadyInstalled = 2359302;

    /// <summary>
    /// WU_S_REBOOT_REQUIRED (0x00240005), la pareja del anterior en el camino de
    /// `wusa`.
    /// </summary>
    public const int WuRebootRequired = 2359301;

    /// <summary>
    /// CBS_E_NOT_APPLICABLE (0x800F081E). ⚠️ AMBIGUO: «ya está» o «no es para
    /// este sistema». Ver la nota de la clase.
    /// </summary>
    public const int CbsNotApplicable = unchecked((int)0x800F081E);

    /// <summary>
    /// WU_E_NOT_APPLICABLE (0x80240017). El equivalente por el lado de Windows
    /// Update, con la misma ambigüedad.
    /// </summary>
    public const int WuNotApplicable = unchecked((int)0x80240017);

    /// <summary>
    /// Clasifica el código de salida. Función pura: ninguna decisión aquí mira
    /// el disco, el reloj ni el sistema.
    /// </summary>
    public static MsuOutcome Classify(int exitCode) => exitCode switch
    {
        0 => MsuOutcome.Success,
        RebootRequired or RestartRequired or WuRebootRequired => MsuOutcome.RebootRequired,
        RebootInitiated => MsuOutcome.RebootInitiated,
        WuAlreadyInstalled => MsuOutcome.AlreadyInstalled,
        CbsNotApplicable or WuNotApplicable => MsuOutcome.NotApplicable,
        _ => MsuOutcome.Failed,
    };

    /// <summary>
    /// ¿Este código significa que el paquete quedó puesto, con o sin reinicio
    /// pendiente?
    ///
    /// ⚠️ `NotApplicable` devuelve FALSE, y es la decisión importante de este
    /// módulo: ante la duda no se afirma que algo se instaló. Quien llame tiene
    /// que resolverlo con evidencia —la revisión del sistema— y no con una
    /// suposición optimista que cerraría el job como hecho.
    /// </summary>
    public static bool IsInstalled(int exitCode) => Classify(exitCode) switch
    {
        MsuOutcome.Success or MsuOutcome.RebootRequired
            or MsuOutcome.RebootInitiated or MsuOutcome.AlreadyInstalled => true,
        _ => false,
    };

    /// <summary>
    /// Un motivo legible para el operador. Sin esto, la ficha del job enseña un
    /// número con signo —`-2146498530` para 0x800F081E— que no se puede buscar
    /// en la documentación de Microsoft, escrita siempre en hexadecimal.
    /// </summary>
    public static string Describe(int exitCode)
    {
        var hex = "0x" + exitCode.ToString("X8");
        return Classify(exitCode) switch
        {
            MsuOutcome.Success => "installed",
            MsuOutcome.RebootRequired => $"installed; reboot required ({exitCode})",
            MsuOutcome.RebootInitiated => $"installed; reboot already started ({exitCode})",
            MsuOutcome.AlreadyInstalled => $"already installed ({hex})",
            MsuOutcome.NotApplicable =>
                $"not applicable ({hex}) — Windows reports this BOTH when the update is " +
                "already present and when it does not apply to this system; the system " +
                "revision (UBR) is what tells them apart",
            _ => $"failed ({hex})",
        };
    }
}
