// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/SignInScreenShape.cs
//
// Entrar a un SERVIDOR por su propia pantalla de Windows (inicio de sesión o
// bloqueo) desde el visor remoto: la parte PURA. Aquí se decide; llamar a
// Win32 queda en SessionScreenCapture, SecureAttention e InputInjection. Sin
// Microsoft.Win32 dentro, para probarse fuera de Windows como RevertShape.
//
// ── Por qué existe este fichero ─────────────────────────────────────
//
// TNS-OPER-SNOC04 (T1, 29-sep-2026). Cada despliegue destapaba el siguiente
// paso roto del mismo recorrido: primer fotograma, azul liso, «Take control»
// obligatorio, Ctrl+Alt+Supr imposible, la directiva que lo bloquea. El
// usuario lo cortó: «no estamos viendo más allá de la corrección en turno».
// Así que se recorrió el flujo ENTERO antes de tocar nada —entrar, escribir
// las credenciales, trabajar, irse— y todas sus decisiones viven aquí, con
// pruebas que corren en el Mac.
//
// Decisiones del usuario (29-sep-2026), todas sobre servidores CLASIFICADOS
// como tales y con SKU de servidor:
//   · Ctrl+Alt+Supr: si la directiva no está configurada, la ponemos.
//   · Consola BLOQUEADA: igual que «sin nadie dentro» — se enseña la
//     pantalla de bloqueo y el visor arranca en control.
//   · Al terminar: si se entró por una de esas pantallas, se BLOQUEA la
//     consola. Nadie con acceso a la consola de la VM debe encontrarse una
//     sesión de administrador abierta.

using System.Runtime.InteropServices;

namespace Tracenium.PrivSvc.Windows.Ipc;

/// <summary>Qué hacer con Ctrl+Alt+Supr según `SoftwareSASGeneration`.</summary>
public enum SasPolicyAction
{
    /// <summary>1 o 3: los servicios ya pueden generar la SAS.</summary>
    Send,
    /// <summary>Ausente = no configurada: se pone a 1 y se manda.</summary>
    ConfigureThenSend,
    /// <summary>
    /// Configurada EXPLÍCITAMENTE sin servicios (0, 2 u otro valor). Alguien
    /// lo decidió —casi siempre una GPO, que además la reescribiría en el
    /// próximo refresco—: no se pelea, se explica.
    /// </summary>
    RefuseExplicit
}

/// <summary>Un paso de «escribir este texto».</summary>
public readonly record struct TypeUnit(char Char, ushort Vk)
{
    /// <summary>true = carácter por KEYEVENTF_UNICODE; false = tecla virtual.</summary>
    public bool IsUnicode => Vk == 0;
}

public static class SignInScreenShape
{
    public const string SasPolicyValueName = "SoftwareSASGeneration";

    /// <summary>
    /// Máximo de caracteres por «Type text». Da de sobra para usuario y
    /// contraseña; lo que pase de ahí no es una credencial, es un volcado, y
    /// cada carácter son dos eventos de SendInput sobre el carril del helper.
    /// </summary>
    public const int TypeTextMaxChars = 1024;

    // WTS_SESSIONSTATE_* de WTSINFOEX_LEVEL1.SessionFlags.
    public const int WtsSessionStateLock = 0;
    public const int WtsSessionStateUnlock = 1;

    public static SasPolicyAction DecideSasPolicy(int? value) => value switch
    {
        null => SasPolicyAction.ConfigureThenSend,
        1 or 3 => SasPolicyAction.Send,
        _ => SasPolicyAction.RefuseExplicit
    };

    /// <summary>
    /// ¿Está BLOQUEADA la sesión según `SessionFlags`?
    ///
    /// ⚠️ Sólo el 0 es «bloqueada». -1 (WTS_SESSIONSTATE_UNKNOWN) NO cuenta:
    /// ante la duda no se toma la pantalla de bloqueo de nadie. (En Windows 7 /
    /// Server 2008 R2 los valores venían invertidos; la flota empieza en 2016.)
    /// </summary>
    public static bool IsLocked(int sessionFlags) => sessionFlags == WtsSessionStateLock;

    /// <summary>
    /// ¿Hay que bloquear la consola al terminar la sesión remota?
    ///
    /// Sólo si en ESTA sesión se pasó por la pantalla de inicio de sesión o de
    /// bloqueo —es decir, si el operador entró con credenciales del servidor—
    /// y ahora hay alguien dentro con la sesión abierta. Si nunca llegó a
    /// entrar, no hay nada que bloquear; si ya está bloqueada, tampoco.
    /// </summary>
    public static bool ShouldLockOnEnd(bool sawSignInScreen, bool consoleHasUser, bool consoleLocked) =>
        sawSignInScreen && consoleHasUser && !consoleLocked;

    /// <summary>
    /// Convierte un texto en pasos de SendInput que no dependen de la
    /// distribución de teclado de NINGUNO de los dos lados.
    ///
    /// 🔴 El motivo: la entrada normal manda teclas FÍSICAS
    /// (`KeyboardEvent.code` → VK) y el servidor las interpreta con SU
    /// distribución. Desde un Mac con teclado español, `@` es Option+2 y al
    /// servidor le llega Alt+2. En el campo de contraseña no se ve lo que
    /// llega: «contraseña incorrecta» sin pista de por qué.
    ///
    /// Con KEYEVENTF_UNICODE cada carácter viaja como carácter. Salto de línea
    /// y tabulador van como teclas, para poder escribir «usuario⇥clave⏎».
    /// `\r\n` es UN Enter. Los pares suplentes (emoji…) van como dos unidades
    /// UTF-16 seguidas, que es como KEYEVENTF_UNICODE los espera.
    /// </summary>
    public static (IReadOnlyList<TypeUnit>? units, string? error) PlanTypeText(string? text)
    {
        if (string.IsNullOrEmpty(text)) return (null, "Nothing to type.");
        if (text.Length > TypeTextMaxChars)
            return (null, $"Text is longer than {TypeTextMaxChars} characters.");

        const ushort VkReturn = 0x0D, VkTab = 0x09;
        var units = new List<TypeUnit>(text.Length);
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '\r')
            {
                if (i + 1 < text.Length && text[i + 1] == '\n') i++;
                units.Add(new TypeUnit('\0', VkReturn));
            }
            else if (c == '\n') units.Add(new TypeUnit('\0', VkReturn));
            else if (c == '\t') units.Add(new TypeUnit('\0', VkTab));
            else if (char.IsControl(c)) continue; // nada invisible por Unicode
            else units.Add(new TypeUnit(c, 0));
        }
        return units.Count == 0 ? (null, "Nothing to type.") : (units, null);
    }
}

// ── Interop de WTSINFOEX, aquí para poder PROBAR su disposición ─────
//
// Sólo interesa `SessionFlags`, pero la estructura va completa a propósito:
// la unión de nivel 1 lleva LARGE_INTEGER, así que se alinea a 8 y `Data`
// empieza en el byte 8, no en el 4. Truncarla después de SessionFlags
// cambiaría la alineación y leería el campo de al lado — un «bloqueada»
// falso decidiría si se toma la pantalla de bloqueo de alguien. La prueba
// fija el desplazamiento: SessionFlags en el byte 16.

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WtsInfoExLevel1
{
    public uint SessionId;
    public int SessionState;
    public int SessionFlags;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)] public string WinStationName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string UserName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)] public string DomainName;
    public long LogonTime;
    public long ConnectTime;
    public long DisconnectTime;
    public long LastInputTime;
    public long CurrentTime;
    public uint IncomingBytes;
    public uint OutgoingBytes;
    public uint IncomingFrames;
    public uint OutgoingFrames;
    public uint IncomingCompressedBytes;
    public uint OutgoingCompressedBytes;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WtsInfoEx
{
    public uint Level;
    public WtsInfoExLevel1 Data;
}
