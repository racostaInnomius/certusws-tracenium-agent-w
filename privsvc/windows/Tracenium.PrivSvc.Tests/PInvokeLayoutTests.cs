// PInvokeLayoutTests.cs
//
// ⚠️ La disposicion en memoria de los structs que cruzan a user32.
//
// ── Por que existen estas pruebas ────────────────────────────────────
//
// Este modulo ha tenido TRES fallos de layout en P/Invoke. Ninguno da un
// error de compilacion y ninguno lanza una excepcion: SendInput acepta el
// buffer, devuelve exito, y en el equipo remoto no pasa NADA — o pasa algo
// distinto de lo que el operador hizo. El sintoma llega dias despues como
// "el raton se mueve pero no hace clic", y nadie lo relaciona con un campo
// que se colo entre otros dos.
//
// Un `Marshal.SizeOf` por struct convierte ese fallo mudo en un test rojo.
// No prueba que los campos esten en el orden correcto —eso lo dice la
// documentacion de Win32 y la revision—, pero SI atrapa lo que de verdad
// pasa cuando alguien edita esto: un campo anadido, quitado, o de un tipo
// que ocupa distinto.
//
// ── Por que los numeros son estos ────────────────────────────────────
//
// Son los tamanos de Win32 en 64 bits, calculados campo a campo con las
// reglas de alineacion habituales (cada campo alineado a su tamano, el
// struct al mayor de ellos). Se escriben con la cuenta al lado a proposito:
// un numero magico sin derivacion es imposible de revisar, y el dia que
// falle nadie sabra si el numero o el codigo es el equivocado.
//
// ── Por que corren fuera de Windows ──────────────────────────────────
//
// `[DllImport]` solo falla al INVOCARLO; aqui no se invoca nada. Y el
// tamano marshalado coincide con el de Windows porque los tipos usados
// (int, uint, ushort, IntPtr) miden lo mismo en cualquier plataforma de 64
// bits. Eso es justamente lo que hace que la prueba valga: corre en la
// maquina del desarrollador y en CI, no solo en un Windows que nadie tiene
// delante — que es como una suite deja de correrse.

using System.Reflection;
using System.Runtime.InteropServices;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

namespace Tracenium.PrivSvc.Tests;

public class PInvokeLayoutTests
{
    /// <summary>
    /// Los structs son `private` dentro de InputInjection, y deben seguir
    /// siendolo: son un detalle de la frontera con user32. Se alcanzan por
    /// reflexion en vez de ensanchar su visibilidad para poder probarlos.
    /// </summary>
    private static Type Nested(string name)
    {
        var t = typeof(InputInjection).GetNestedType(
            name,
            BindingFlags.NonPublic | BindingFlags.Public);
        Assert.True(t is not null, $"InputInjection ya no declara {name}");
        return t!;
    }

    [Theory]
    // dx(4) dy(4) mouseData(4) dwFlags(4) time(4) = 20, relleno hasta 24 para
    // alinear el puntero, dwExtraInfo(8) = 32.
    [InlineData("MOUSEINPUT", 32)]
    // wVk(2) wScan(2) dwFlags(4) time(4) = 12, relleno hasta 16, dwExtraInfo(8) = 24.
    [InlineData("KEYBDINPUT", 24)]
    // Union explicita: el mayor de los dos, MOUSEINPUT.
    [InlineData("INPUTUNION", 32)]
    // type(4) + relleno hasta 8 + union(32) = 40. Es el valor que espera
    // SendInput como `cbSize`; equivocarlo hace que la llamada devuelva 0
    // eventos insertados sin decir por que.
    [InlineData("INPUT", 40)]
    public void StructSizeMatchesWin32(string name, int expected)
    {
        Assert.Equal(expected, Marshal.SizeOf(Nested(name)));
    }

    [Fact]
    public void InputIsExactlyTypePlusUnion()
    {
        // La relacion entre los tres, no solo sus tamanos sueltos. Si alguien
        // anade un campo a INPUT y ajusta el numero de arriba para que pase,
        // esta prueba sigue exigiendo que INPUT sea lo que SendInput espera:
        // un discriminante y la union, y nada mas.
        var input = Marshal.SizeOf(Nested("INPUT"));
        var union = Marshal.SizeOf(Nested("INPUTUNION"));
        Assert.Equal(8 + union, input); // 4 de `type` + 4 de relleno
    }

    [Fact]
    public void UnionIsSizedByItsLargestMember()
    {
        var union = Marshal.SizeOf(Nested("INPUTUNION"));
        var mouse = Marshal.SizeOf(Nested("MOUSEINPUT"));
        var keyboard = Marshal.SizeOf(Nested("KEYBDINPUT"));
        Assert.Equal(Math.Max(mouse, keyboard), union);
        // Y que la union no se haya quedado, por un descuido, del tamano del
        // miembro pequeno: eso truncaria cada evento de raton en silencio.
        Assert.True(union >= mouse);
    }
}
