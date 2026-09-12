// A quién preguntarle por sus GPO de usuario.
//
// ⚠️ Este fichero existe por un fallo que costó CUATRO pasadas de diagnóstico y
// una GPO de prueba creada a mano en un equipo de producción: `appliedUserGpos`
// llegaba `null` en 18 de 50 equipos, y la causa no era gpresult —con la cuenta
// dada a mano corre en 2,09 s como SYSTEM y devuelve la GPO— sino que
// `Win32_ComputerSystem.UserName` NO ve las sesiones RDP y devolvía vacío. Sin
// cuenta, el colector ni llamaba.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class LoggedOnUsersShapeTests
{
    [Fact]
    public void LaCuentaDeConsolaVaPrimero()
    {
        // Es la respuesta históricamente correcta y la más barata: si está, se
        // pregunta por ella antes de gastar intentos en las hives.
        var r = LoggedOnUsersShape.Candidates(@"MOUNTAINSIDE\ana", new[] { @"MOUNTAINSIDE\bruno" });
        Assert.Equal(@"MOUNTAINSIDE\ana", r[0]);
        Assert.Equal(2, r.Count);
    }

    [Fact]
    public void SIN_consola_SE_USAN_LAS_HIVES()
    {
        // El caso real: usuario por RDP, UserName vacío, hive cargada.
        var r = LoggedOnUsersShape.Candidates(null, new[] { @"MOUNTAINSIDE\nextgsys" });
        Assert.Equal(new[] { @"MOUNTAINSIDE\nextgsys" }, r);
    }

    [Fact]
    public void UnaCadenaVaciaNoEsUnaCuenta()
    {
        // `Win32_ComputerSystem.UserName` devuelve "" con sesión RDP, no null.
        Assert.Empty(LoggedOnUsershapeVacio());
        static List<string> LoggedOnUsershapeVacio()
            => LoggedOnUsersShape.Candidates("", new string?[] { "", "   ", null });
    }

    [Fact]
    public void NoPreguntaDosVecesALaMismaPersona()
    {
        // La cuenta de consola suele estar TAMBIÉN entre las hives cargadas.
        // Duplicarla gastaría la mitad del presupuesto en nada.
        var r = LoggedOnUsersShape.Candidates(@"MOUNTAINSIDE\ana",
            new[] { @"mountainside\ANA", @"MOUNTAINSIDE\bruno" });
        Assert.Equal(2, r.Count);
    }

    [Fact]
    public void NoPasaDelTopeDeCuentas()
    {
        // Cada gpresult cuesta ~2 s medidos y el ámbito de usuario tiene 12 s.
        // Un servidor de sesiones con ocho perfiles cambiaría un `null` por un
        // `timeout`, que no es mejor.
        var muchas = Enumerable.Range(1, 8).Select(i => $@"DOM\u{i}").ToArray();
        var r = LoggedOnUsersShape.Candidates(null, muchas);
        Assert.Equal(LoggedOnUsersShape.MaxUsers, r.Count);
    }

    [Fact]
    public void LaUnionNoRepiteNombres()
    {
        // Dos usuarios del mismo equipo comparten casi todas sus directivas.
        var r = LoggedOnUsersShape.Union(new List<List<string>?>
        {
            new() { "ADU-TestUserGPO", "ADU-Comun" },
            new() { "ADU-Comun", "ADU-Otra" },
        });
        Assert.Equal(new[] { "ADU-TestUserGPO", "ADU-Comun", "ADU-Otra" }, r);
    }

    [Fact]
    public void LaUnionIgnoraLasCuentasQueNoSePudieronLeer()
    {
        // `null` es "no se pudo", y no puede vaciar lo que sí se leyó.
        var r = LoggedOnUsersShape.Union(new List<List<string>?> { null, new() { "ADU-TestUserGPO" }, null });
        Assert.Equal(new[] { "ADU-TestUserGPO" }, r);
    }

    [Fact]
    public void LaUnionDeNadaEsVacio_NoNulo()
    {
        Assert.Empty(LoggedOnUsersShape.Union(new List<List<string>?>()));
    }
}
