// Las impresoras de red de los usuarios, leídas de HKEY_USERS.
//
// ⚠️ Este fichero existe por un punto ciego que costó tres pasadas de
// diagnóstico: `Get-Printer` desde un servicio (LocalSystem, Sesión 0) no ve
// las conexiones de red, que son POR USUARIO. Medido: 60 equipos Windows con el
// colector ya arreglado y cero impresoras, mientras los macOS del mismo tenant
// sí reportaban.
//
// Lo que se prueba aquí son las dos piezas puras — decodificar el nombre de la
// clave y fundir sin duplicar — porque leer el registro de verdad exige una
// sesión de usuario en Windows y eso no cabe en un test unitario.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class UserPrinterConnectionsTests
{
    [Fact]
    public void DecodificaElNombreDeLaClaveAUnc()
    {
        // Windows no puede poner `\` en una clave, así que guarda
        // `\\SRV\Cola` como `,,SRV,Cola`.
        Assert.Equal(@"\\SRV\Cola", UserPrinterConnectionsShape.UncFromKeyName(",,SRV,Cola"));
        Assert.Equal(@"\\PRINTSRV01\HP-Recepcion",
                     UserPrinterConnectionsShape.UncFromKeyName(",,PRINTSRV01,HP-Recepcion"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("SoloTexto")]      // sin comas: no es una conexión
    [InlineData(",,SoloServidor")] // servidor sin cola
    [InlineData(",,")]
    public void NoInventaUnNombreCuandoLaClaveNoSirve(string? clave)
    {
        // ⚠️ Devolver algo aquí metería una impresora fantasma en el inventario
        // de un cliente. Preferimos perder la fila a inventarla.
        Assert.Null(UserPrinterConnectionsShape.UncFromKeyName(clave));
    }

    [Fact]
    public void SacaElServidorDeLaUnc()
    {
        Assert.Equal("PRINTSRV01", UserPrinterConnectionsShape.ServerFromUnc(@"\\PRINTSRV01\HP"));
        Assert.Null(UserPrinterConnectionsShape.ServerFromUnc(@"\\SinCola"));
        Assert.Null(UserPrinterConnectionsShape.ServerFromUnc("no-es-unc"));
        Assert.Null(UserPrinterConnectionsShape.ServerFromUnc(null));
    }

    [Fact]
    public void NoDuplicaUnaColaQueYaVioLaMaquina()
    {
        // La misma impresora puede estar instalada a nivel de máquina Y
        // conectada por el usuario. Contarla dos veces infla el inventario.
        var usuario = new[]
        {
            new UserPrinterConnection(@"\\SRV\Cola", "SRV", "S-1-5-21-1"),
            new UserPrinterConnection(@"\\SRV\Otra", "SRV", "S-1-5-21-1"),
        };
        var extra = UserPrinterConnectionsShape.MergeByName(new[] { @"\\SRV\Cola" }, usuario);
        Assert.Single(extra);
    }

    [Fact]
    public void CompararNombresIgnoraMayusculas()
    {
        // Windows no distingue mayúsculas en nombres UNC; comparar sensible
        // duplicaría la misma cola por una diferencia que no existe.
        var usuario = new[] { new UserPrinterConnection(@"\\srv\cola", "srv", "S-1-5-21-1") };
        Assert.Empty(UserPrinterConnectionsShape.MergeByName(new[] { @"\\SRV\COLA" }, usuario));
    }

    [Fact]
    public void DosUsuariosConLaMismaColaLaReportanUnaVez()
    {
        var usuario = new[]
        {
            new UserPrinterConnection(@"\\SRV\Cola", "SRV", "S-1-5-21-1"),
            new UserPrinterConnection(@"\\SRV\Cola", "SRV", "S-1-5-21-2"),
        };
        Assert.Single(UserPrinterConnectionsShape.MergeByName(System.Array.Empty<string>(), usuario));
    }

    [Fact]
    public void NoRellenaDriverNiEstadoConValoresInventados()
    {
        // ⚠️ La conexión del registro no trae driver ni estado. Poner
        // "Unknown" los volvería indistinguibles de un dato leído de verdad.
        var extra = UserPrinterConnectionsShape.MergeByName(
            System.Array.Empty<string>(),
            new[] { new UserPrinterConnection(@"\\SRV\Cola", "SRV", "S-1-5-21-1") });

        var json = System.Text.Json.JsonSerializer.Serialize(extra[0]);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        Assert.Equal(System.Text.Json.JsonValueKind.Null, doc.RootElement.GetProperty("driverName").ValueKind);
        Assert.Equal(System.Text.Json.JsonValueKind.Null, doc.RootElement.GetProperty("printerStatus").ValueKind);
        // Y declara de dónde salió, para que el backend pueda distinguirla.
        Assert.Equal("user_connection", doc.RootElement.GetProperty("source").GetString());
        Assert.Equal(@"\\SRV", doc.RootElement.GetProperty("portName").GetString());
    }

    [Fact]
    public void LosTresAlcancesSonValoresDistintos()
    {
        // "se leyó y no hay ninguna", "no hay a quién leer" y "no se pudo
        // leer" eran la misma fila vacía. Ya no.
        Assert.NotEqual(UserPrinterConnectionsShape.ScopeCollected, UserPrinterConnectionsShape.ScopeNoUserHive);
        Assert.NotEqual(UserPrinterConnectionsShape.ScopeCollected, UserPrinterConnectionsShape.ScopeUnavailable);
        Assert.NotEqual(UserPrinterConnectionsShape.ScopeNoUserHive, UserPrinterConnectionsShape.ScopeUnavailable);
    }
}
