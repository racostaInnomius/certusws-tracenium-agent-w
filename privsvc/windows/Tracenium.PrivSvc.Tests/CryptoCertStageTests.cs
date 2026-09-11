// privsvc/windows/Tracenium.PrivSvc.Tests/CryptoCertStageTests.cs
//
// ADR-0015 punto 10 — el bundle de CA en espera.
//
// ⚠️ ESTO NO EXISTÍA EN WINDOWS, Y NINGÚN EQUIPO NUEVO PODÍA ENROLARSE.
//
// macOS y Linux recibieron `crypto.cert.stage` el 2026-09-06; el router de
// Windows no, y respondía `not_supported`. El agente lo llama sin
// condiciones al enrolar y reintentaba cada 30 s para siempre. Visto en
// campo el 2026-09-11 al instalar una VM nueva.
//
// Los parámetros se construyen deserializando JSON, no con strings de C#:
// es la forma REAL en que llegan por el pipe (valores JsonElement). Un test
// con strings pasaría con un GetString que no supiera leer JsonElement.

using System.Text.Json;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class CryptoCertStageTests : IDisposable
{
    private const string Ca =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBkTCCATegAwIBAgIUX0000000000000000000000000000wCgYIKoZIzj0EAwIw\n" +
        "-----END CERTIFICATE-----\n";

    private readonly string _dir;

    public CryptoCertStageTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "tracenium-stage-" + Guid.NewGuid().ToString("N"));
        CryptoCertStage.DirectoryForTests = _dir;
    }

    public void Dispose()
    {
        CryptoCertStage.DirectoryForTests = null;
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private static PrivSvcRequest Peticion(object parametros) => new()
    {
        Id = "s1",
        Method = "crypto.cert.stage",
        Params = JsonSerializer.Deserialize<Dictionary<string, object>>(
            JsonSerializer.Serialize(parametros))
    };

    [Fact]
    public async Task Deja_el_bundle_en_espera_con_la_forma_real_del_pipe()
    {
        var r = await CryptoCertStage.HandleStage(Peticion(new { caBundlePem = Ca }));

        Assert.True(r.Ok, r.Error?.Message);
        Assert.True(File.Exists(CryptoCertStage.StagedPath()));
        Assert.Contains("BEGIN CERTIFICATE", CryptoCertStage.ReadStaged());
    }

    [Fact]
    public async Task Rechaza_lo_que_no_es_un_certificado_y_no_escribe_nada()
    {
        var r = await CryptoCertStage.HandleStage(Peticion(new { caBundlePem = "no soy un PEM" }));

        Assert.False(r.Ok);
        Assert.Equal("invalid_ca_bundle", r.Error?.Code);
        Assert.False(File.Exists(CryptoCertStage.StagedPath()));
    }

    [Fact]
    public async Task Sin_bundle_rechaza()
    {
        var r = await CryptoCertStage.HandleStage(Peticion(new { deviceId = "x" }));

        Assert.False(r.Ok);
        Assert.Equal("invalid_ca_bundle", r.Error?.Code);
    }

    [Fact]
    public async Task Un_segundo_stage_reemplaza_al_primero()
    {
        // Un reintento del enrolamiento no puede quedarse con la cadena
        // del intento anterior.
        var otra = Ca.Replace("X0000", "Y1111");
        await CryptoCertStage.HandleStage(Peticion(new { caBundlePem = Ca }));
        await CryptoCertStage.HandleStage(Peticion(new { caBundlePem = otra }));

        Assert.Contains("Y1111", CryptoCertStage.ReadStaged());
        Assert.DoesNotContain("X0000", CryptoCertStage.ReadStaged());
    }

    [Fact]
    public async Task Descartar_lo_borra_para_el_siguiente_enrolamiento()
    {
        await CryptoCertStage.HandleStage(Peticion(new { caBundlePem = Ca }));

        CryptoCertStage.DiscardStaged();

        Assert.Null(CryptoCertStage.ReadStaged());
    }

    [Fact]
    public void Sin_nada_en_espera_devuelve_null()
    {
        Assert.Null(CryptoCertStage.ReadStaged());
    }

    [Fact]
    public void Un_fichero_plantado_que_no_es_certificado_se_ignora()
    {
        // Lo que se lee de aquí acaba en el almacén Root de la máquina.
        // Basura en su lugar tiene que ignorarse, no instalarse.
        Directory.CreateDirectory(_dir);
        File.WriteAllText(CryptoCertStage.StagedPath(), "esto no es un certificado");

        Assert.Null(CryptoCertStage.ReadStaged());
    }

    [Fact]
    public async Task Normaliza_los_finales_de_linea_de_Windows()
    {
        await CryptoCertStage.HandleStage(Peticion(new { caBundlePem = Ca.Replace("\n", "\r\n") }));

        Assert.DoesNotContain("\r", CryptoCertStage.ReadStaged());
    }
}
