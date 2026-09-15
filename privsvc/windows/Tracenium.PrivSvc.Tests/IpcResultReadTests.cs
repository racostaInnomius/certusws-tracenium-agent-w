// privsvc/windows/Tracenium.PrivSvc.Tests/IpcResultReadTests.cs
//
// La lista de CAs emisoras tiene que CRUZAR de crypto.cert.install a
// crypto.cert.renew. No cruzaba, y MSIG-VEEAM-PC se quedó a oscuras (14-sep).

using System.Text.Json;
using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class IpcResultReadTests
{
    [Fact]
    public void Lee_el_string_array_del_objeto_anónimo_que_devuelve_la_instalación()
    {
        // La forma EXACTA del resultado de CryptoCertInstall.HandleInstallCert.
        var result = new { issuingCaThumbprint = "D0A308F5", issuingCaThumbprints = new[] { "D0A308F5", "1B340C41" } };
        Assert.Equal(new[] { "D0A308F5", "1B340C41" }, IpcResultRead.StringArray(result, "issuingCaThumbprints"));
    }

    [Fact]
    public void Lee_también_JSON()
    {
        var je = JsonDocument.Parse("{\"issuingCaThumbprints\":[\"A\",null,\" B \",3]}").RootElement;
        Assert.Equal(new[] { "A", "B" }, IpcResultRead.StringArray(je, "issuingCaThumbprints"));
    }

    [Fact]
    public void Ausente_o_de_otro_tipo_da_vacía_nunca_null()
    {
        Assert.Empty(IpcResultRead.StringArray(null, "x"));
        Assert.Empty(IpcResultRead.StringArray(new { x = "no-es-lista" }, "x"));
        Assert.Empty(IpcResultRead.StringArray(new { y = new[] { "a" } }, "x"));
    }
}
