// privsvc/windows/Tracenium.PrivSvc.Tests/CdpKeyInfoShapeTests.cs
//
// Ola 1.3b — el mapeo proveedor → almacenamiento y la lectura de la
// política de exportación. Lo que más importa: un proveedor desconocido
// (un HSM de un fabricante) NO sale como «software», y los bits de
// archivado no hacen exportable una clave.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class CdpKeyInfoShapeTests
{
    [Theory]
    [InlineData("Microsoft Platform Crypto Provider", "tpm")]
    [InlineData("Microsoft Smart Card Key Storage Provider", "smartcard")]
    [InlineData("Microsoft Base Smart Card Crypto Provider", "smartcard")]
    [InlineData("Microsoft Software Key Storage Provider", "software")]
    [InlineData("Microsoft Enhanced RSA and AES Cryptographic Provider", "software")]
    [InlineData("microsoft software key storage provider", "software")]
    [InlineData("SafeNet Key Storage Provider", "unknown")]
    [InlineData("Microsoft Passport Key Storage Provider", "unknown")]
    [InlineData("", "unknown")]
    [InlineData(null, "unknown")]
    public void Storage_by_provider(string? provider, string expected)
    {
        Assert.Equal(expected, CdpKeyInfoShape.StorageFor(provider));
    }

    [Theory]
    [InlineData(0x0, false)]
    [InlineData(0x1, true)]  // ALLOW_EXPORT
    [InlineData(0x2, true)]  // ALLOW_PLAINTEXT_EXPORT
    [InlineData(0x4, false)] // ALLOW_ARCHIVING: solo al crear
    [InlineData(0x8, false)] // ALLOW_PLAINTEXT_ARCHIVING: solo al crear
    [InlineData(0x5, true)]
    public void Cng_export_policy(int policy, bool exportable)
    {
        Assert.Equal(exportable, CdpKeyInfoShape.ExportableFromCngPolicy(policy));
    }

    [Fact]
    public void Hardware_keys_are_not_exportable_without_opening_them()
    {
        Assert.False(CdpKeyInfoShape.ExportableByStorage("tpm"));
        Assert.False(CdpKeyInfoShape.ExportableByStorage("smartcard"));
        Assert.Null(CdpKeyInfoShape.ExportableByStorage("software"));
        Assert.Null(CdpKeyInfoShape.ExportableByStorage("unknown"));
    }
}
