// privsvc/windows/Tracenium.PrivSvc.Tests/CdpKeyAlgorithmTests.cs
//
// ADR-0033 F1 — la tabla de algoritmos de `cdp.csr.generate`.
//
// Lo que de verdad se mide aqui es el RECHAZO. Un algoritmo desconocido
// que cayera al de por defecto produciria una clave RSA-2048 cuando
// alguien pidio ECDSA P-384, con un CSR que el inventario declararia
// como lo pedido: un falso verde que solo se veria auditando la CA meses
// despues. Por eso hay un caso por cada forma de escribirlo mal.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

namespace Tracenium.PrivSvc.Tests;

public class CdpKeyAlgorithmTests
{
    [Theory]
    [InlineData("RSA_2048", CdpKeyKind.Rsa, 2048, "SHA256")]
    [InlineData("RSA_3072", CdpKeyKind.Rsa, 3072, "SHA256")]
    [InlineData("RSA_4096", CdpKeyKind.Rsa, 4096, "SHA256")]
    [InlineData("ECDSA_P256", CdpKeyKind.Ecdsa, 256, "SHA256")]
    // El hash acompaña a la curva: P-384 con SHA-256 seria legal y
    // desperdiciaria la curva que alguien eligio a proposito.
    [InlineData("ECDSA_P384", CdpKeyKind.Ecdsa, 384, "SHA384")]
    public void ResuelveLosCincoAdmitidos(string raw, CdpKeyKind kind, int bits, string hash)
    {
        Assert.True(CdpKeyAlgorithm.TryResolve(raw, out var spec, out var error));
        Assert.Equal("", error);
        Assert.Equal(raw, spec.Name);
        Assert.Equal(kind, spec.Kind);
        Assert.Equal(bits, spec.Bits);
        Assert.Equal(hash, spec.HashName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void SinCampoSigueSiendoRsa2048(string? raw)
    {
        // ⚠️ Un control plane que todavia no manda `keyAlgorithm` tiene
        // que seguir emitiendo lo mismo que antes de ADR-0033.
        Assert.True(CdpKeyAlgorithm.TryResolve(raw, out var spec, out _));
        Assert.Equal("RSA_2048", spec.Name);
        Assert.Equal(CdpKeyKind.Rsa, spec.Kind);
        Assert.Equal(2048, spec.Bits);
    }

    [Fact]
    public void LaCajaNoImporta()
    {
        Assert.True(CdpKeyAlgorithm.TryResolve("ecdsa_p384", out var spec, out _));
        Assert.Equal("ECDSA_P384", spec.Name);
    }

    [Theory]
    [InlineData("RSA_1024")]        // mas debil: jamas
    [InlineData("RSA_2047")]
    [InlineData("ECDSA_P521")]      // no esta en la lista de F1
    [InlineData("ECDSA-P384")]      // guion en vez de subrayado
    [InlineData("ED25519")]
    [InlineData("P384")]
    [InlineData("RSA")]
    [InlineData("rsa_3072 ; DROP")]
    public void LoDesconocidoSeRechazaYNoCaeAOtraCosa(string raw)
    {
        Assert.False(CdpKeyAlgorithm.TryResolve(raw, out _, out var error));
        Assert.Contains("no soportado", error);
        // El mensaje dice QUE se admite: un rechazo sin la lista obliga a
        // leer el codigo del PrivSvc desde el otro lado del mundo.
        Assert.Contains("ECDSA_P384", error);
    }

    [Fact]
    public void LosNombresSonLosDeLaTabla()
    {
        // Los cuatro gemelos (Windows, Linux, macOS TS y el helper Swift)
        // tienen que admitir EXACTAMENTE esto. Si alguien añade uno aqui
        // sin tocar los otros tres, la misma peticion emitiria cosas
        // distintas segun el sistema operativo del endpoint.
        Assert.Equal(
            new[] { "RSA_2048", "RSA_3072", "RSA_4096", "ECDSA_P256", "ECDSA_P384" },
            CdpKeyAlgorithm.Names);
    }
}
