// privsvc/windows/Tracenium.PrivSvc.Tests/UninstallIdentityTests.cs
//
// ADR-0019 F0 — la identidad con la que se puede QUITAR una app.
//
// ⚠️ Se prueba porque una ruta mal construida NO FALLA: se guarda tal cual y el
// error aparece meses despues, cuando alguien intenta desinstalar con ella y no
// encuentra nada — o encuentra otra cosa.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class UninstallIdentityTests
{
    [Fact]
    public void Reconoce_un_ProductCode_de_MSI()
    {
        Assert.True(UninstallIdentity.LooksLikeProductCode("{D73883EB-7167-37B2-A69C-06A4744F64D2}"));
    }

    [Fact]
    public void No_inventa_un_ProductCode_donde_no_lo_hay()
    {
        // Un instalador EXE pone en la clave el nombre que quiere. Devolver eso
        // como ProductCode seria peor que devolver null: `msiexec /x` con basura
        // no falla ruidosamente, desinstala otra cosa o nada.
        Assert.False(UninstallIdentity.LooksLikeProductCode("Dropbox"));
        Assert.False(UninstallIdentity.LooksLikeProductCode("Zoom"));
        Assert.False(UninstallIdentity.LooksLikeProductCode(""));
        Assert.False(UninstallIdentity.LooksLikeProductCode(null));
        // Un GUID SIN llaves no es la forma con la que Windows nombra la clave.
        Assert.False(UninstallIdentity.LooksLikeProductCode("D73883EB-7167-37B2-A69C-06A4744F64D2"));
    }

    [Fact]
    public void La_ruta_de_una_app_por_usuario_lleva_HKU_y_el_SID()
    {
        // El backend se niega a desinstalar lo que empieza por HKU\: el PrivSvc
        // corre como SYSTEM y un desinstalador de usuario no sabe de quién es
        // el perfil. Si el prefijo cambiara, esa guarda dejaría de ver la fila.
        Assert.Equal(
            @"HKU\S-1-5-21-1111111111-2222222222-3333333333-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome",
            UninstallIdentity.BuildUserKeyPath("S-1-5-21-1111111111-2222222222-3333333333-1001", "Google Chrome"));
    }

    [Fact]
    public void La_ruta_de_HKLM_en_64_bits_no_lleva_WOW6432Node()
    {
        Assert.Equal(
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{ABC}",
            UninstallIdentity.BuildKeyPath(localMachine: true, wow6432: false, "{ABC}"));
    }

    [Fact]
    public void La_vista_de_32_bits_va_bajo_WOW6432Node()
    {
        // Omitirlo daria una ruta que NO EXISTE para quien la lea despues con
        // la vista por defecto.
        Assert.Equal(
            @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Dropbox",
            UninstallIdentity.BuildKeyPath(localMachine: true, wow6432: true, "Dropbox"));
    }

    [Fact]
    public void HKCU_se_distingue_de_HKLM()
    {
        // ⚠️ No es cosmetico. HKCU aqui es el del usuario bajo el que corre el
        // PrivSvc —LocalSystem—, no el humano sentado delante. Desinstalar una
        // entrada de HKCU desde LocalSystem es otra operacion, y a menudo
        // imposible: quien decida tiene que poder verlo sin adivinar.
        var hkcu = UninstallIdentity.BuildKeyPath(localMachine: false, wow6432: false, "X");
        var hklm = UninstallIdentity.BuildKeyPath(localMachine: true, wow6432: false, "X");
        Assert.StartsWith(@"HKCU\", hkcu);
        Assert.StartsWith(@"HKLM\", hklm);
        Assert.NotEqual(hkcu, hklm);
    }

    [Fact]
    public void Las_cuatro_combinaciones_dan_cuatro_rutas_distintas()
    {
        // El colector lee los cuatro sitios. Si dos colapsaran en la misma
        // ruta, dos apps distintas serian indistinguibles.
        var rutas = new[]
        {
            UninstallIdentity.BuildKeyPath(true,  false, "X"),
            UninstallIdentity.BuildKeyPath(true,  true,  "X"),
            UninstallIdentity.BuildKeyPath(false, false, "X"),
            UninstallIdentity.BuildKeyPath(false, true,  "X"),
        };
        Assert.Equal(4, new HashSet<string>(rutas).Count);
    }
}
