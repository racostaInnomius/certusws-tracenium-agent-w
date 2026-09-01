// privsvc/windows/Tracenium.PrivSvc.Tests/CryptoKeyNamesTests.cs
//
// ADR-0011 action item 9.
//
// Lo que se defiende aqui tiene un modo de fallo concreto y caro: con el
// `keyName` sin validar, una peticion podia borrar la clave privada de
// la identidad mTLS del agente. El equipo deja de hablar con el control
// plane y, como no habla, no se le puede mandar el arreglo — es una
// visita presencial por equipo.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class CryptoKeyNamesTests
{
    private const string Device = "9f1c2b30-0000-4000-8000-abcdefabcdef";
    private static string Enrolamiento => $"tracenium-{Device}";

    [Fact]
    public void SinNombre_devuelve_el_de_enrolamiento()
    {
        // El comportamiento de siempre: el agente no pasa `keyName`.
        Assert.Equal(Enrolamiento, CryptoKeyNames.Resolve(null, Device));
        Assert.Equal(Enrolamiento, CryptoKeyNames.Resolve("", Device));
        Assert.Equal(Enrolamiento, CryptoKeyNames.Resolve("   ", Device));
    }

    [Fact]
    public void Acepta_la_clave_pendiente_de_rotacion()
    {
        // La forma que produce CryptoCertRenew. Si esto dejara de pasar,
        // la rotacion de certificados se rompe en toda la flota.
        var pendiente = $"{Enrolamiento}-renew-1756700000";
        Assert.Equal(pendiente, CryptoKeyNames.Resolve(pendiente, Device));
    }

    [Theory]
    // ⭐ Otro contenedor del equipo: el daño saliendose del producto.
    [InlineData("iisConfigurationKey")]
    [InlineData("Microsoft Internet Information Server")]
    // El espacio de nombres de otro dispositivo.
    [InlineData("tracenium-otro-device")]
    // Variaciones que "casi" pasan.
    [InlineData("tracenium-9f1c2b30-0000-4000-8000-abcdefabcdef-renew-")]
    [InlineData("tracenium-9f1c2b30-0000-4000-8000-abcdefabcdef-renew-abc")]
    [InlineData("tracenium-9f1c2b30-0000-4000-8000-abcdefabcdef-renew-1x")]
    [InlineData("xtracenium-9f1c2b30-0000-4000-8000-abcdefabcdef")]
    [InlineData("tracenium-9f1c2b30-0000-4000-8000-abcdefabcdef-otracosa")]
    // Sufijo sin tope: un nombre de contenedor arbitrariamente largo.
    [InlineData("tracenium-9f1c2b30-0000-4000-8000-abcdefabcdef-renew-123456789012345678901")]
    public void Rechaza_todo_lo_que_no_puede_haber_derivado_el_propio_servicio(string pedido)
    {
        Assert.Throws<ArgumentException>(() => CryptoKeyNames.Resolve(pedido, Device));
    }

    [Fact]
    public void El_deviceId_se_escapa_antes_de_entrar_en_el_patron()
    {
        // Sin `Regex.Escape`, un deviceId con metacaracteres convertiria
        // la comprobacion en un comodin y volveria a aceptar nombres
        // ajenos. Llega del llamante, asi que no es hipotetico.
        const string raro = "a.c";
        Assert.Equal($"tracenium-{raro}", CryptoKeyNames.Resolve(null, raro));
        Assert.Throws<ArgumentException>(() => CryptoKeyNames.Resolve("tracenium-abc", raro));
        Assert.Throws<ArgumentException>(() => CryptoKeyNames.Resolve("tracenium-a-c-renew-1", raro));
    }

    [Fact]
    public void Exige_deviceId()
    {
        Assert.Throws<ArgumentException>(() => CryptoKeyNames.Resolve(null, ""));
        Assert.Throws<ArgumentException>(() => CryptoKeyNames.Resolve(null, "  "));
    }

    [Fact]
    public void Estrella_pedir_la_identidad_viva_con_reuse_false_es_destruirla()
    {
        // ESTE es el agujero del action item 9. `reuseExistingKey:false`
        // sobre el contenedor vivo entra en OpenOrCreateMachineRsaKey,
        // que hace `existingKey.Delete()`.
        Assert.True(CryptoKeyNames.WouldDestroyLiveIdentity(Enrolamiento, Device, reuseExistingKey: false));
    }

    // ── Que ALGUIEN lo llame ───────────────────────────────────────
    //
    // Un guard perfecto que nadie invoca no defiende de nada, y en este
    // repositorio ese es un fallo con historial: `purge_after` se
    // escribe y no lo barre nadie, `consumeApprovedRequest` estuvo sin
    // llamarse, `expireStaleRequests` igual.
    //
    // Los handlers no se pueden ejecutar aqui —abren contenedores CNG,
    // que es solo-Windows—, asi que lo que se comprueba es el CABLEADO
    // leyendo el fuente. Es una comprobacion mas debil que ejecutar el
    // handler, y conviene decirlo: cubre «se dejo de llamar», no «se
    // llama mal».

    private static string LeerFuente(string nombre)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && dir.Name != "Tracenium.PrivSvc.Tests") dir = dir.Parent;
        Assert.NotNull(dir);
        var ruta = Path.Combine(dir!.Parent!.FullName, "Tracenium.PrivSvc.Windows", "Ipc", nombre);
        Assert.True(File.Exists(ruta), $"no se encontro {ruta}");
        return File.ReadAllText(ruta);
    }

    [Theory]
    [InlineData("CryptoCsr.cs")]
    [InlineData("CryptoCertInstall.cs")]
    public void Los_handlers_derivan_el_nombre_en_vez_de_usar_el_del_llamante(string fichero)
    {
        var fuente = LeerFuente(fichero);
        Assert.Contains("CryptoKeyNames.Resolve", fuente);
        // Y que no haya vuelto la construccion inline, que es la forma
        // exacta que tenia el agujero.
        Assert.DoesNotContain("GetString(p, \"keyName\") ?? $\"tracenium-", fuente);
    }

    [Fact]
    public void El_generador_de_CSR_ademas_rechaza_destruir_la_identidad_viva()
    {
        Assert.Contains("WouldDestroyLiveIdentity", LeerFuente("CryptoCsr.cs"));
    }

    [Fact]
    public void Lo_que_la_rotacion_hace_de_verdad_sigue_permitido()
    {
        // La rotacion usa reuse:false, pero sobre la clave PENDIENTE, no
        // sobre la viva. Si esta comprobacion tambien la bloqueara, el
        // arreglo habria roto la renovacion de certificados — que es el
        // camino que mas veces corre en produccion.
        var pendiente = $"{Enrolamiento}-renew-1756700000";
        Assert.False(CryptoKeyNames.WouldDestroyLiveIdentity(pendiente, Device, reuseExistingKey: false));

        // Y reutilizar la viva no destruye nada: es el enrolamiento normal.
        Assert.False(CryptoKeyNames.WouldDestroyLiveIdentity(Enrolamiento, Device, reuseExistingKey: true));
    }
}
