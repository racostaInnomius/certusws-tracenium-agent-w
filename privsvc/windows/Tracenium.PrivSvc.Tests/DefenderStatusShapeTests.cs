// privsvc/windows/Tracenium.PrivSvc.Tests/DefenderStatusShapeTests.cs
//
// El modo de fallo que se defiende aquí es concreto y caro: un equipo
// SIN antivirus activo puntuaba igual que uno protegido.
//
// `GetDefenderStatus` devolvía `{ status = "not_present" }` a secas
// cuando el servicio de Defender no estaba activo — sin los tres campos
// que el catálogo evalúa. El backend leía "path not reported", resolvía
// `not_applicable`, y ese estado sale del numerador Y del denominador
// del score. Medido en producción el 2026-09-02 (T111): 38 de 50 equipos
// desaparecían del cálculo de antimalware en silencio.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class DefenderStatusShapeTests
{
    private static Dictionary<string, object> Status(
        object? service = null,
        object? realtime = null,
        object? antivirus = null)
    {
        var d = new Dictionary<string, object>();
        if (service != null) d["AMServiceEnabled"] = service;
        if (realtime != null) d["RealTimeProtectionEnabled"] = realtime;
        if (antivirus != null) d["AntivirusEnabled"] = antivirus;
        return d;
    }

    [Fact]
    public void Servicio_apagado_sigue_reportando_los_tres_campos()
    {
        // ⭐ El bug. La lectura tuvo éxito y dijo que el servicio está
        // apagado: eso es un HALLAZGO, no una ausencia de evidencia. Los
        // campos tienen que viajar para que el control pueda FALLAR.
        var shaped = DefenderStatusShape.FromComputerStatus(
            Status(service: false, realtime: false, antivirus: false));

        Assert.NotNull(shaped);
        Assert.Equal("not_present", shaped!["status"]);
        Assert.Equal(false, shaped["serviceEnabled"]);
        Assert.Equal(false, shaped["realTimeProtectionEnabled"]);
        Assert.Equal(false, shaped["antivirusEnabled"]);
    }

    [Fact]
    public void Los_tres_campos_del_catalogo_estan_siempre_que_haya_lectura()
    {
        // El catálogo evalúa `all_equal` sobre estas tres claves. Si
        // cualquiera falta, el backend resuelve not_applicable y el
        // equipo sale del score — que es justo lo que pasaba.
        foreach (var caso in new[]
        {
            Status(service: true,  realtime: true,  antivirus: true),
            Status(service: true,  realtime: false, antivirus: true),
            Status(service: false, realtime: false, antivirus: false),
            Status(service: false),                       // campos ausentes
            new Dictionary<string, object>(),             // respuesta vacía
        })
        {
            var shaped = DefenderStatusShape.FromComputerStatus(caso);
            Assert.NotNull(shaped);
            Assert.True(shaped!.ContainsKey("serviceEnabled"));
            Assert.True(shaped.ContainsKey("realTimeProtectionEnabled"));
            Assert.True(shaped.ContainsKey("antivirusEnabled"));
        }
    }

    [Fact]
    public void Lectura_fallida_es_lo_unico_que_justifica_el_silencio()
    {
        // null = Get-MpComputerStatus no devolvió nada parseable. Ahí el
        // llamador emite "unknown" sin campos, y `not_applicable` es el
        // veredicto correcto: no se puede juzgar lo que no se leyó.
        Assert.Null(DefenderStatusShape.FromComputerStatus(null));
    }

    [Fact]
    public void Nombra_el_estado_por_lo_que_leyo()
    {
        Assert.Equal("enabled",
            DefenderStatusShape.FromComputerStatus(Status(service: true, realtime: true))!["status"]);

        // Servicio activo pero protección en tiempo real apagada: no es
        // "no está", es que está y no protege.
        Assert.Equal("disabled",
            DefenderStatusShape.FromComputerStatus(Status(service: true, realtime: false))!["status"]);

        Assert.Equal("not_present",
            DefenderStatusShape.FromComputerStatus(Status(service: false))!["status"]);
    }

    [Fact]
    public void Acepta_las_formas_en_que_PowerShell_serializa_un_booleano()
    {
        // ConvertTo-Json emite True/False, y algunas propiedades vuelven
        // como 0/1. Un parseo que sólo entendiera una de las dos formas
        // devolvería false por defecto y marcaría como desprotegido un
        // equipo que sí lo está — el error simétrico, igual de malo.
        Assert.Equal(true,
            DefenderStatusShape.FromComputerStatus(Status(service: "True"))!["serviceEnabled"]);
        Assert.Equal(true,
            DefenderStatusShape.FromComputerStatus(Status(service: 1))!["serviceEnabled"]);
        Assert.Equal(false,
            DefenderStatusShape.FromComputerStatus(Status(service: 0))!["serviceEnabled"]);
    }

    [Fact]
    public void Un_campo_ausente_no_se_inventa()
    {
        // Ausente ≠ false para lo que NO decide el veredicto: la versión
        // del motor no está, y eso se dice con null, no con un string
        // vacío que parecería un dato.
        var shaped = DefenderStatusShape.FromComputerStatus(Status(service: true, realtime: true));
        Assert.Null(shaped!["engineVersion"]);
        Assert.Null(shaped["signatureVersion"]);
    }
}
