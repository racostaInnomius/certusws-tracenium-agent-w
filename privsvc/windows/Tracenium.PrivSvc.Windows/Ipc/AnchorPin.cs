// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AnchorPin.cs
//
// Fijacion (pinning) de las ANCLAS DE CONFIANZA. ADR-0011, fase 0.
//
// Port directo de privsvc/macos/src/anchor-pin.ts — misma decision, mismo
// formato de fichero, mismos modos. Se mantienen deliberadamente
// paralelos: dos implementaciones de la misma regla que divergen es peor
// que no tener ninguna, porque nadie sabe cual manda.
//
// ── Que problema resuelve ────────────────────────────────────────────
//
// CryptoCertInstall instala en LocalMachine\Root el certificado
// autofirmado que venga en el bundle, y ese bundle sale de la respuesta
// del servidor — incluida la de RENOVACION, que es periodica. Al enrolar
// es legitimo: hay que confiar en algo para arrancar. Que la renovacion
// lo repita sin recordar en que se confio la primera vez es lo que
// permite a un control plane comprometido plantar un ancla arbitraria en
// cada endpoint, sin ninguna capacidad de escritura nueva.
//
// ── Por que OBSERVA y no BLOQUEA por defecto ─────────────────────────
//
// Hay una rotacion de CA en curso. Un pin estricto en mitad de una
// rotacion legitima rechaza el ancla nueva, y un equipo que no confia en
// la CA nueva acaba sin poder conectar — sin conexion no hay forma de
// mandarle el arreglo, asi que se convierte en visita presencial. Es el
// mismo razonamiento que ya esta escrito en server-pin.ts para el pin de
// conexion, y la misma secuencia que la fase 1 de ADR-0009: expediente
// primero, gate despues.
//
// Se activa con la variable de entorno TRACENIUM_ANCHOR_PIN=enforce.

using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public sealed class AnchorPinVerdict
{
    public List<string> Pinned { get; init; } = new();
    public List<string> Incoming { get; init; } = new();
    public List<string> Unpinned { get; init; } = new();
    public List<string> Rejected { get; init; } = new();
    public bool FirstRun { get; init; }
}

public static class AnchorPin
{
    private sealed class PinFile
    {
        public int version { get; set; } = 1;
        public List<string> anchors { get; set; } = new();
    }

    /// <summary>`enforce` solo si se pide explicitamente. Ver cabecera.</summary>
    public static bool IsEnforcing() =>
        string.Equals(
            Environment.GetEnvironmentVariable("TRACENIUM_ANCHOR_PIN"),
            "enforce",
            StringComparison.OrdinalIgnoreCase);

    private static string PinPath() =>
        Path.Combine(AppContext.BaseDirectory, "anchor-pins.json");

    /// <summary>
    /// Ausente o ilegible = sin linea base, no alarma. Un fichero corrupto
    /// no puede convertirse en una alerta para toda la flota.
    /// </summary>
    public static List<string> Load()
    {
        try
        {
            var path = PinPath();
            if (!File.Exists(path)) return new List<string>();
            var parsed = JsonSerializer.Deserialize<PinFile>(File.ReadAllText(path));
            return parsed?.anchors?.Where(a => !string.IsNullOrWhiteSpace(a)).ToList()
                   ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }

    /// <summary>
    /// Guarda la UNION de lo fijado y lo aceptado.
    ///
    /// Union y no reemplazo: durante una rotacion conviven la CA vieja y
    /// la nueva, y olvidar la vieja haria que la siguiente comprobacion la
    /// viera como desconocida. Un pin que se reescribe entero cada vez no
    /// es un pin.
    /// </summary>
    public static void Save(IEnumerable<string> anchors)
    {
        try
        {
            var merged = anchors
                .Where(a => !string.IsNullOrWhiteSpace(a))
                .Select(a => a.ToLowerInvariant())
                .Distinct()
                .OrderBy(a => a, StringComparer.Ordinal)
                .ToList();

            var path = PinPath();
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(new PinFile { anchors = merged }));
            File.Move(tmp, path, overwrite: true);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PrivSvc][AnchorPin] no se pudo persistir la linea base: {ex.Message}");
        }
    }

    /// <summary>
    /// El nucleo. Equivalente literal de `evaluateAnchorPins` en TypeScript.
    ///
    /// La PRIMERA vez no acusa a nadie: sin linea base no hay contra que
    /// comparar, y tratar todo como sospechoso convertiria cada
    /// enrolamiento en una alarma.
    /// </summary>
    public static AnchorPinVerdict Evaluate(
        List<string> pinned,
        List<string> incoming,
        bool enforcing)
    {
        var known = new HashSet<string>(
            pinned.Select(p => p.ToLowerInvariant()), StringComparer.Ordinal);
        var firstRun = pinned.Count == 0;

        var unpinned = firstRun
            ? new List<string>()
            : incoming.Where(fp => !known.Contains(fp.ToLowerInvariant())).ToList();

        return new AnchorPinVerdict
        {
            Pinned = pinned,
            Incoming = incoming,
            Unpinned = unpinned,
            FirstRun = firstRun,
            Rejected = enforcing ? unpinned : new List<string>()
        };
    }

    /// <summary>Texto para el log. Separado para que el mensaje sea probable.</summary>
    public static string Describe(AnchorPinVerdict v)
    {
        if (v.FirstRun)
            return $"anchor-pin: linea base establecida con {v.Incoming.Count} ancla(s)";
        if (v.Unpinned.Count == 0)
            return $"anchor-pin: {v.Incoming.Count} ancla(s), todas ya fijadas";

        var verb = v.Rejected.Count > 0 ? "RECHAZADA(S)" : "ACEPTADA(S) en modo observe";
        return $"anchor-pin: ATENCION — {v.Unpinned.Count} ancla(s) NO fijada(s) {verb}: "
               + string.Join(", ", v.Unpinned);
    }
}
