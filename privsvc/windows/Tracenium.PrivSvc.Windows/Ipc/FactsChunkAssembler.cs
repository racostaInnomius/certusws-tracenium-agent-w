// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/FactsChunkAssembler.cs
//
// Reensamblar un envío de facts que el agente trocea por IPC. Pura: sin
// pipe ni gRPC, para compilarse y probarse fuera de Windows. Quién la usa:
// IpcGrpcHandlers.HandleFactsChunk.
//
// ── Por qué existe ───────────────────────────────────────────────────
//
// El reensamblado estaba dentro del handler con un tope propio de 512 KiB
// que nada justificaba: el control plane acepta 16 MiB
// (certusws-tracenium/modules/grpc/payload-limits.ts). Y el rechazo volvía
// al agente como un fallo cualquiera; el agente tiraba la conexión,
// reconectaba y reenviaba el MISMO evento.
//
// TNS-OPER-SNOC04 (Server 2022), 28-sep-2026: su compliance creció de 0,51
// a 0,52 MiB, pasó de 512 KiB, y durante cuatro días el equipo reenvió los
// mismos 17 trozos en bucle sin que el servidor anotara nada. Los
// inventarios de certificados de los Windows del CDP caían en el mismo tope.
//
// Ahora:
//   · el tope es el del servidor, en bytes UTF-8 como allí (no en
//     caracteres: un payload con acentos ocupa más bytes que caracteres);
//   · se cuenta al llegar cada trozo, así un envío que no cabe se corta en
//     el primer trozo que pasa y no se guarda entero en memoria;
//   · «demasiado grande» lleva su propio código, TooLargeCode, y el agente
//     lo da por rechazado sin tocar la conexión. Reenviarlo daría lo mismo.
//
// El mismo valor está en src/transport/grpc-client.ts y en
// privsvc/shared/facts-limits.ts; un test compara los tres.

using System.Text;

namespace Tracenium.PrivSvc.Windows.Ipc;

public sealed class FactsChunkAssembler
{
    /// <summary>Bytes UTF-8 del payloadJson reensamblado. Igual que el backend.</summary>
    public const long MaxPayloadBytes = 16L * 1024 * 1024;

    /// <summary>
    /// Trozos por envío. Sólo protege la reserva antes de que llegue ningún
    /// byte: con los trozos de 32 KiB del agente, 16 MiB son 512.
    /// </summary>
    public const int MaxChunks = 1024;

    /// <summary>Código de error IPC de un envío que pasa del tope.</summary>
    public const string TooLargeCode = "facts_too_large";

    /// <summary>Un envío a medias más viejo que esto se da por abandonado.</summary>
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(2);

    public enum Outcome { Pending, Complete, TooLarge }

    public sealed record Result(
        Outcome Outcome,
        bool Duplicate = false,
        string? Payload = null,
        string? Namespace = null,
        IReadOnlyList<string>? Namespaces = null,
        string? Reason = null);

    private sealed class Entry
    {
        public int TotalChunks;
        public DateTime CreatedAt;
        public long Bytes;
        public readonly SortedDictionary<int, string> Chunks = new();
        public string? Namespace;
        public List<string> Namespaces = new();
    }

    private readonly Dictionary<string, Entry> _entries = new();
    private readonly object _lock = new();

    /// <summary>Descarta los envíos a medias abandonados; devuelve sus eventId.</summary>
    public IReadOnlyList<string> SweepStale(DateTime nowUtc)
    {
        lock (_lock)
        {
            var stale = _entries
                .Where(kv => nowUtc - kv.Value.CreatedAt > StaleAfter)
                .Select(kv => kv.Key)
                .ToList();
            foreach (var key in stale)
                _entries.Remove(key);
            return stale;
        }
    }

    /// <summary>
    /// Añade un trozo. Parámetros inválidos lanzan ArgumentException (un
    /// error de programación del llamador, no del tamaño).
    /// </summary>
    public Result Add(
        string eventId,
        int chunkIndex,
        int totalChunks,
        string payloadChunk,
        string? factNamespace,
        List<string> namespaces,
        DateTime nowUtc)
    {
        if (string.IsNullOrWhiteSpace(eventId))
            throw new ArgumentException("eventId required");
        if (totalChunks <= 0)
            throw new ArgumentException("totalChunks must be > 0");
        if (chunkIndex < 0 || chunkIndex >= totalChunks)
            throw new ArgumentException("chunkIndex out of range");

        if (totalChunks > MaxChunks)
            return new Result(Outcome.TooLarge, Reason: $"totalChunks {totalChunks} exceeds cap {MaxChunks}");

        lock (_lock)
        {
            if (!_entries.TryGetValue(eventId, out var entry))
            {
                entry = new Entry
                {
                    TotalChunks = totalChunks,
                    CreatedAt = nowUtc,
                    Namespace = factNamespace,
                    Namespaces = namespaces
                };
                _entries[eventId] = entry;
            }
            else if (entry.TotalChunks != totalChunks)
            {
                throw new ArgumentException("inconsistent totalChunks for eventId");
            }

            // Un trozo repetido se ignora en vez de sobrescribirlo en silencio.
            if (entry.Chunks.ContainsKey(chunkIndex))
                return new Result(Outcome.Pending, Duplicate: true);

            var bytes = entry.Bytes + Encoding.UTF8.GetByteCount(payloadChunk);
            if (bytes > MaxPayloadBytes)
            {
                _entries.Remove(eventId);
                return new Result(Outcome.TooLarge, Reason: $"facts payload exceeds {MaxPayloadBytes} bytes");
            }

            entry.Chunks[chunkIndex] = payloadChunk;
            entry.Bytes = bytes;

            if (entry.Chunks.Count < entry.TotalChunks)
                return new Result(Outcome.Pending);

            _entries.Remove(eventId);
            return new Result(
                Outcome.Complete,
                Payload: string.Concat(entry.Chunks.Values),
                Namespace: entry.Namespace,
                Namespaces: entry.Namespaces);
        }
    }

    /// <summary>Envíos a medias en memoria (para tests).</summary>
    public int PendingCount
    {
        get { lock (_lock) return _entries.Count; }
    }
}
