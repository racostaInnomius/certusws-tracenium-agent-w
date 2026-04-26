using System.Text.Json;
using Tracenium.AgentTray.Models;

namespace Tracenium.AgentTray;

internal sealed class StatusReader
{
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public string StatusPath { get; }

    public StatusReader()
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        StatusPath = Path.Combine(programData, "Tracenium", "Agent", "status", "tray-status.json");
    }

    public TrayStatus? Read()
    {
        if (!File.Exists(StatusPath))
        {
            return null;
        }

        try
        {
            var json = File.ReadAllText(StatusPath);
            return JsonSerializer.Deserialize<TrayStatus>(json, _jsonOptions);
        }
        catch
        {
            return null;
        }
    }
}
