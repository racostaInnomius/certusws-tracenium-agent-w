// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/Protocol.cs
using System.Text.Json.Serialization;

namespace Tracenium.PrivSvc.Windows.Ipc;

public sealed class PrivSvcRequest
{
    [JsonPropertyName("v")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("method")]
    public string Method { get; set; } = "";

    [JsonPropertyName("params")]
    public Dictionary<string, object>? Params { get; set; }

    [JsonPropertyName("meta")]
    public PrivSvcMeta Meta { get; set; } = new();
}

public sealed class PrivSvcMeta
{
    [JsonPropertyName("tenantId")]
    public string TenantId { get; set; } = "";

    [JsonPropertyName("deviceId")]
    public string DeviceId { get; set; } = "";
}

public sealed class PrivSvcResponse
{
    [JsonPropertyName("v")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("ok")]
    public bool Ok { get; set; }

    [JsonPropertyName("result")]
    public object? Result { get; set; }

    [JsonPropertyName("error")]
    public PrivSvcError? Error { get; set; }

    public static PrivSvcResponse Success(string id, object? result) =>
        new()
        {
            Id = id,
            Ok = true,
            Result = result,
            Error = null
        };

    public static PrivSvcResponse Fail(string id, string code, string message) =>
        new()
        {
            Id = id,
            Ok = false,
            Result = null,
            Error = new PrivSvcError { Code = code, Message = message }
        };
}

public sealed class PrivSvcError
{
    [JsonPropertyName("code")]
    public string Code { get; set; } = "";

    [JsonPropertyName("message")]
    public string Message { get; set; } = "";
}