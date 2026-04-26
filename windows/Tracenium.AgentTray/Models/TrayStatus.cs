namespace Tracenium.AgentTray.Models;

internal sealed class TrayStatus
{
    public DateTime? UpdatedAtUtc { get; set; }
    public string AgentVersion { get; set; } = "";
    public string CoreVersion { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string TenantId { get; set; } = "";
    public string Hostname { get; set; } = "";
    public TrayGrpcStatus Grpc { get; set; } = new();
    public TrayPolicyStatus Policy { get; set; } = new();
    public TrayJobStatus Jobs { get; set; } = new();
    public TrayUpdateStatus Update { get; set; } = new();
    public TrayPatchStatus Patch { get; set; } = new();
}

internal sealed class TrayGrpcStatus
{
    public bool Connected { get; set; }
    public DateTime? LastConnectedAtUtc { get; set; }
    public DateTime? LastDisconnectedAtUtc { get; set; }
    public DateTime? LastHeartbeatAtUtc { get; set; }
}

internal sealed class TrayPolicyStatus
{
    public string Version { get; set; } = "none";
    public string? Hash { get; set; }
    public List<string> Plugins { get; set; } = [];
    public List<string> Modules { get; set; } = [];
}

internal sealed class TrayJobStatus
{
    public string? LastJobType { get; set; }
    public string? LastJobStatus { get; set; }
    public DateTime? LastJobAtUtc { get; set; }
}

internal sealed class TrayUpdateStatus
{
    public string? Status { get; set; }
    public DateTime? LastCheckedAtUtc { get; set; }
    public DateTime? LastCompletedAtUtc { get; set; }
    public string? LastError { get; set; }
}

internal sealed class TrayPatchStatus
{
    public string? Status { get; set; }
    public DateTime? LastScanAtUtc { get; set; }
    public bool? RebootRequired { get; set; }
    public string? LastError { get; set; }
}
