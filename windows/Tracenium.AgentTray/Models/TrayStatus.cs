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
    // Device Info (support widget). Null on snapshots from older agents.
    public TrayDeviceInfo? Device { get; set; }
}

/// <summary>
/// Static device identity written by the agent at startup. Logged-in
/// user and screen resolution are NOT here — this tray runs in the user
/// session and reads those live (Environment / Screen), where the
/// SYSTEM-service agent's view would be wrong.
/// </summary>
internal sealed class TrayDeviceInfo
{
    public string? Hostname { get; set; }
    public string? Domain { get; set; }
    public string? Fqdn { get; set; }
    public string? Ipv4 { get; set; }
    public string? Ipv6 { get; set; }
    public string? Mac { get; set; }
    public string? OsName { get; set; }
    public string? OsVersion { get; set; }
    public string? OsBuild { get; set; }
    public string? Manufacturer { get; set; }
    public string? Model { get; set; }
    public string? Serial { get; set; }
    public string? Cpu { get; set; }
    public double? MemoryGb { get; set; }
}

internal sealed class TrayPolicyFeatures
{
    // Gates the always-visible top-center flyout (DeviceInfoFlyout).
    // The in-window Device Info tab is NOT gated.
    public bool? DeviceInfoWidget { get; set; }
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
    public TrayPolicyFeatures? Features { get; set; }
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
