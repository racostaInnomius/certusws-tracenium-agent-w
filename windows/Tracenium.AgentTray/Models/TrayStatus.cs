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
    // Self-service Software Catalog. Null on snapshots from older agents
    // (pre self-service catalog) — treated the same as an empty catalog.
    public TrayCatalogStatus? Catalog { get; set; }

    /// <summary>
    /// Sesión de control remoto en curso, o null si no hay ninguna (ADR-0012).
    /// Ausente en snapshots de agentes anteriores al indicador.
    /// </summary>
    public TrayRemoteSession? RemoteSession { get; set; }
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
    // Present only between markJobStarted() and the matching
    // markJobFinished() on the agent side — see tray-status-types.ts's
    // TrayCurrentJob doc comment. Drives the "Active Job" tab.
    public TrayCurrentJob? Current { get; set; }
}

internal sealed class TrayCurrentJob
{
    public string JobId { get; set; } = "";
    public string JobType { get; set; } = "";
    public DateTime StartedAtUtc { get; set; }
}

/// <summary>
/// One entry in the self-service Software Catalog tray tab. Mirrors
/// proto SoftwareCatalogItem — see controlplane.proto's "SOFTWARE
/// CATALOG (self-service)" doc block.
/// </summary>
internal sealed class TrayCatalogItem
{
    public string PackageId { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Vendor { get; set; }
    public string Version { get; set; } = "";
    public string? Description { get; set; }
    public bool? RequiresReboot { get; set; }
}

internal sealed class TrayCatalogStatus
{
    public DateTime? UpdatedAtUtc { get; set; }
    public string? CatalogVersion { get; set; }
    public List<TrayCatalogItem> Items { get; set; } = new();
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

/// <summary>
/// Sesión de control remoto viva en este equipo.
///
/// La bandeja la usa para mostrar un indicador PERMANENTE mientras dure. No es
/// un aviso que se descarta: lo que protege a la persona no es enterarse una
/// vez, sino poder ver en todo momento que la están mirando y cortarlo.
/// </summary>
internal sealed class TrayRemoteSession
{
    public bool Active { get; set; }
    public string SessionId { get; set; } = "";
    public string Capability { get; set; } = "";
    public DateTime? StartedAtUtc { get; set; }

    /// <summary>
    /// Quién está mirando. Vacío en backends anteriores al campo; la UI dice
    /// "un operador" antes que inventarse un nombre.
    /// </summary>
    public string? Operator { get; set; }

    public bool Controlling { get; set; }
    public bool Recording { get; set; }
}
