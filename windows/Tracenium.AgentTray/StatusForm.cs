using Tracenium.AgentTray.Models;

namespace Tracenium.AgentTray;

internal sealed class StatusForm : Form
{
    private readonly Dictionary<string, Label> _valueLabels = new();
    private readonly Label _statusBadge;
    private readonly Label _headerSubtitle;

    public StatusForm()
    {
        Text = "Tracenium Agent Status";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(680, 560);
        BackColor = Color.White;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var header = new Panel
        {
            Dock = DockStyle.Top,
            Height = 86,
            Padding = new Padding(18, 16, 18, 10),
            BackColor = Color.FromArgb(34, 40, 49)
        };

        var headerTitle = new Label
        {
            Text = "Tracenium Agent",
            AutoSize = true,
            ForeColor = Color.White,
            Font = new Font(Font.FontFamily, 15, FontStyle.Bold)
        };

        _statusBadge = new Label
        {
            Text = "UNKNOWN",
            AutoSize = true,
            Padding = new Padding(8, 4, 8, 4),
            Font = new Font(Font.FontFamily, 9, FontStyle.Bold),
            BackColor = Color.FromArgb(96, 96, 96),
            ForeColor = Color.White,
            Location = new Point(0, 0)
        };

        _headerSubtitle = new Label
        {
            Text = "Waiting for local status snapshot...",
            AutoSize = true,
            ForeColor = Color.FromArgb(210, 216, 224),
            Location = new Point(0, 0)
        };

        header.Controls.Add(headerTitle);
        header.Controls.Add(_statusBadge);
        header.Controls.Add(_headerSubtitle);
        header.Resize += (_, _) =>
        {
            _statusBadge.Location = new Point(header.Width - _statusBadge.Width - 18, 18);
            _headerSubtitle.Location = new Point(20, 48);
        };

        var content = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(18, 14, 18, 18),
            ColumnCount = 2,
            AutoScroll = true
        };
        content.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190));
        content.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        AddSection(content, "Connectivity");
        AddRow(content, "Connectivity", "connectivity");
        AddRow(content, "Snapshot updated", "snapshotUpdated");
        AddRow(content, "Last heartbeat", "lastHeartbeat");
        AddRow(content, "Last connected", "lastConnected");
        AddRow(content, "Last disconnected", "lastDisconnected");

        AddSection(content, "Identity");
        AddRow(content, "Hostname", "hostname");
        AddRow(content, "Tenant ID", "tenantId");
        AddRow(content, "Device ID", "deviceId");
        AddRow(content, "Agent version", "agentVersion");
        AddRow(content, "Core version", "coreVersion");

        AddSection(content, "Policy");
        AddRow(content, "Policy version", "policyVersion");
        AddRow(content, "Policy hash", "policyHash");
        AddRow(content, "Enabled plugins", "plugins");
        AddRow(content, "Enabled modules", "modules");

        AddSection(content, "Operations");
        AddRow(content, "Last job", "lastJob");
        AddRow(content, "Update status", "updateStatus");
        AddRow(content, "Last update check", "lastUpdateCheck");
        AddRow(content, "Last update complete", "lastUpdateComplete");
        AddRow(content, "Patch status", "patchStatus");
        AddRow(content, "Patch last scan", "patchLastScan");
        AddRow(content, "Patch error", "patchError");

        root.Controls.Add(header, 0, 0);
        root.Controls.Add(content, 0, 1);
        Controls.Add(root);
    }

    public void Render(TrayStatus? status)
    {
        if (status is null)
        {
            ApplyHeader(false, Environment.MachineName, null, null);
            Set("connectivity", "No local status snapshot found");
            Set("snapshotUpdated", "—");
            Set("lastHeartbeat", "—");
            Set("lastConnected", "—");
            Set("lastDisconnected", "—");
            Set("agentVersion", "—");
            Set("coreVersion", "—");
            Set("hostname", Environment.MachineName);
            Set("tenantId", "—");
            Set("deviceId", "—");
            Set("policyVersion", "—");
            Set("policyHash", "—");
            Set("plugins", "—");
            Set("modules", "—");
            Set("lastJob", "—");
            Set("updateStatus", "—");
            Set("lastUpdateCheck", "—");
            Set("lastUpdateComplete", "—");
            Set("patchStatus", "—");
            Set("patchLastScan", "—");
            Set("patchError", "—");
            return;
        }

        ApplyHeader(status.Grpc.Connected, ResolveHostname(status), status.AgentVersion, status.UpdatedAtUtc);
        Set("connectivity", status.Grpc.Connected ? "Online" : "Offline");
        Set("snapshotUpdated", FormatTimestamp(status.UpdatedAtUtc));
        Set("lastHeartbeat", FormatTimestamp(status.Grpc.LastHeartbeatAtUtc));
        Set("lastConnected", FormatTimestamp(status.Grpc.LastConnectedAtUtc));
        Set("lastDisconnected", FormatTimestamp(status.Grpc.LastDisconnectedAtUtc));
        Set("agentVersion", status.AgentVersion);
        Set("coreVersion", string.IsNullOrWhiteSpace(status.CoreVersion) ? "—" : status.CoreVersion);
        Set("hostname", ResolveHostname(status));
        Set("tenantId", string.IsNullOrWhiteSpace(status.TenantId) ? "—" : status.TenantId);
        Set("deviceId", string.IsNullOrWhiteSpace(status.DeviceId) ? "—" : status.DeviceId);
        Set("policyVersion", string.IsNullOrWhiteSpace(status.Policy.Version) ? "none" : status.Policy.Version);
        Set("policyHash", string.IsNullOrWhiteSpace(status.Policy.Hash) ? "—" : status.Policy.Hash!);
        Set("plugins", status.Policy.Plugins.Count > 0 ? string.Join(", ", status.Policy.Plugins) : "—");
        Set("modules", status.Policy.Modules.Count > 0 ? string.Join(", ", status.Policy.Modules) : "—");
        Set("lastJob", FormatLastJob(status.Jobs));
        Set("updateStatus", FormatUpdateStatus(status.Update));
        Set("lastUpdateCheck", FormatTimestamp(status.Update.LastCheckedAtUtc));
        Set("lastUpdateComplete", FormatTimestamp(status.Update.LastCompletedAtUtc));
        Set("patchStatus", FormatPatchStatus(status.Patch));
        Set("patchLastScan", FormatTimestamp(status.Patch.LastScanAtUtc));
        Set("patchError", string.IsNullOrWhiteSpace(status.Patch.LastError) ? "—" : status.Patch.LastError!);
    }

    private void AddSection(TableLayoutPanel grid, string title)
    {
        var row = grid.RowStyles.Count;
        grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var section = new Label
        {
            Text = title,
            AutoSize = true,
            Font = new Font(Font.FontFamily, 10, FontStyle.Bold),
            ForeColor = Color.FromArgb(0, 120, 212),
            Margin = new Padding(0, row == 0 ? 0 : 12, 0, 8)
        };

        grid.Controls.Add(section, 0, row);
        grid.SetColumnSpan(section, 2);
    }

    private void AddRow(TableLayoutPanel grid, string label, string key)
    {
        var row = grid.RowStyles.Count;
        grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var labelControl = new Label
        {
            Text = label,
            AutoSize = true,
            Font = new Font(Font, FontStyle.Bold),
            Margin = new Padding(0, 0, 12, 10)
        };

        var valueControl = new Label
        {
            Text = "—",
            AutoSize = true,
            MaximumSize = new Size(430, 0),
            Margin = new Padding(0, 0, 0, 10)
        };

        _valueLabels[key] = valueControl;

        grid.Controls.Add(labelControl, 0, row);
        grid.Controls.Add(valueControl, 1, row);
    }

    private void ApplyHeader(bool online, string hostname, string? agentVersion, DateTime? updatedAtUtc)
    {
        _statusBadge.Text = online ? "ONLINE" : "OFFLINE";
        _statusBadge.BackColor = online
            ? Color.FromArgb(28, 160, 98)
            : Color.FromArgb(196, 59, 59);

        var version = string.IsNullOrWhiteSpace(agentVersion) ? "unknown version" : $"v{agentVersion}";
        var updated = updatedAtUtc.HasValue
            ? $"Last refresh {updatedAtUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss}"
            : "Last refresh unavailable";
        _headerSubtitle.Text = $"{hostname}  |  {version}  |  {updated}";
    }

    private void Set(string key, string value)
    {
        if (_valueLabels.TryGetValue(key, out var label))
        {
            label.Text = value;
        }
    }

    private static string ResolveHostname(TrayStatus status)
    {
        return string.IsNullOrWhiteSpace(status.Hostname) ? Environment.MachineName : status.Hostname;
    }

    private static string FormatTimestamp(DateTime? value)
    {
        return value?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "—";
    }

    private static string FormatLastJob(TrayJobStatus jobs)
    {
        if (string.IsNullOrWhiteSpace(jobs.LastJobType))
        {
            return "—";
        }

        var status = string.IsNullOrWhiteSpace(jobs.LastJobStatus) ? "unknown" : jobs.LastJobStatus;
        var at = jobs.LastJobAtUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown time";
        return $"{jobs.LastJobType} · {status} · {at}";
    }

    private static string FormatPatchStatus(TrayPatchStatus patch)
    {
        if (string.IsNullOrWhiteSpace(patch.Status))
        {
            return "—";
        }

        var reboot = patch.RebootRequired == true ? " · reboot required" : "";
        return $"{patch.Status}{reboot}";
    }

    private static string FormatUpdateStatus(TrayUpdateStatus update)
    {
        if (string.IsNullOrWhiteSpace(update.Status))
        {
            return "—";
        }

        if (string.IsNullOrWhiteSpace(update.LastError))
        {
            return update.Status;
        }

        return $"{update.Status} · {update.LastError}";
    }
}
