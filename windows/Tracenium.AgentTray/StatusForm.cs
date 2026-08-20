using Tracenium.AgentTray.Models;

namespace Tracenium.AgentTray;

internal sealed class StatusForm : Form
{
    private readonly Dictionary<string, Label> _valueLabels = new();
    private readonly List<Label> _deviceValueLabels = new();
    private readonly Label _statusBadge;
    private readonly Label _headerSubtitle;
    private readonly Button _copyAllButton;
    private readonly TabPage _activeJobPage;
    private readonly ProgressBar _jobProgress;
    private readonly Label _jobNote;
    private readonly TabPage _catalogPage;
    private readonly FlowLayoutPanel _catalogFlow;
    private readonly Label _catalogEmptyLabel;
    // Grace window a just-clicked Install button stays "Installing…" even
    // if the next 5s poll hasn't yet reflected a running job — avoids a
    // one-tick flash back to enabled between the click and the job
    // actually starting.
    private static readonly TimeSpan InstallRequestGrace = TimeSpan.FromSeconds(90);
    private readonly Dictionary<string, DateTime> _pendingInstallClicks = new();
    private TrayStatus? _lastStatus;

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
        AddRow(content, "Enabled plugins", "plugins");
        AddRow(content, "Enabled modules", "modules");

        // Tabs: Device Info (soporte, default) | Agent Info (grid clásico).
        var tabs = new TabControl
        {
            Dock = DockStyle.Fill
        };

        var devicePage = new TabPage("Device Info") { BackColor = Color.White, UseVisualStyleBackColor = true };
        var agentPage = new TabPage("Agent Info") { BackColor = Color.White, UseVisualStyleBackColor = true };

        // El grid clásico completo se muda intacto al tab de agente.
        agentPage.Controls.Add(content);

        // Device page: strip con "Copy all" arriba + grid de campos abajo.
        var deviceLayout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2
        };
        deviceLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        deviceLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var copyStrip = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            FlowDirection = FlowDirection.RightToLeft,
            AutoSize = true,
            Padding = new Padding(12, 8, 12, 0)
        };
        _copyAllButton = new Button
        {
            Text = "Copy all",
            AutoSize = true,
            UseVisualStyleBackColor = true
        };
        _copyAllButton.Click += (_, _) => CopyAllToClipboard();
        copyStrip.Controls.Add(_copyAllButton);

        var deviceGrid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(18, 6, 18, 18),
            ColumnCount = 2,
            AutoScroll = true
        };
        deviceGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190));
        deviceGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        // Las rows salen del provider para que el tab, el flyout y el
        // Copy all muestren siempre los mismos campos en el mismo orden.
        AddSection(deviceGrid, "Device information");
        foreach (var field in DeviceInfoProvider.BuildFields(null))
        {
            _deviceValueLabels.Add(AddDeviceRow(deviceGrid, field.Label));
        }

        deviceLayout.Controls.Add(copyStrip, 0, 0);
        deviceLayout.Controls.Add(deviceGrid, 0, 1);
        devicePage.Controls.Add(deviceLayout);

        // Activity page: current job (if any) + an indeterminate progress
        // bar, plus the Operations rows (last job, update/patch status)
        // that used to sit on the Agent Info tab — moved here so
        // everything about "what the agent is doing" lives in one place.
        // The agent never reports a completion percentage (RunJob over
        // gRPC carries only jobId/jobType/payload), so the job section
        // can only confirm "something is running" and show elapsed time
        // — same contract as the macOS tray's Active Job tab.
        _activeJobPage = new TabPage("Activity") { BackColor = Color.White, UseVisualStyleBackColor = true };

        var jobGrid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(18, 14, 18, 18),
            ColumnCount = 2,
            AutoScroll = true
        };
        jobGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190));
        jobGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        AddSection(jobGrid, "Active Job");
        AddRow(jobGrid, "Status", "jobActiveStatus");
        AddRow(jobGrid, "Job type", "jobActiveType");
        AddRow(jobGrid, "Job ID", "jobActiveId");
        AddRow(jobGrid, "Started at", "jobActiveStarted");
        AddRow(jobGrid, "Elapsed", "jobActiveElapsed");

        _jobProgress = new ProgressBar
        {
            Style = ProgressBarStyle.Marquee,
            MarqueeAnimationSpeed = 30,
            Width = 320,
            Height = 16,
            Margin = new Padding(0, 4, 0, 10),
            Visible = false
        };
        var progressRow = jobGrid.RowStyles.Count;
        jobGrid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        jobGrid.Controls.Add(_jobProgress, 0, progressRow);
        jobGrid.SetColumnSpan(_jobProgress, 2);

        _jobNote = new Label
        {
            Text = "The agent doesn't report a completion percentage — this bar just confirms a job is in flight, and the elapsed time above is live.",
            AutoSize = true,
            MaximumSize = new Size(430, 0),
            ForeColor = Color.Gray,
            Font = new Font(Font.FontFamily, 8.5f),
            Visible = false
        };
        var noteRow = jobGrid.RowStyles.Count;
        jobGrid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        jobGrid.Controls.Add(_jobNote, 0, noteRow);
        jobGrid.SetColumnSpan(_jobNote, 2);

        // Moved from the Agent Info tab: last job dispatched, plus
        // agent-update/patch status. Same _valueLabels keys as before —
        // Render()'s Set(...) calls don't need to change, only where the
        // row lives.
        AddSection(jobGrid, "Operations");
        AddRow(jobGrid, "Last job", "lastJob");
        AddRow(jobGrid, "Update status", "updateStatus");
        AddRow(jobGrid, "Last update check", "lastUpdateCheck");
        AddRow(jobGrid, "Last update complete", "lastUpdateComplete");
        AddRow(jobGrid, "Patch status", "patchStatus");
        AddRow(jobGrid, "Patch last scan", "patchLastScan");
        AddRow(jobGrid, "Patch error", "patchError");

        _activeJobPage.Controls.Add(jobGrid);

        // Catalog page: self-service Software Catalog — admin-opted-in
        // packages the user can install themselves. A FlowLayoutPanel
        // (not a TableLayoutPanel) holds the dynamic per-package rows on
        // purpose: it supports Controls.Clear() + rebuild safely on every
        // render tick, unlike a TableLayoutPanel's row/cell bookkeeping.
        _catalogPage = new TabPage("Catalog") { BackColor = Color.White, UseVisualStyleBackColor = true };

        var catalogScroll = new Panel
        {
            Dock = DockStyle.Fill,
            AutoScroll = true,
            Padding = new Padding(18, 14, 18, 18)
        };

        _catalogFlow = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
            Width = 560
        };

        _catalogEmptyLabel = new Label
        {
            Text = "Nothing available right now.",
            AutoSize = true,
            Font = new Font(Font.FontFamily, 9.5f),
            ForeColor = Color.Gray,
            Margin = new Padding(0, 6, 0, 0)
        };

        catalogScroll.Controls.Add(_catalogFlow);
        _catalogPage.Controls.Add(catalogScroll);

        tabs.TabPages.Add(devicePage);
        tabs.TabPages.Add(agentPage);
        tabs.TabPages.Add(_activeJobPage);
        tabs.TabPages.Add(_catalogPage);

        root.Controls.Add(header, 0, 0);
        root.Controls.Add(tabs, 0, 1);
        Controls.Add(root);
    }

    private void CopyAllToClipboard()
    {
        try
        {
            Clipboard.SetText(DeviceInfoProvider.BuildCopyText(_lastStatus));
            // Feedback breve en el propio botón, sin popups.
            _copyAllButton.Text = "Copied ✓";
            var revert = new System.Windows.Forms.Timer { Interval = 1500 };
            revert.Tick += (_, _) =>
            {
                _copyAllButton.Text = "Copy all";
                revert.Stop();
                revert.Dispose();
            };
            revert.Start();
        }
        catch
        {
            // Clipboard puede fallar si otro proceso lo tiene bloqueado —
            // no es motivo para crashear el tray.
        }
    }

    public void Render(TrayStatus? status)
    {
        _lastStatus = status;
        RenderDeviceInfo(status);
        if (status is null)
        {
            ApplyHeader(false, Environment.MachineName, null, null);
            Set("connectivity", "No local status snapshot found");
            Set("lastHeartbeat", "—");
            Set("lastConnected", "—");
            Set("lastDisconnected", "—");
            Set("agentVersion", "—");
            Set("coreVersion", "—");
            Set("hostname", Environment.MachineName);
            Set("tenantId", "—");
            Set("deviceId", "—");
            Set("policyVersion", "—");
            Set("plugins", "—");
            Set("modules", "—");
            Set("lastJob", "—");
            Set("updateStatus", "—");
            Set("lastUpdateCheck", "—");
            Set("lastUpdateComplete", "—");
            Set("patchStatus", "—");
            Set("patchLastScan", "—");
            Set("patchError", "—");
            RenderActiveJob(null);
            RenderCatalog(null, false);
            return;
        }

        ApplyHeader(status.Grpc.Connected, ResolveHostname(status), status.AgentVersion, status.UpdatedAtUtc);
        Set("connectivity", status.Grpc.Connected ? "Online" : "Offline");
        Set("lastHeartbeat", FormatTimestamp(status.Grpc.LastHeartbeatAtUtc));
        Set("lastConnected", FormatTimestamp(status.Grpc.LastConnectedAtUtc));
        Set("lastDisconnected", FormatTimestamp(status.Grpc.LastDisconnectedAtUtc));
        Set("agentVersion", status.AgentVersion);
        Set("coreVersion", string.IsNullOrWhiteSpace(status.CoreVersion) ? "—" : status.CoreVersion);
        Set("hostname", ResolveHostname(status));
        Set("tenantId", string.IsNullOrWhiteSpace(status.TenantId) ? "—" : status.TenantId);
        Set("deviceId", string.IsNullOrWhiteSpace(status.DeviceId) ? "—" : status.DeviceId);
        Set("policyVersion", string.IsNullOrWhiteSpace(status.Policy.Version) ? "none" : status.Policy.Version);
        Set("plugins", status.Policy.Plugins.Count > 0 ? string.Join(", ", status.Policy.Plugins) : "—");
        Set("modules", status.Policy.Modules.Count > 0 ? string.Join(", ", status.Policy.Modules) : "—");
        Set("lastJob", FormatLastJob(status.Jobs));
        Set("updateStatus", FormatUpdateStatus(status.Update));
        Set("lastUpdateCheck", FormatTimestamp(status.Update.LastCheckedAtUtc));
        Set("lastUpdateComplete", FormatTimestamp(status.Update.LastCompletedAtUtc));
        Set("patchStatus", FormatPatchStatus(status.Patch));
        Set("patchLastScan", FormatTimestamp(status.Patch.LastScanAtUtc));
        Set("patchError", string.IsNullOrWhiteSpace(status.Patch.LastError) ? "—" : status.Patch.LastError!);
        RenderActiveJob(status.Jobs.Current);
        RenderCatalog(status.Catalog, status.Jobs.Current != null);
    }

    /// <summary>
    /// Mirrors the macOS tray's Active Job tab: no live progress percentage
    /// (RunJob over gRPC carries only jobId/jobType/payload), so this only
    /// confirms a job is in flight and shows elapsed time. The tab label
    /// gets a "●" suffix while running so the signal is visible even when
    /// a different tab is focused.
    /// </summary>
    private void RenderActiveJob(TrayCurrentJob? job)
    {
        if (job is null)
        {
            Set("jobActiveStatus", "Idle — no job currently running");
            Set("jobActiveType", "—");
            Set("jobActiveId", "—");
            Set("jobActiveStarted", "—");
            Set("jobActiveElapsed", "—");
            _jobProgress.Visible = false;
            _jobNote.Visible = false;
            _activeJobPage.Text = "Activity";
            return;
        }

        Set("jobActiveStatus", "Running");
        Set("jobActiveType", string.IsNullOrWhiteSpace(job.JobType) ? "—" : job.JobType);
        Set("jobActiveId", string.IsNullOrWhiteSpace(job.JobId) ? "—" : job.JobId);
        Set("jobActiveStarted", FormatTimestamp(job.StartedAtUtc));
        Set("jobActiveElapsed", FormatElapsed(job.StartedAtUtc));
        _jobProgress.Visible = true;
        _jobNote.Visible = true;
        _activeJobPage.Text = "Activity ●";
    }

    private static string FormatElapsed(DateTime startedAtUtc)
    {
        var elapsed = DateTime.UtcNow - startedAtUtc;
        if (elapsed < TimeSpan.Zero)
        {
            elapsed = TimeSpan.Zero;
        }

        return elapsed.TotalHours >= 1
            ? $"{(int)elapsed.TotalHours}h {elapsed.Minutes}m {elapsed.Seconds}s"
            : elapsed.TotalMinutes >= 1
                ? $"{(int)elapsed.TotalMinutes}m {elapsed.Seconds}s"
                : $"{elapsed.Seconds}s";
    }

    /// <summary>
    /// Self-service Software Catalog — mirrors the macOS tray's Catalog
    /// tab. Full clear + rebuild on every render tick (every 5s): the
    /// catalog rarely changes and the list is normally short, so the
    /// redraw cost is negligible and it sidesteps any row-bookkeeping
    /// bugs entirely (the class of bug that hit the macOS NSGridView
    /// version — see fix/tray-catalog-merged-row-crash).
    /// </summary>
    private void RenderCatalog(TrayCatalogStatus? catalog, bool jobRunning)
    {
        var items = catalog?.Items ?? new List<TrayCatalogItem>();
        var now = DateTime.UtcNow;

        // Drop grace entries older than the window — a stale entry here
        // would keep an Install button permanently disabled for a job
        // that already finished (or never started) minutes ago.
        foreach (var staleKey in _pendingInstallClicks
                     .Where(kv => now - kv.Value > InstallRequestGrace)
                     .Select(kv => kv.Key)
                     .ToList())
        {
            _pendingInstallClicks.Remove(staleKey);
        }

        _catalogFlow.SuspendLayout();
        _catalogFlow.Controls.Clear();

        if (items.Count == 0)
        {
            _catalogFlow.Controls.Add(_catalogEmptyLabel);
            _catalogFlow.ResumeLayout();
            return;
        }

        foreach (var item in items)
        {
            _catalogFlow.Controls.Add(BuildCatalogRow(item, jobRunning));
        }

        _catalogFlow.ResumeLayout();
    }

    private Control BuildCatalogRow(TrayCatalogItem item, bool jobRunning)
    {
        var row = new TableLayoutPanel
        {
            ColumnCount = 2,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Width = 540,
            Margin = new Padding(0, 4, 0, 10)
        };
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        var nameField = new Label
        {
            Text = item.Name,
            AutoSize = true,
            Font = new Font(Font, FontStyle.Bold)
        };

        var isPending = _pendingInstallClicks.ContainsKey(item.PackageId);
        var installButton = new Button
        {
            Text = isPending || jobRunning ? "Installing…" : "Install",
            AutoSize = true,
            Enabled = !isPending && !jobRunning,
            UseVisualStyleBackColor = true
        };
        installButton.Click += (_, _) =>
        {
            _pendingInstallClicks[item.PackageId] = DateTime.UtcNow;
            installButton.Text = "Installing…";
            installButton.Enabled = false;
            CatalogInstallSink.Write(item.PackageId);
        };

        row.Controls.Add(nameField, 0, 0);
        row.Controls.Add(installButton, 1, 0);

        var detailParts = new List<string>();
        if (!string.IsNullOrWhiteSpace(item.Vendor)) detailParts.Add(item.Vendor!);
        if (!string.IsNullOrWhiteSpace(item.Version)) detailParts.Add($"v{item.Version}");
        if (!string.IsNullOrWhiteSpace(item.Description)) detailParts.Add(item.Description!);
        if (item.RequiresReboot == true) detailParts.Add("Requires a restart");

        if (detailParts.Count > 0)
        {
            var detailField = new Label
            {
                Text = string.Join("  ·  ", detailParts),
                AutoSize = true,
                MaximumSize = new Size(520, 0),
                Font = new Font(Font.FontFamily, 8.5f),
                ForeColor = Color.Gray
            };
            row.Controls.Add(detailField, 0, 1);
            row.SetColumnSpan(detailField, 2);
        }

        return row;
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

    private void RenderDeviceInfo(TrayStatus? status)
    {
        var fields = DeviceInfoProvider.BuildFields(status);
        // BuildFields siempre devuelve la misma cantidad/orden de campos
        // (los labels se crearon de esa misma lista en el constructor).
        for (var i = 0; i < fields.Count && i < _deviceValueLabels.Count; i++)
        {
            _deviceValueLabels[i].Text = fields[i].Value;
        }
    }

    private Label AddDeviceRow(TableLayoutPanel grid, string label)
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

        grid.Controls.Add(labelControl, 0, row);
        grid.Controls.Add(valueControl, 1, row);
        return valueControl;
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
